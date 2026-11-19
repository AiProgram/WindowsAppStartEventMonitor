using System.Runtime.InteropServices;
using System.Text;
using AppObs.Probe.Common;

namespace WinEvt;

/// <summary>
/// 阶段 0 探针 2/3：用户会话侧窗口/前台事件打印机。
/// SetWinEventHook(WINEVENT_OUTOFCONTEXT) + RegisterShellHookWindow，只打印 hwnd/tid/pid/时间。
/// 要回答的问题：WinEvent 是否漏、Shell hook 是否重复、一次双击对应几条窗口事件。
/// 注意：本工具必须跑在交互用户会话里（Session 0 服务收不到任何用户桌面事件）。
/// </summary>
internal static class Program
{
    private const uint EVENT_SYSTEM_FOREGROUND = 0x0003;
    private const uint EVENT_OBJECT_CREATE = 0x8000;
    private const uint EVENT_OBJECT_DESTROY = 0x8001;
    private const uint EVENT_OBJECT_SHOW = 0x8002;
    private const uint EVENT_OBJECT_HIDE = 0x8003;
    private const uint EVENT_OBJECT_CLOAKED = 0x8017;
    private const uint EVENT_OBJECT_UNCLOAKED = 0x8018;

    private const int OBJID_WINDOW = 0;
    private const int CHILDID_SELF = 0;

    private const uint WINEVENT_OUTOFCONTEXT = 0x0000;

    private const int HSHELL_WINDOWCREATED = 1;
    private const int HSHELL_WINDOWDESTROYED = 2;
    private const int HSHELL_WINDOWACTIVATED = 4;
    private const int HSHELL_REDRAW = 6;
    private const int HSHELL_WINDOWREPLACED = 13;
    private const int HSHELL_WINDOWREPLACING = 14;
    private const int HSHELL_MONITORCHANGED = 16;
    private const int HSHELL_HIGHBIT = 0x8000;
    private const int HSHELL_FLASH = HSHELL_REDRAW | HSHELL_HIGHBIT;
    private const int HSHELL_RUDEAPPACTIVATED = HSHELL_WINDOWACTIVATED | HSHELL_HIGHBIT;

    private static JsonlSink _sink = null!;
    private static Options _opt = null!;
    private static IntPtr _winEventHookForeground;
    private static IntPtr _winEventHookObjects;
    private static uint _shellHookMessage;
    private static readonly object StatsLock = new();
    private static readonly Dictionary<string, long> Counts = new(StringComparer.OrdinalIgnoreCase);
    private static readonly HashSet<IntPtr> DistinctWindows = new();
    private static long _dropped;
    private static long _objectEvents;

    // 委托必须由字段持有，否则可能被 GC 回收导致回调崩溃
    private static readonly WinEventDelegate WinEventCallback = OnWinEvent;
    private static readonly WndProcDelegate WindowProcCallback = WindowProc;

    public static int Main(string[] args)
    {
        Log.InitConsole();
        _opt = Options.Parse(args);
        if (_opt.ShowHelp) { Options.PrintHelp(); return 0; }

        ProbeClock.Reanchor();
        _sink = new JsonlSink(_opt.OutPath);

        Log.Info($"输出     : {_sink.Path}");
        Log.Info($"时长     : {(_opt.DurationSeconds <= 0 ? "直到 Ctrl+C" : _opt.DurationSeconds + " 秒")}");
        Log.Info($"对象事件 : {(_opt.Objects ? "开（CREATE/SHOW/HIDE/DESTROY/CLOAKED）" : "关")}");

        var hInstance = GetModuleHandleW(null);
        var className = "AppObsProbe_WinEvtSink";
        var wc = new WNDCLASSEX
        {
            cbSize = (uint)Marshal.SizeOf<WNDCLASSEX>(),
            lpfnWndProc = Marshal.GetFunctionPointerForDelegate(WindowProcCallback),
            hInstance = hInstance,
            lpszClassName = className,
        };
        if (RegisterClassExW(ref wc) == 0)
        {
            Log.Error($"RegisterClassEx 失败, GetLastError={Marshal.GetLastWin32Error()}");
            return 3;
        }

        // 隐藏的顶层窗口：Shell hook 需要与本桌面关联的窗口来收 SHELLHOOK 消息
        var hwnd = CreateWindowExW(0, className, "AppObsProbe", 0, 0, 0, 0, 0,
            IntPtr.Zero, IntPtr.Zero, hInstance, IntPtr.Zero);
        if (hwnd == IntPtr.Zero)
        {
            Log.Error($"CreateWindowEx 失败, GetLastError={Marshal.GetLastWin32Error()}");
            return 3;
        }

        _shellHookMessage = RegisterWindowMessageW("SHELLHOOK");

        _winEventHookForeground = SetWinEventHook(EVENT_SYSTEM_FOREGROUND, EVENT_SYSTEM_FOREGROUND,
            IntPtr.Zero, WinEventCallback, 0, 0, WINEVENT_OUTOFCONTEXT);
        if (_winEventHookForeground == IntPtr.Zero)
            Log.Warn($"SetWinEventHook(FOREGROUND) 失败, GetLastError={Marshal.GetLastWin32Error()}");

        if (_opt.Objects)
        {
            _winEventHookObjects = SetWinEventHook(EVENT_OBJECT_CREATE, EVENT_OBJECT_UNCLOAKED,
                IntPtr.Zero, WinEventCallback, 0, 0, WINEVENT_OUTOFCONTEXT);
            if (_winEventHookObjects == IntPtr.Zero)
                Log.Warn($"SetWinEventHook(OBJECT) 失败, GetLastError={Marshal.GetLastWin32Error()}");
        }

        var shellHookOk = RegisterShellHookWindow(hwnd);
        if (!shellHookOk)
            Log.Warn($"RegisterShellHookWindow 失败, GetLastError={Marshal.GetLastWin32Error()}（无此信号仍可继续）");

        Log.Info($"钩子     : foreground={_winEventHookForeground != IntPtr.Zero}, objects={_winEventHookObjects != IntPtr.Zero}, shellhook={shellHookOk}");
        Log.Info("开始采集 —— 现在去双击几个应用。");

        if (_opt.DurationSeconds > 0)
        {
            // PostQuitMessage 只对调用线程有效，定时器跑在线程池上，必须投递到主线程队列
            var mainThreadId = GetCurrentThreadId();
            var timer = new System.Threading.Timer(_ => PostThreadMessageW(mainThreadId, WM_QUIT, IntPtr.Zero, IntPtr.Zero),
                null, _opt.DurationSeconds * 1000, Timeout.Infinite);
            GC.KeepAlive(timer);
        }

        // 真正的消息泵：out-of-context 回调与 SHELLHOOK 消息都投递到这个队列
        while (GetMessage(out var msg, IntPtr.Zero, 0, 0) > 0)
        {
            TranslateMessage(ref msg);
            DispatchMessage(ref msg);
        }

        if (shellHookOk) DeregisterShellHookWindow(hwnd);
        if (_winEventHookForeground != IntPtr.Zero) UnhookWinEvent(_winEventHookForeground);
        if (_winEventHookObjects != IntPtr.Zero) UnhookWinEvent(_winEventHookObjects);

        _sink.Flush();
        var summary = new Dictionary<string, object?>
        {
            ["tool"] = "win-evt",
            ["durationMs"] = _opt.DurationSeconds * 1000,
            ["recordsWritten"] = _sink.Written,
            ["dropped"] = _dropped,
            ["objectEvents"] = _objectEvents,
            ["distinctWindows"] = DistinctWindows.Count,
            ["counts"] = new Dictionary<string, long>(Counts),
            ["hooks"] = new Dictionary<string, bool>
            {
                ["foreground"] = _winEventHookForeground != IntPtr.Zero,
                ["objects"] = _winEventHookObjects != IntPtr.Zero,
                ["shellHook"] = shellHookOk,
            },
        };

        var countersDir = Path.GetDirectoryName(Path.GetFullPath(_opt.CountersPath));
        if (!string.IsNullOrEmpty(countersDir)) Directory.CreateDirectory(countersDir);
        File.WriteAllText(_opt.CountersPath,
            System.Text.Json.JsonSerializer.Serialize(summary,
                new System.Text.Json.JsonSerializerOptions { WriteIndented = true }), new UTF8Encoding(false));

        Console.WriteLine();
        Console.WriteLine("================ 采集结束 ================");
        foreach (var (k, v) in Counts) Console.WriteLine($"  {k,-26} = {v}");
        Console.WriteLine($"  distinctWindows            = {DistinctWindows.Count}");
        Console.WriteLine($"  records                    = {_sink.Written} (dropped {_dropped})");
        Console.WriteLine("==========================================");
        _sink.Dispose();
        return 0;
    }

    private static void OnWinEvent(IntPtr hWinEventHook, uint eventType, IntPtr hwnd,
        int idObject, int idChild, uint idEventThread, uint msEventTime)
    {
        var qpc = ProbeClock.Now();
        try
        {
            if (hwnd == IntPtr.Zero) return;
            if (eventType != EVENT_SYSTEM_FOREGROUND)
            {
                // 主报告 §2：系统会为控件/插入符/工具栏也发这些事件，必须过滤
                if (idObject != OBJID_WINDOW || idChild != CHILDID_SELF) return;
                if (Native.GetAncestor(hwnd, Native.GA_ROOT) != hwnd) return;
                Interlocked.Increment(ref _objectEvents);
                if (_opt.MaxObjectEvents > 0 && _objectEvents > _opt.MaxObjectEvents)
                {
                    if (Interlocked.Increment(ref _dropped) % 5000 == 1)
                        Log.Warn($"对象事件超过上限 {_opt.MaxObjectEvents}，后续丢弃（只计数）。");
                    return;
                }
            }

            Emit(qpc, KindOf(eventType), hwnd, idEventThread, msEventTime, "winevent");
        }
        catch (Exception ex)
        {
            if (Interlocked.Increment(ref _dropped) <= 3) Log.Warn("WinEvent 回调异常: " + ex.Message);
        }
    }

    private static IntPtr WindowProc(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam)
    {
        if (_shellHookMessage != 0 && msg == _shellHookMessage)
        {
            var code = (int)(wParam.ToInt64() & 0x7FFF);
            var hwnd = lParam;
            var qpc = ProbeClock.Now();
            try
            {
                if (hwnd != IntPtr.Zero)
                    Emit(qpc, ShellKindOf(code), hwnd, 0, 0, "shellhook");
            }
            catch (Exception ex)
            {
                if (Interlocked.Increment(ref _dropped) <= 3) Log.Warn("ShellHook 处理异常: " + ex.Message);
            }
            return IntPtr.Zero;
        }
        return DefWindowProcW(hWnd, msg, wParam, lParam);
    }

    private static void Emit(long qpc, string kind, IntPtr hwnd, uint idEventThread, uint msEventTime, string via)
    {
        Native.GetWindowThreadProcessId(hwnd, out var pid);

        var cls = new StringBuilder(256);
        Native.GetClassNameW(hwnd, cls, cls.Capacity);

        var title = new StringBuilder(512);
        Native.GetWindowTextW(hwnd, title, title.Capacity);

        var visible = Native.IsWindowVisible(hwnd);
        var topLevel = Native.GetAncestor(hwnd, Native.GA_ROOT) == hwnd;
        var exStyle = Native.GetWindowLongW(hwnd, Native.GWL_EXSTYLE);
        var toolWindow = (exStyle & Native.WS_EX_TOOLWINDOW) != 0;

        var rec = Rec.New("win-evt", kind, qpc)
            .Put("hwnd", "0x" + hwnd.ToInt64().ToString("X"))
            .Put("tid", idEventThread)
            .Put("pid", pid)
            .Put("class", cls.ToString())
            .Put("titleMasked", TitleMasker.Mask(title.ToString()))
            .Put("visible", visible)
            .Put("topLevel", topLevel)
            .Put("toolWindow", toolWindow ? true : null)
            .Put("via", via);
        if (msEventTime != 0) rec["eventTimeMs"] = msEventTime;

        _sink.Write(rec);

        lock (StatsLock)
        {
            Counts.TryGetValue(kind, out var n);
            Counts[kind] = n + 1;
            if (DistinctWindows.Count < 4096) DistinctWindows.Add(hwnd);
        }
    }

    private static string KindOf(uint eventType) => eventType switch
    {
        EVENT_SYSTEM_FOREGROUND => "Foreground",
        EVENT_OBJECT_CREATE => "ObjCreate",
        EVENT_OBJECT_DESTROY => "ObjDestroy",
        EVENT_OBJECT_SHOW => "ObjShow",
        EVENT_OBJECT_HIDE => "ObjHide",
        EVENT_OBJECT_CLOAKED => "ObjCloaked",
        EVENT_OBJECT_UNCLOAKED => "ObjUncloaked",
        _ => $"Event0x{eventType:X}",
    };

    private static string ShellKindOf(int code) => code switch
    {
        HSHELL_WINDOWCREATED => "ShellWindowCreated",
        HSHELL_WINDOWDESTROYED => "ShellWindowDestroyed",
        HSHELL_WINDOWACTIVATED => "ShellWindowActivated",
        HSHELL_RUDEAPPACTIVATED => "ShellRudeAppActivated",
        HSHELL_WINDOWREPLACING => "ShellWindowReplacing",
        HSHELL_WINDOWREPLACED => "ShellWindowReplaced",
        HSHELL_REDRAW => "ShellRedraw",
        HSHELL_FLASH => "ShellFlash",
        HSHELL_MONITORCHANGED => "ShellMonitorChanged",
        _ => $"Shell0x{code:X2}",
    };

    // ---------------- P/Invoke ----------------

    private delegate void WinEventDelegate(IntPtr hWinEventHook, uint eventType, IntPtr hwnd,
        int idObject, int idChild, uint idEventThread, uint msEventTime);

    private delegate IntPtr WndProcDelegate(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WNDCLASSEX
    {
        public uint cbSize;
        public uint style;
        public IntPtr lpfnWndProc;
        public int cbClsExtra;
        public int cbWndExtra;
        public IntPtr hInstance;
        public IntPtr hIcon;
        public IntPtr hCursor;
        public IntPtr hbrBackground;
        public string? lpszMenuName;
        public string lpszClassName;
        public IntPtr hIconSm;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MSG
    {
        public IntPtr hwnd;
        public uint message;
        public IntPtr wParam;
        public IntPtr lParam;
        public uint time;
        public int ptX;
        public int ptY;
    }

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr SetWinEventHook(uint eventMin, uint eventMax, IntPtr hmodWinEventProc,
        WinEventDelegate lpfnWinEventProc, uint idProcess, uint idThread, uint dwFlags);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UnhookWinEvent(IntPtr hWinEventHook);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern ushort RegisterClassExW(ref WNDCLASSEX lpwcx);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateWindowExW(uint exStyle, string className, string windowName, uint style,
        int x, int y, int width, int height, IntPtr parent, IntPtr menu, IntPtr instance, IntPtr param);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr DefWindowProcW(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool RegisterShellHookWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeregisterShellHookWindow(IntPtr hWnd);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern uint RegisterWindowMessageW(string lpString);

    [DllImport("user32.dll")]
    private static extern int GetMessage(out MSG lpMsg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TranslateMessage(ref MSG lpMsg);

    [DllImport("user32.dll")]
    private static extern IntPtr DispatchMessage(ref MSG lpMsg);

    [DllImport("user32.dll")]
    private static extern void PostQuitMessage(int exitCode);

    private const uint WM_QUIT = 0x0012;

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool PostThreadMessageW(uint idThread, uint msg, IntPtr wParam, IntPtr lParam);

    [DllImport("kernel32.dll")]
    private static extern uint GetCurrentThreadId();

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr GetModuleHandleW(string? moduleName);
}

internal sealed class Options
{
    public string OutPath = "out/win-evt.jsonl";
    public string CountersPath = "out/win-evt.counters.json";
    public int DurationSeconds;
    public bool Objects = true;
    public int MaxObjectEvents = 200_000;
    public bool ShowHelp;

    public static Options Parse(string[] args)
    {
        var o = new Options();
        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--duration" or "-d": o.DurationSeconds = int.Parse(args[++i]); break;
                case "--out" or "-o": o.OutPath = args[++i]; break;
                case "--counters": o.CountersPath = args[++i]; break;
                case "--no-objects": o.Objects = false; break;
                case "--max-object-events": o.MaxObjectEvents = int.Parse(args[++i]); break;
                case "--help" or "-h" or "/?": o.ShowHelp = true; break;
                default:
                    Console.Error.WriteLine($"未知参数: {args[i]}");
                    o.ShowHelp = true;
                    break;
            }
        }
        return o;
    }

    public static void PrintHelp()
    {
        Console.WriteLine("""
            win-evt —— 阶段 0 探针：WinEvent(out-of-context) + Shell hook 窗口事件打印

            用法:
              win-evt [选项]

            选项:
              -d, --duration <秒>   采集时长；0 或不给 = 直到 Ctrl+C
              -o, --out <路径>      JSONL 输出（默认 out/win-evt.jsonl）
                  --counters <路径> 计数器输出（默认 out/win-evt.counters.json）
                  --no-objects      不订阅 OBJECT_CREATE/SHOW/HIDE/DESTROY/CLOAKED（只留前台+Shell hook）
                  --max-object-events <n> 对象事件上限，超出只计数不落盘（默认 200000）
              -h, --help            显示本帮助
            """);
    }
}
