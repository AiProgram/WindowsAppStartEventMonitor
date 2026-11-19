using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using AppObs.Probe.Common;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;

namespace EtwProc;

/// <summary>
/// 阶段 0 探针 1/3：ETW 进程事件打印机。
/// StartTrace + Microsoft-Windows-Kernel-Process（0x10 进程 / 可选 0x40 镜像），只打印字段，不做业务逻辑。
/// 要回答的问题：ETW 是否漏、字段是否够用、与 EDR 是否抢会话、OpenProcess 拒绝率多少。
/// </summary>
internal static class Program
{
    /// <summary>Microsoft-Windows-Kernel-Process（主报告 §2 表首行）。</summary>
    private static readonly Guid KernelProcessProvider = new("22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716");

    private const ulong KeywordProcess = 0x10;
    private const ulong KeywordImage = 0x40;

    private static readonly object StatsLock = new();
    private static readonly List<double> ParseNsSamples = new(4096);
    private static readonly List<double> LagSamples = new(4096);
    private static readonly Dictionary<string, long> ByProvider = new(StringComparer.OrdinalIgnoreCase);
    private static readonly Dictionary<string, long> ByEventName = new(StringComparer.OrdinalIgnoreCase);
    private static readonly Stopwatch RunWatch = Stopwatch.StartNew();

    private static long _eventsTotal;
    private static long _processStart;
    private static long _processStop;
    private static long _processDCStart;
    private static long _imageLoad;
    private static long _otherEvents;
    private static long _dumpCount;
    private static long _handleOk;
    private static long _handleDenied;
    private static long _parseFailures;
    private static string _mode = "manifest";
    private static double _durationMs;

    public static int Main(string[] args)
    {
        Log.InitConsole();
        var opt = Options.Parse(args);
        if (opt.ShowHelp) { Options.PrintHelp(); return 0; }

        if (!(TraceEventSession.IsElevated() ?? false))
        {
            Log.Error("当前进程未提权。启动/控制 ETW 实时会话需要管理员或 Performance Log Users 组成员身份。");
            Log.Error("请以管理员身份运行本工具。");
            return 2;
        }

        ProbeClock.Reanchor();
        using var sink = new JsonlSink(opt.OutPath);

        Log.Info($"会话名   : {opt.SessionName}");
        Log.Info($"输出     : {sink.Path}");
        Log.Info($"关键词   : 0x{KeywordProcess:X2} Process{(opt.Images ? " | 0x40 Image" : "")}");
        Log.Info($"时长     : {(opt.DurationSeconds <= 0 ? "直到 Ctrl+C" : opt.DurationSeconds + " 秒")}");
        Log.Info($"句柄探测 : {(opt.ProbeHandles ? "开（统计 OpenProcess 拒绝率）" : "关")}");

        TraceEventSession session;
        try
        {
            session = CreateManifestSession(opt);
            _mode = "manifest";
        }
        catch (Exception ex)
        {
            Log.Warn($"manifest 会话启动失败: {ex.GetType().Name}: {ex.Message}");
            Log.Warn("回退到经典 NT Kernel Logger（全机单例，与 EDR/PerfView/WPR 冲突）—— 这本身就是待记录的证据。");
            try
            {
                session = CreateKernelLoggerSession(opt);
                _mode = "kernel-logger";
            }
            catch (Exception ex2)
            {
                Log.Error($"经典内核 logger 也失败: {ex2.GetType().Name}: {ex2.Message}");
                Log.Error("结论：本机 ETW 实时会话不可用。");
                return 3;
            }
        }

        var counters = default(SessionCounters);
        using (session)
        {
            if (_mode == "manifest")
                session.Source.Dynamic.All += data => OnEvent(data, sink, opt);
            else
                session.Source.Kernel.All += data => OnEvent(data, sink, opt);

            var processor = new Thread(() =>
            {
                try { session.Source.Process(); }
                catch (Exception ex) { Log.Error("ProcessTrace 异常退出: " + ex.Message); }
            })
            { IsBackground = true, Name = "etw-processor" };

            Log.Info("开始采集 —— 现在去双击几个应用。");
            processor.Start();

            if (opt.DurationSeconds > 0)
            {
                while (RunWatch.Elapsed.TotalSeconds < opt.DurationSeconds && processor.IsAlive)
                    Thread.Sleep(100);
            }
            else
            {
                using var quit = new ManualResetEventSlim();
                Console.CancelKeyPress += (_, e) => { e.Cancel = true; quit.Set(); };
                quit.Wait();
            }

            // 必须在会话仍在运行时查询：StopProcessing 之后再 ControlTrace(QUERY) 会返回
            // INSTANCE_NOT_FOUND，计数器全 0 会被误读成「零丢失」。
            counters = ReadSessionCounters(opt.SessionName);

            try { session.Source.StopProcessing(); } catch { /* 已停止 */ }
            processor.Join(TimeSpan.FromSeconds(5));
        }

        _durationMs = Math.Round(RunWatch.Elapsed.TotalMilliseconds, 1);

        var summary = new Dictionary<string, object?>
        {
            ["tool"] = "etw-proc",
            ["sessionMode"] = _mode,
            ["sessionName"] = opt.SessionName,
            ["durationMs"] = _durationMs,
            ["eventsTotal"] = Interlocked.Read(ref _eventsTotal),
            ["processStart"] = Interlocked.Read(ref _processStart),
            ["processStop"] = Interlocked.Read(ref _processStop),
            ["processDCStart"] = Interlocked.Read(ref _processDCStart),
            ["imageLoad"] = Interlocked.Read(ref _imageLoad),
            ["otherEvents"] = Interlocked.Read(ref _otherEvents),
            ["byProvider"] = ByProvider.Count == 0 ? null : new Dictionary<string, long>(ByProvider),
            ["byEventName"] = ByEventName.Count == 0 ? null : new Dictionary<string, long>(ByEventName),
            ["etwEventsLost"] = counters.EventsLost,
            ["buffersWritten"] = counters.BuffersWritten,
            ["freeBuffers"] = counters.FreeBuffers,
            ["realTimeBuffersLost"] = counters.RealTimeBuffersLost,
            ["countersQueryRc"] = CountersQueryRc,
            ["handleProbeOk"] = Interlocked.Read(ref _handleOk),
            ["handleProbeDenied"] = Interlocked.Read(ref _handleDenied),
            ["parseNsP50"] = Percentile(ParseNsSamples, 50),
            ["parseNsP99"] = Percentile(ParseNsSamples, 99),
            ["deliveryLagMsP50"] = Percentile(LagSamples, 50),
            ["deliveryLagMsP99"] = Percentile(LagSamples, 99),
            ["parseFailures"] = Interlocked.Read(ref _parseFailures),
            ["recordsWritten"] = sink.Written,
            ["recordsDropped"] = sink.Dropped,
            ["clockFrequency"] = ProbeClock.Frequency,
        };

        sink.Flush();
        var countersDir = Path.GetDirectoryName(Path.GetFullPath(opt.CountersPath));
        if (!string.IsNullOrEmpty(countersDir)) Directory.CreateDirectory(countersDir);
        File.WriteAllText(opt.CountersPath,
            System.Text.Json.JsonSerializer.Serialize(summary,
                new System.Text.Json.JsonSerializerOptions { WriteIndented = true }),
            new UTF8Encoding(false));

        PrintSummary(summary);
        return 0;
    }

    private static TraceEventSession CreateManifestSession(Options opt)
    {
        var session = new TraceEventSession(opt.SessionName) { StopOnDispose = true };
        var keywords = KeywordProcess | (opt.Images ? KeywordImage : 0UL);
        session.EnableProvider(KernelProcessProvider, TraceEventLevel.Informational, keywords);
        Log.Info("会话模式 : manifest provider（非内核 logger，可与 EDR 共存）");
        return session;
    }

    private static TraceEventSession CreateKernelLoggerSession(Options opt)
    {
        var keywords = KernelTraceEventParser.Keywords.Process |
                       (opt.Images ? KernelTraceEventParser.Keywords.ImageLoad : 0);
        var session = new TraceEventSession(KernelTraceEventParser.KernelSessionName) { StopOnDispose = true };
        session.EnableKernelProvider(keywords);
        Log.Info("会话模式 : NT Kernel Logger（单例）");
        return session;
    }

    private static void OnEvent(TraceEvent data, JsonlSink sink, Options opt)
    {
        var t0 = ProbeClock.Now();
        try
        {
            Interlocked.Increment(ref _eventsTotal);
            var provider = data.ProviderName ?? "(null)";
            lock (StatsLock)
            {
                ByProvider.TryGetValue(provider, out var n);
                ByProvider[provider] = n + 1;

                // 事件名直方图：用来证伪「字段/事件名是否如文档所述」
                if (ByEventName.Count < 200)
                {
                    var key = $"{data.EventName}#{data.ID}v{data.Version}";
                    ByEventName.TryGetValue(key, out var m);
                    ByEventName[key] = m + 1;
                }
            }

            if (opt.DumpFirst > 0 && Interlocked.Increment(ref _dumpCount) <= opt.DumpFirst)
                sink.Write(RawRecord(data));

            // 关键：不能按 EventName 判类型 —— 名称是本地化的（本机显示为「开始」「停止」）。
            // 稳定判据是 Provider + EventID：1=ProcessStart、2=ProcessStop、3=DCStart、4=DCStop。
            switch ((int)data.ID)
            {
                case 2:
                case 4:
                    Interlocked.Increment(ref _processStop);
                    return;
                case 3:
                    // 会话启动时对存量进程的 rundown，不是用户发起，单独计数
                    Interlocked.Increment(ref _processDCStart);
                    return;
                case 5:
                case 6:
                    Interlocked.Increment(ref _imageLoad);
                    return;
                case 1:
                    break;
                default:
                    Interlocked.Increment(ref _otherEvents);
                    return;
            }

            Interlocked.Increment(ref _processStart);

            uint pid, ppid, sessionId;
            ulong psn, ppsn;
            bool? elevated;
            string elevationType = string.Empty;
            string createTimeText = string.Empty;
            string rawImage = string.Empty;
            var eventHasImageName = false;

            if (data is ProcessTraceData classic)
            {
                pid = (uint)classic.ProcessID;
                ppid = (uint)classic.ParentID;
                psn = 0;
                ppsn = 0;
                sessionId = 0;
                rawImage = classic.ImageFileName ?? string.Empty;
                eventHasImageName = !string.IsNullOrEmpty(rawImage);
                elevated = null;
            }
            else
            {
                pid = AsUInt32(Field(data, "ProcessID", "ProcessId", "PID"));
                ppid = AsUInt32(Field(data, "ParentProcessID", "ParentID", "ParentProcessId"));
                psn = AsUInt64(Field(data, "ProcessSequenceNumber", "SequenceNumber"));
                ppsn = AsUInt64(Field(data, "ParentProcessSequenceNumber", "ParentSequenceNumber"));
                sessionId = AsUInt32(Field(data, "SessionID", "SessionId"));
                elevated = AsBool(Field(data, "ProcessTokenIsElevated"));
                elevationType = AsString(Field(data, "ProcessTokenElevationType"));
                createTimeText = AsString(Field(data, "CreateTime"));

                // 本机 v4 实测：ProcessStart 不带 ImageFileName / PackageFullName / MandatoryLabel。
                // 这里仍尝试按名取一次，取不到就明确标出，交给句柄侧解析。
                rawImage = AsString(Field(data, "ImageFileName", "ImageName", "Image", "FileName"));
                eventHasImageName = !string.IsNullOrEmpty(rawImage);
            }

            // 句柄侧解析：镜像路径 + 包身份（ETW 事件本身不提供）
            var imagePath = string.Empty;
            var pfn = string.Empty;
            var aumid = string.Empty;
            var handleProbe = opt.ProbeHandles ? "skipped" : "off";

            if (pid != 0)
            {
                var h = Native.OpenProcess(Native.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
                if (h == IntPtr.Zero)
                {
                    handleProbe = "denied";
                    Interlocked.Increment(ref _handleDenied);
                }
                else
                {
                    handleProbe = "ok";
                    Interlocked.Increment(ref _handleOk);
                    try
                    {
                        imagePath = QueryImagePath(h);
                        pfn = QueryPackageFullName(h);
                        aumid = QueryAumid(h);
                    }
                    finally { Native.CloseHandle(h); }
                }
            }

            if (string.IsNullOrEmpty(imagePath) && !string.IsNullOrEmpty(rawImage))
                imagePath = rawImage;
            imagePath = PathNormalizer.Normalize(imagePath, out var unresolved);

            // 事件自带时间戳映射到 QPC：不能让投递延迟污染 T1a
            var recvQpc = ProbeClock.Now();
            var evtQpc = ProbeClock.ResolveEventQpc(data.TimeStamp);
            var lagMs = Math.Max(0, ProbeClock.Ms(recvQpc - evtQpc));
            lock (StatsLock)
            {
                if (LagSamples.Count < 100_000) LagSamples.Add(lagMs);
            }

            var rec = Rec.New("etw", "ProcessStart", evtQpc)
                .Put("pid", pid)
                .Put("ppid", ppid)
                .Put("psn", psn)
                .Put("ppsn", ppsn)
                .Put("sid", sessionId)
                .Put("image", rawImage)
                .Put("imagePath", imagePath)
                .Put("exe", PathNormalizer.FileNameOf(imagePath))
                .Put("elevated", elevated)
                .Put("elevationType", string.IsNullOrEmpty(elevationType) ? null : elevationType)
                .Put("eventCreateTime", string.IsNullOrEmpty(createTimeText) ? null : createTimeText)
                .Put("eventHasImageName", eventHasImageName)
                .Put("packageFullName", string.IsNullOrEmpty(pfn) ? null : pfn)
                .Put("aumid", string.IsNullOrEmpty(aumid) ? null : aumid)
                .Put("devicePathUnresolved", unresolved ? true : null)
                .Put("handleProbe", handleProbe)
                .Put("deliveryLagMs", Math.Round(lagMs, 1))
                .Put("provider", provider)
                .Put("eventId", (int)data.ID)
                .Put("version", data.Version)
                .Put("eventNameLocalized", data.EventName);

            sink.Write(rec);
        }
        catch (Exception ex)
        {
            var n = Interlocked.Increment(ref _parseFailures);
            if (n <= 3) Log.Warn("事件解析异常: " + ex.Message);
        }
        finally
        {
            var ns = ProbeClock.Ms(ProbeClock.Now() - t0) * 1_000_000.0;
            lock (StatsLock)
            {
                if (ParseNsSamples.Count < 200_000) ParseNsSamples.Add(ns);
            }
        }
    }

    /// <summary>把事件原样落盘，用于校准「字段名/事件号到底长什么样」。</summary>
    private static Dictionary<string, object?> RawRecord(TraceEvent data)
    {
        var rec = Rec.New("etw", "RawEvent", ProbeClock.Now())
            .Put("provider", data.ProviderName)
            .Put("eventId", data.ID)
            .Put("version", data.Version)
            .Put("opcode", data.OpcodeName)
            .Put("task", data.TaskName)
            .Put("keywords", "0x" + ((ulong)data.Keywords).ToString("X"))
            .Put("level", data.Level.ToString());

        var names = new List<string>();
        var payload = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var name in data.PayloadNames)
            {
                names.Add(name);
                try { payload[name] = data.PayloadByName(name)?.ToString(); }
                catch { payload[name] = "<err>"; }
            }
        }
        catch { /* 无 payload */ }

        rec["payloadNames"] = names;
        rec["payload"] = payload;
        return rec;
    }

    /// <summary>按下标兜底取值。字段名可能被本地化（与 EventName 同理），但 manifest 的字段顺序是稳定的。</summary>
    private static object? FieldAt(TraceEvent data, int index)
    {
        try
        {
            if (data.PayloadNames is { Length: > 0 } names && index < names.Length)
                return data.PayloadByName(names[index]);
        }
        catch { }
        return null;
    }

    private static string QueryImagePath(IntPtr hProcess)
    {
        var sb = new StringBuilder(1024);
        uint size = (uint)sb.Capacity;
        return Native.QueryFullProcessImageNameW(hProcess, 0, sb, ref size) ? sb.ToString() : string.Empty;
    }

    private static string QueryPackageFullName(IntPtr hProcess)
    {
        try
        {
            uint len = 0;
            var rc = Native.GetPackageFullName(hProcess, ref len, null);
            if (rc != Native.ERROR_INSUFFICIENT_BUFFER || len == 0) return string.Empty;
            var sb = new StringBuilder((int)len);
            rc = Native.GetPackageFullName(hProcess, ref len, sb);
            return rc == 0 ? sb.ToString() : string.Empty;
        }
        catch { return string.Empty; }
    }

    private static string QueryAumid(IntPtr hProcess)
    {
        try
        {
            uint len = 0;
            var rc = Native.GetApplicationUserModelId(hProcess, ref len, null);
            if (rc != Native.ERROR_INSUFFICIENT_BUFFER || len == 0) return string.Empty;
            var sb = new StringBuilder((int)len);
            rc = Native.GetApplicationUserModelId(hProcess, ref len, sb);
            return rc == 0 ? sb.ToString() : string.Empty;
        }
        catch { return string.Empty; }
    }

    private static object? Field(TraceEvent data, params string[] candidates)
    {        foreach (var c in candidates)
        {
            try
            {
                var v = data.PayloadByName(c);
                if (v is not null) return v;
            }
            catch { /* 字段不存在 */ }
        }

        try
        {
            foreach (var name in data.PayloadNames)
            {
                foreach (var c in candidates)
                {
                    if (!string.Equals(name, c, StringComparison.OrdinalIgnoreCase)) continue;
                    try { return data.PayloadByName(name); } catch { }
                }
            }
        }
        catch { }
        return null;
    }

    private static string AsString(object? v) => v switch
    {
        null => string.Empty,
        string s => s,
        byte[] b => Encoding.Unicode.GetString(b).TrimEnd('\0'),
        _ => v.ToString() ?? string.Empty,
    };

    private static uint AsUInt32(object? v) => v switch
    {
        null => 0,
        uint u => u,
        int i => (uint)i,
        long l => (uint)l,
        ulong ul => (uint)ul,
        _ => uint.TryParse(v.ToString(), out var p) ? p : 0,
    };

    private static ulong AsUInt64(object? v) => v switch
    {
        null => 0,
        ulong ul => ul,
        long l => (ulong)l,
        uint u => u,
        int i => (ulong)i,
        _ => ulong.TryParse(v.ToString(), out var p) ? p : 0,
    };

    private static bool? AsBool(object? v) => v switch
    {
        null => null,
        bool b => b,
        byte by => by != 0,
        uint u => u != 0,
        int i => i != 0,
        ulong ul => ul != 0,
        _ => bool.TryParse(v.ToString(), out var p) ? p : null,
    };

    private static double Percentile(List<double> samples, int p)
    {
        double[] arr;
        lock (StatsLock)
        {
            if (samples.Count == 0) return 0;
            arr = samples.ToArray();
        }
        Array.Sort(arr);
        var idx = (int)Math.Round((p / 100.0) * (arr.Length - 1));
        return Math.Round(arr[Math.Clamp(idx, 0, arr.Length - 1)], 1);
    }

    private readonly record struct SessionCounters(uint EventsLost, uint BuffersWritten, uint FreeBuffers, uint RealTimeBuffersLost);

    private static SessionCounters ReadSessionCounters(string sessionName)
    {
        const int size = 4096;
        var ptr = Marshal.AllocHGlobal(size);
        try
        {
            for (var i = 0; i < size; i++) Marshal.WriteByte(ptr, i, 0);
            var props = new Native.EventTraceProperties
            {
                Wnode = new Native.WnodeHeader
                {
                    BufferSize = (uint)size,
                    Flags = Native.WNODE_FLAG_TRACED_GUID,
                },
                LogFileNameOffset = 0,
                LoggerNameOffset = (uint)Marshal.SizeOf<Native.EventTraceProperties>(),
            };
            Marshal.StructureToPtr(props, ptr, false);
            var rc = Native.ControlTraceW(0, sessionName, ptr, Native.CONTROLTRACE_QUERY);
            CountersQueryRc = (int)rc;
            if (rc != 0)
            {
                Log.Warn($"ControlTrace(QUERY) 失败 rc={rc}（0 以外的值代表计数器不可用，不是“零丢失”）。");
                return default;
            }
            var back = Marshal.PtrToStructure<Native.EventTraceProperties>(ptr);
            return new SessionCounters(back.EventsLost, back.BuffersWritten, back.FreeBuffers, back.RealTimeBuffersLost);
        }
        catch (Exception ex)
        {
            Log.Warn("读取 ETW 计数器失败: " + ex.Message);
            return default;
        }
        finally { Marshal.FreeHGlobal(ptr); }
    }

    private static int CountersQueryRc;

    private static void PrintSummary(Dictionary<string, object?> s)
    {
        Console.WriteLine();
        Console.WriteLine("================ 采集结束 ================");
        foreach (var (k, v) in s)
        {
            if (v is Dictionary<string, long> map)
                foreach (var (pk, pv) in map) Console.WriteLine($"  byProvider[{pk}] = {pv}");
            else
                Console.WriteLine($"  {k} = {v ?? "<null>"}");
        }
        Console.WriteLine("==========================================");
    }
}

internal sealed class Options
{
    public string SessionName = "AppObsProbe";
    public string OutPath = "out/etw-proc.jsonl";
    public string CountersPath = "out/etw-proc.counters.json";
    public int DurationSeconds;
    public bool Images;
    public bool ProbeHandles = true;
    public int DumpFirst;
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
                case "--session": o.SessionName = args[++i]; break;
                case "--images": o.Images = true; break;
                case "--no-handle-probe": o.ProbeHandles = false; break;
                case "--dump-first": o.DumpFirst = int.Parse(args[++i]); break;
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
            etw-proc —— 阶段 0 探针：Kernel-Process ETW 字段打印

            用法:
              etw-proc [选项]

            选项:
              -d, --duration <秒>   采集时长；0 或不给 = 直到 Ctrl+C
              -o, --out <路径>      JSONL 输出（默认 out/etw-proc.jsonl）
                  --counters <路径> 计数器输出（默认 out/etw-proc.counters.json）
                  --session <名>    ETW 会话名（默认 AppObsProbe）
                  --images          同时开启 Image 关键词 0x40
                  --no-handle-probe 不做 OpenProcess 拒绝率探测
                  --dump-first <n>  前 n 条 ProcessStart 额外输出全部原始字段（字段名校准用）
              -h, --help            显示本帮助
            """);
    }
}
