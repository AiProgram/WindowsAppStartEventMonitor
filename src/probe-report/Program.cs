using System.Diagnostics;
using System.Text;
using System.Text.Json;
using AppObs.Probe.Common;

namespace ProbeReport;

/// <summary>
/// 阶段 0 的产出工具：把 etw-proc.jsonl 与 win-evt.jsonl 按 QPC 时间轴合并，
/// 生成「信号覆盖率表」——阶段 0 的唯一交付物，用来决定后续设计是否需要改。
/// </summary>
internal static class Program
{
    private static int Main(string[] args)
    {
        Log.InitConsole();
        var opt = Options.Parse(args);
        if (opt.ShowHelp) { Options.PrintHelp(); return 0; }

        if (!File.Exists(opt.EtwPath)) { Console.Error.WriteLine($"找不到 {opt.EtwPath}"); return 1; }
        if (!File.Exists(opt.WinEvtPath)) { Console.Error.WriteLine($"找不到 {opt.WinEvtPath}"); return 1; }

        var etwAll = Load(opt.EtwPath);
        var etw = etwAll.Where(r => r.Kind == "ProcessStart").ToList();
        var win = Load(opt.WinEvtPath).Where(r => r.Kind != "RawEvent").ToList();

        var freq = opt.Freq;
        var t0WindowTicks = (long)(opt.T0WindowMs / 1000.0 * freq);
        var launchWindowTicks = (long)(opt.LaunchWindowMs / 1000.0 * freq);

        // ---- 用户动作（T0 候选）：前台切换 + Shell 激活，同 hwnd 300ms 内去重 ----
        var actions = new List<ActionPoint>();
        foreach (var r in win.Where(r => r.Kind is "Foreground" or "ShellWindowActivated" or "ShellRudeAppActivated"))
        {
            var last = actions.LastOrDefault();
            if (last is not null && last.HwndStr == r.HwndStr && r.Qpc - last.Qpc < (long)(0.3 * freq)) continue;
            actions.Add(new ActionPoint(r.Qpc, r.Ts, r.HwndStr, r.Pid, r.TitleMasked, r.ClassName, r.Kind));
        }

        var starts = etw.OrderBy(r => r.Qpc).ToList();
        var appStarts = starts.Where(s => !IsInfra(s.Exe)).ToList();

        // ---- 配对 ----
        var rows = new List<Row>();
        var usedStarts = new HashSet<int>();

        foreach (var a in actions)
        {
            var window = starts
                .Where((s, i) => s.Qpc >= a.Qpc - t0WindowTicks && s.Qpc <= a.Qpc + launchWindowTicks)
                .ToList();

            var samePid = window.FirstOrDefault(s => s.Pid == a.Pid);
            var anyApp = window.FirstOrDefault(s => !IsInfra(s.Exe));

            string verdict;
            string detail;
            int? t1aMs = null;
            string? appName = null;

            if (samePid is not null)
            {
                verdict = "A：ETW+WinEvent 同 PID";
                t1aMs = Ms(samePid.Qpc - a.Qpc, freq);
                appName = DisplayName(samePid.ImagePath, samePid.Exe);
                usedStarts.Add(starts.IndexOf(samePid));
                detail = $"pid={samePid.Pid} psn={samePid.Psn} ppid={samePid.Ppid} via={samePid.Via}";
            }
            else if (anyApp is not null)
            {
                verdict = "B：窗口命中/进程 PID 不同";
                // PID 不同说明中间隔了宿主/中转，强行相减会得到伪耗时，这里不报 T1a
                t1aMs = null;
                appName = DisplayName(anyApp.ImagePath, anyApp.Exe);
                usedStarts.Add(starts.IndexOf(anyApp));
                detail = $"窗口 pid={a.Pid}，进程 pid={anyApp.Pid}（宿主/归并待定）";
            }
            else
            {
                verdict = "C：仅 WinEvent，无进程事件";
                detail = "复用/热启动，或 ETW 漏报";
                var known = starts.LastOrDefault(s => s.Pid == a.Pid);
                if (known is not null) appName = DisplayName(known.ImagePath, known.Exe);
            }

            rows.Add(new Row(a.Qpc, a.Ts, a.HwndStr, a.Pid, a.TitleMasked, a.ClassName, verdict, appName, t1aMs, detail));
        }

        var unmatchedStarts = appStarts.Where(s => !usedStarts.Contains(starts.IndexOf(s))).ToList();

        // ---- 统计 ----
        var report = new StringBuilder();
        var etwCounters = ReadCounters(opt.EtwCountersPath);
        var winCounters = ReadCounters(opt.WinEvtCountersPath);

        var byVerdict = rows.GroupBy(r => r.Verdict).ToDictionary(g => g.Key, g => g.Count());

        report.AppendLine("# 阶段 0 · 信号覆盖率实测");
        report.AppendLine();
        report.AppendLine($"> 生成时间：{DateTime.Now:O}　|　ETW 记录：`{opt.EtwPath}`　|　WinEvent 记录：`{opt.WinEvtPath}`");
        report.AppendLine();
        report.AppendLine("## 1. 覆盖结论");
        report.AppendLine();
        report.AppendLine("| 指标 | 值 | 说明 |");
        report.AppendLine("|---|---|---|");
        report.AppendLine($"| 用户动作（T0 去重后） | {actions.Count} | Foreground + Shell 激活，同 hwnd 300ms 去重 |");
        report.AppendLine($"| A 级命中（ETW+WinEvent 同 PID） | {byVerdict.GetValueOrDefault("A：ETW+WinEvent 同 PID")} | 强证据，可直接判「用户发起」 |");
        report.AppendLine($"| B 级命中（窗口有、PID 不同） | {byVerdict.GetValueOrDefault("B：窗口命中/进程 PID 不同")} | 宿主归并 / 子进程归因 |");
        report.AppendLine($"| C 级（仅窗口，无进程事件） | {byVerdict.GetValueOrDefault("C：仅 WinEvent，无进程事件")} | 复用/热启动，或 ETW 漏报 |");
        report.AppendLine($"| 进程创建总数 | {starts.Count} | 含系统进程 |");
        report.AppendLine($"| 应用级进程创建 | {appStarts.Count} | 已剔除基础设施进程 |");
        report.AppendLine($"| 未见窗口的进程创建 | {unmatchedStarts.Count} | 系统拉起 / 后台任务 / 窗口事件未捕获 |");
        var aCount = byVerdict.GetValueOrDefault("A：ETW+WinEvent 同 PID");
        var hitRate = actions.Count == 0 ? 0 : Math.Round(100.0 * aCount / actions.Count, 1);
        report.AppendLine($"| **A 级覆盖率** | **{hitRate}%** | A / 用户动作 |");
        report.AppendLine();

        var rawStart = etwAll.FirstOrDefault(r => r.Kind == "RawEvent" && r.EventId == 1);
        if (rawStart is not null && rawStart.PayloadNames.Count > 0)
        {
            report.AppendLine("## 1.5 ProcessStart 实际字段（本机实测）");
            report.AppendLine();
            report.AppendLine("| 序 | 字段名 |");
            report.AppendLine("|---|---|");
            for (var i = 0; i < rawStart.PayloadNames.Count; i++)
                report.AppendLine($"| {i} | `{rawStart.PayloadNames[i]}` |");
            report.AppendLine();
            report.AppendLine("> 实测：本机 v4 的 ProcessStart **不含** `ImageFileName` / `PackageFullName` / `MandatoryLabel`。");
            report.AppendLine("> 镜像路径与包身份只能靠 `OpenProcess` + `QueryFullProcessImageNameW` + `GetPackageFullName` 补齐。");
            report.AppendLine();
        }

        report.AppendLine("## 2. ETW 侧计数器");
        report.AppendLine("| 计数器 | 值 |");
        report.AppendLine("|---|---|");
        foreach (var (k, v) in etwCounters)
            report.AppendLine($"| `{k}` | {v} |");
        if (winCounters.Count > 0)
        {
            report.AppendLine();
            report.AppendLine("## 3. 窗口侧计数器");
            report.AppendLine();
            report.AppendLine("| 计数器 | 值 |");
            report.AppendLine("|---|---|");
            foreach (var (k, v) in winCounters)
                if (!k.StartsWith("counts.") && k != "tool") report.AppendLine($"| `{k}` | {v} |");
            foreach (var (k, v) in winCounters.Where(kv => kv.Key.StartsWith("counts.")))
                report.AppendLine($"| {k[7..]} | {v} |");
        }

        report.AppendLine();
        report.AppendLine("## 4. 时间线（前 60 个动作）");
        report.AppendLine();
        report.AppendLine("| # | T0 (本地) | 窗口类 | 窗口 pid | 应用 | 结论 | T1a−T0 (ms) |");
        report.AppendLine("|---|---|---|---|---|---|---|");
        var n = 0;
        foreach (var r in rows.OrderBy(r => r.Qpc).Take(60))
        {
            n++;
            report.AppendLine($"| {n} | {LocalTime(r.Ts):HH:mm:ss.fff} | {r.ClassName} | {r.Pid} | {r.AppName ?? "-"} | {r.Verdict} | {(r.T1aMs?.ToString() ?? "-")} |");
        }

        report.AppendLine();
        report.AppendLine("## 5. 未见窗口的进程创建（前 40，按时间）");
        report.AppendLine();
        report.AppendLine("| 时间 | pid | ppid | 应用 |");
        report.AppendLine("|---|---|---|---|");
        foreach (var s in unmatchedStarts.OrderBy(s => s.Qpc).Take(40))
        {
            report.AppendLine($"| {LocalTime(s.Ts):HH:mm:ss.fff} | {s.Pid} | {s.Ppid} | {Path.GetFileName(s.Exe)} |");
        }

        report.AppendLine();
        report.AppendLine("## 6. 进程创建的按应用分布（多进程归并的输入）");
        report.AppendLine();
        report.AppendLine("| 应用 | 进程数 | exe |");
        report.AppendLine("|---|---|---|");
        foreach (var g in appStarts.GroupBy(s => s.Exe, StringComparer.OrdinalIgnoreCase)
                     .OrderByDescending(g => g.Count()).Take(12))
        {
            report.AppendLine($"| {DisplayName(g.First().ImagePath, g.Key)} | {g.Count()} | {g.Key} |");
        }

        var md = report.ToString();
        var outDir = Path.GetDirectoryName(Path.GetFullPath(opt.OutPath));
        if (!string.IsNullOrEmpty(outDir)) Directory.CreateDirectory(outDir);
        File.WriteAllText(opt.OutPath, md, new UTF8Encoding(false));

        Console.WriteLine(md);
        Console.WriteLine();
        Console.WriteLine($"已写入: {Path.GetFullPath(opt.OutPath)}");
        return 0;
    }

    private static readonly string[] InfraExes =
    [
        "svchost.exe", "conhost.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "smss.exe",
        "services.exe", "lsass.exe", "dwm.exe", "fontdrvhost.exe", "RuntimeBroker.exe", "SearchProtocolHost.exe",
        "SearchFilterHost.exe", "sihost.exe", "taskhostw.exe", "ctfmon.exe", "SecurityHealthSystray.exe",
        "WmiPrvSE.exe", "dllhost.exe", "audiodg.exe", "spoolsv.exe", "winlogon.exe", "SearchIndexer.exe",
        "backgroundTaskHost.exe", "ShellExperienceHost.exe", "StartMenuExperienceHost.exe", "TextInputHost.exe",
        "ApplicationFrameHost.exe", "MoUsoCoreWorker.exe", "SystemSettings.exe", "LockApp.exe",
        // 探针自身，避免把观察者算成被观察对象
        "etw-proc.exe", "win-evt.exe", "probe-report.exe", "ident.exe",
    ];

    private static bool IsInfra(string exe)
    {
        if (string.IsNullOrEmpty(exe)) return true;
        return InfraExes.Contains(exe, StringComparer.OrdinalIgnoreCase);
    }

    private static readonly Dictionary<string, string> NameCache = new(StringComparer.OrdinalIgnoreCase);

    private static string DisplayName(string? imagePath, string exe)
    {
        if (!string.IsNullOrEmpty(imagePath) && NameCache.TryGetValue(imagePath, out var cached)) return cached;
        var name = Path.GetFileNameWithoutExtension(exe);
        if (!string.IsNullOrEmpty(imagePath))
        {
            try
            {
                if (File.Exists(imagePath))
                {
                    var vi = FileVersionInfo.GetVersionInfo(imagePath);
                    var display = vi.FileDescription ?? vi.ProductName;
                    if (!string.IsNullOrWhiteSpace(display)) name = display!.Trim();
                }
            }
            catch { /* 读不到就用文件名 */ }
        }
        if (!string.IsNullOrEmpty(imagePath)) NameCache[imagePath] = name;
        return name;
    }

    private static int Ms(long ticks, long freq) => (int)Math.Round(ticks * 1000.0 / freq);

    private static DateTime LocalTime(string iso) =>
        DateTime.TryParse(iso, null, System.Globalization.DateTimeStyles.RoundtripKind, out var dt)
            ? dt.ToLocalTime()
            : DateTime.Now;

    private static List<Evt> Load(string path)
    {
        var list = new List<Evt>(4096);
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using var reader = new StreamReader(fs, Encoding.UTF8);
        while (reader.ReadLine() is { } line)
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            try
            {
                using var doc = JsonDocument.Parse(line);
                var root = doc.RootElement;
                var e = new Evt
                {
                    Src = Str(root, "src"),
                    Kind = Str(root, "kind"),
                    Qpc = Long(root, "qpc"),
                    Pid = (int)Long(root, "pid"),
                    Ppid = (int)Long(root, "ppid"),
                    Psn = Long(root, "psn"),
                    Exe = Str(root, "exe"),
                    ImagePath = Str(root, "imagePath"),
                    HwndStr = Str(root, "hwnd"),
                    TitleMasked = Str(root, "titleMasked"),
                    ClassName = Str(root, "class"),
                    Via = Str(root, "via"),
                    HandleProbe = Str(root, "handleProbe"),
                    PackageFullName = Str(root, "packageFullName"),
                    Ts = Str(root, "ts"),
                    EventId = (int)Long(root, "eventId"),
                };
                if (root.TryGetProperty("payloadNames", out var pn) && pn.ValueKind == JsonValueKind.Array)
                {
                    foreach (var x in pn.EnumerateArray())
                        e.PayloadNames.Add(x.GetString() ?? "");
                }
                list.Add(e);
            }
            catch { /* 跳过坏行 */ }
        }
        return list;
    }

    private static Dictionary<string, string> ReadCounters(string path)
    {
        var d = new Dictionary<string, string>();
        if (!File.Exists(path)) return d;
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            Flatten(doc.RootElement, "", d);
        }
        catch { /* 忽略 */ }
        return d;
    }

    private static void Flatten(JsonElement e, string prefix, Dictionary<string, string> into)
    {
        switch (e.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var p in e.EnumerateObject()) Flatten(p.Value, prefix.Length == 0 ? p.Name : $"{prefix}.{p.Name}", into);
                break;
            case JsonValueKind.Array:
                into[prefix] = $"[{e.GetArrayLength()} 项]";
                break;
            default:
                into[prefix] = e.ToString();
                break;
        }
    }

    private static string Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";

    private static long Long(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetInt64() : 0;
}

internal sealed class Evt
{
    public string Src = "", Kind = "", Exe = "", ImagePath = "", HwndStr = "", TitleMasked = "", ClassName = "", Via = "", HandleProbe = "", PackageFullName = "", Ts = "";
    public int EventId;
    public readonly List<string> PayloadNames = new();
    public long Qpc;
    public int Pid, Ppid;
    public long Psn;
}

internal sealed record ActionPoint(long Qpc, string Ts, string HwndStr, int Pid, string TitleMasked, string ClassName, string Kind);

internal sealed record Row(long Qpc, string Ts, string HwndStr, int Pid, string TitleMasked, string ClassName, string Verdict, string? AppName, int? T1aMs, string Detail);

internal sealed class Options
{
    public string EtwPath = "out/etw-proc.jsonl";
    public string WinEvtPath = "out/win-evt.jsonl";
    public string EtwCountersPath = "out/etw-proc.counters.json";
    public string WinEvtCountersPath = "out/win-evt.counters.json";
    public string OutPath = "out/coverage.md";
    public int T0WindowMs = 1500;
    public int LaunchWindowMs = 5000;
    public long Freq = 10_000_000;
    public bool ShowHelp;

    public static Options Parse(string[] args)
    {
        var o = new Options();
        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--etw": o.EtwPath = args[++i]; break;
                case "--win": o.WinEvtPath = args[++i]; break;
                case "--out" or "-o": o.OutPath = args[++i]; break;
                case "--t0-window": o.T0WindowMs = int.Parse(args[++i]); break;
                case "--launch-window": o.LaunchWindowMs = int.Parse(args[++i]); break;
                case "--freq": o.Freq = long.Parse(args[++i]); break;
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
            probe-report —— 把 etw-proc / win-evt 的 JSONL 合成「信号覆盖率表」

            用法:
              probe-report [选项]

            选项:
                  --etw <路径>       etw-proc.jsonl（默认 out/etw-proc.jsonl）
                  --win <路径>       win-evt.jsonl（默认 out/win-evt.jsonl）
              -o, --out <路径>       报告输出（默认 out/coverage.md）
                  --t0-window <ms>   T0 向前回看窗口（默认 1500ms）
                  --launch-window <ms> T0 向后启动窗口（默认 5000ms）
                  --freq <值>        QPC 频率（默认 10000000）
              -h, --help             显示本帮助
            """);
    }
}
