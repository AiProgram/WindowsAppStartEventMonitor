using System.Text.Json;

namespace AppObs.Probe.Common;

/// <summary>
/// 单调时钟封装。所有时间戳以 QPC 为准（主报告 §3 的硬规则：不依赖到达顺序、不用系统时间排序），
/// 同时派生一个便于人读的 UTC 时间；跨进程合并时以 QPC 为准（同一次开机内 QPC 全机一致）。
/// </summary>
public static class ProbeClock
{
    public static long Frequency { get; }
    public static long AnchorQpc { get; private set; }
    public static DateTime AnchorUtc { get; private set; }

    static ProbeClock()
    {
        Native.QueryPerformanceFrequency(out var freq);
        Frequency = freq;
        Reanchor();
    }

    /// <summary>以当前时刻重新锚定 wall clock（进程启动时调用一次）。</summary>
    public static void Reanchor()
    {
        Native.QueryPerformanceCounter(out var qpc);
        AnchorQpc = qpc;
        AnchorUtc = DateTime.UtcNow;
    }

    public static long Now()
    {
        Native.QueryPerformanceCounter(out var qpc);
        return qpc;
    }

    public static DateTime ToUtc(long qpc)
    {
        var deltaSeconds = (qpc - AnchorQpc) / (double)Frequency;
        return AnchorUtc.AddSeconds(deltaSeconds);
    }

    /// <summary>把事件自带的时间戳映射回 QPC，用于跨进程对齐（避免把投递延迟算成启动耗时）。</summary>
    public static long FromUtc(DateTime utc)
    {
        var deltaSeconds = (utc - AnchorUtc).TotalSeconds;
        return AnchorQpc + (long)(deltaSeconds * Frequency);
    }

    /// <summary>
    /// 解析事件时间戳。不同 provider / 不同 TraceEvent 版本可能给出 UTC 或「本地时间冒充 UTC」，
    /// 这里同时算两种解释，取离当前时刻更近的那个 —— 错 8 小时会直接毁掉跨进程配对。
    /// </summary>
    public static long ResolveEventQpc(DateTime stamp)
    {
        var now = Now();
        var asUtc = FromUtc(DateTime.SpecifyKind(stamp, DateTimeKind.Utc));
        long asLocal;
        try
        {
            asLocal = FromUtc(DateTime.SpecifyKind(stamp, DateTimeKind.Local).ToUniversalTime());
        }
        catch { return asUtc; }

        return Math.Abs(now - asUtc) <= Math.Abs(now - asLocal) ? asUtc : asLocal;
    }

    public static double Ms(long deltaTicks) => deltaTicks * 1000.0 / Frequency;
}

/// <summary>线程安全的 JSONL 输出。写失败不抛，只累计 dropped，避免探针自身拖垮被测系统。</summary>
public sealed class JsonlSink : IDisposable
{
    private static readonly JsonSerializerOptions Opts = new()
    {
        WriteIndented = false,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    private StreamWriter? _writer;
    private readonly object _lock = new();
    private long _written;
    private long _dropped;

    public string Path { get; }
    public long Written => Interlocked.Read(ref _written);
    public long Dropped => Interlocked.Read(ref _dropped);

    public JsonlSink(string path)
    {
        Path = System.IO.Path.GetFullPath(path);
        var dir = System.IO.Path.GetDirectoryName(Path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        _writer = new StreamWriter(new FileStream(Path, FileMode.Create, FileAccess.Write, FileShare.ReadWrite),
            new System.Text.UTF8Encoding(false)) { AutoFlush = false };
    }

    public void Write(Dictionary<string, object?> record)
    {
        string json;
        try { json = JsonSerializer.Serialize(record, Opts); }
        catch (Exception) { Interlocked.Increment(ref _dropped); return; }

        lock (_lock)
        {
            var w = _writer;
            if (w is null) { Interlocked.Increment(ref _dropped); return; }
            try
            {
                w.WriteLine(json);
                var n = Interlocked.Increment(ref _written);
                if ((n & 0x3FF) == 0) w.Flush();
            }
            catch (Exception) { Interlocked.Increment(ref _dropped); }
        }
    }

    public void Flush()
    {
        lock (_lock) { try { _writer?.Flush(); } catch { /* ignored */ } }
    }

    public void Dispose()
    {
        lock (_lock)
        {
            try { _writer?.Flush(); _writer?.Dispose(); } catch { /* ignored */ }
            _writer = null;
        }
    }
}

/// <summary>构造输出记录的辅助方法，统一字段顺序（ts/qpc/src/kind 在前）。</summary>
public static class Rec
{
    public static Dictionary<string, object?> New(string src, string kind, long qpc)
    {
        var d = new Dictionary<string, object?>(16)
        {
            ["src"] = src,
            ["kind"] = kind,
            ["qpc"] = qpc,
            ["ts"] = ProbeClock.ToUtc(qpc).ToString("O"),
        };
        return d;
    }

    public static Dictionary<string, object?> Put(this Dictionary<string, object?> d, string key, object? value)
    {
        d[key] = value;
        return d;
    }
}
