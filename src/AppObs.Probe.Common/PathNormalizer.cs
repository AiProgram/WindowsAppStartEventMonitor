using System.Text;

namespace AppObs.Probe.Common;

/// <summary>
/// 路径规范化（主报告 §7 六条硬规则的最小实现）：
/// 设备路径→盘符、环境变量展开、8.3 短名展开、统一 \\?\ 键形式、OrdinalIgnoreCase 大小写归一。
/// 映射不到时保留原样并标 devicePathUnresolved，绝不盲目替换成 C:。
/// </summary>
public static class PathNormalizer
{
    private static readonly Lazy<Dictionary<string, string>> DeviceToDrive = new(BuildDeviceMap);

    private static Dictionary<string, string> BuildDeviceMap()
    {
        var map = new Dictionary<string, string>(64, StringComparer.OrdinalIgnoreCase);
        var buf = new char[2048];
        for (var c = 'A'; c <= 'Z'; c++)
        {
            var dev = $"{c}:";
            uint len;
            try { len = Native.QueryDosDeviceW(dev, buf, (uint)buf.Length); }
            catch { continue; }
            if (len == 0) continue;

            var target = new string(buf, 0, (int)Math.Min(len, (uint)buf.Length)).TrimEnd('\0');
            var first = target.Split('\0')[0].TrimEnd('\\');
            if (first.Length == 0) continue;

            // \Device\HarddiskVolume3  →  C:\
            if (!map.ContainsKey(first + "\\")) map[first + "\\"] = dev + "\\";
        }
        return map;
    }

    /// <summary>把 ETW 的 \Device\HarddiskVolumeN\... 转成盘符路径。</summary>
    public static string FromDevicePath(string raw, out bool unresolved)
    {
        unresolved = false;
        if (string.IsNullOrEmpty(raw)) return raw;

        if (!raw.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
            return raw;

        var best = string.Empty;
        var bestDrive = string.Empty;
        foreach (var (dev, drive) in DeviceToDrive.Value)
        {
            if (raw.StartsWith(dev, StringComparison.OrdinalIgnoreCase) && dev.Length > best.Length)
            {
                best = dev;
                bestDrive = drive;
            }
        }

        if (best.Length == 0)
        {
            unresolved = true;
            return raw;
        }
        return bestDrive + raw[best.Length..];
    }

    /// <summary>规范化展示路径：设备路径→盘符、展开环境变量、展开 8.3 短名（存在时）。</summary>
    public static string Normalize(string raw, out bool devicePathUnresolved)
    {
        if (string.IsNullOrWhiteSpace(raw)) { devicePathUnresolved = false; return string.Empty; }

        var p = FromDevicePath(raw, out devicePathUnresolved);

        try { p = Environment.ExpandEnvironmentVariables(p); }
        catch { /* 保持原样 */ }

        if (p.StartsWith(@"\??\", StringComparison.Ordinal))
            p = p[4..];
        else if (p.StartsWith(@"\\?\", StringComparison.Ordinal))
            p = p[4..];

        // 8.3 短名展开：仅对存在的路径调用，失败即忽略
        try
        {
            if (Path.IsPathRooted(p) && File.Exists(p))
            {
                var buf = new char[2048];
                var n = Native.GetLongPathNameW(p, buf, (uint)buf.Length);
                if (n > 0 && n < buf.Length) p = new string(buf, 0, (int)n);
            }
        }
        catch { /* 忽略 */ }

        return p;
    }

    /// <summary>比较用键：\\?\ 前缀 + 大写 + 反斜杠统一。跨条目比较必须用这个，不要用展示路径。</summary>
    public static string Key(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return string.Empty;
        var p = path.Replace('/', '\\').TrimEnd('\\');
        if (p.StartsWith(@"\\?\", StringComparison.Ordinal)) p = p[4..];
        return @"\\?\" + p.ToUpperInvariant();
    }

    public static string FileNameOf(string path)
    {
        if (string.IsNullOrEmpty(path)) return string.Empty;
        var i = path.LastIndexOf('\\');
        return i >= 0 ? path[(i + 1)..] : path;
    }

    public static string DirectoryOf(string path)
    {
        if (string.IsNullOrEmpty(path)) return string.Empty;
        var i = path.LastIndexOf('\\');
        return i > 0 ? path[..i] : string.Empty;
    }

    /// <summary>把 \\?\ 前缀去掉用于展示。</summary>
    public static string Display(string keyOrPath) =>
        keyOrPath.StartsWith(@"\\?\", StringComparison.Ordinal) ? keyOrPath[4..] : keyOrPath;
}

/// <summary>
/// 窗口标题脱敏（主报告 §13：默认不落原文）。
/// 去掉数字、URL、路径、引号内内容，只保留模板形状。
/// </summary>
public static class TitleMasker
{
    private static readonly System.Text.RegularExpressions.Regex UrlRe =
        new(@"\b(?:https?|ftp|file)://\S+|\bwww\.\S+", System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.Compiled);

    private static readonly System.Text.RegularExpressions.Regex PathRe =
        new(@"[A-Za-z]:\\[^\s""'<>|*?]*|\\\\[^\s""'<>|*?]+|\b\\\\\?\S+", System.Text.RegularExpressions.RegexOptions.Compiled);

    private static readonly System.Text.RegularExpressions.Regex QuotedRe =
        new(@"[""「『'][^""」』']{0,120}[""」』']", System.Text.RegularExpressions.RegexOptions.Compiled);

    private static readonly System.Text.RegularExpressions.Regex NumberRe =
        new(@"\d+", System.Text.RegularExpressions.RegexOptions.Compiled);

    public static string Mask(string? title, int maxLen = 80)
    {
        if (string.IsNullOrEmpty(title)) return string.Empty;
        var s = title;
        s = UrlRe.Replace(s, "<url>");
        s = PathRe.Replace(s, "<path>");
        s = QuotedRe.Replace(s, "<q>");
        s = NumberRe.Replace(s, "#");
        s = s.Trim();
        if (s.Length > maxLen) s = s[..maxLen] + "…";
        return s;
    }
}

/// <summary>控制台输出：统一给探针的进度/告警加前缀，避免和 JSON 混看。</summary>
public static class Log
{
    /// <summary>控制台统一 UTF-8，否则中文在 CP936 终端/重定向文件里会变乱码。</summary>
    public static void InitConsole()
    {
        try
        {
            Console.OutputEncoding = System.Text.Encoding.UTF8;
            Console.InputEncoding = System.Text.Encoding.UTF8;
        }
        catch { /* 某些宿主不支持 */ }
    }

    public static void Info(string msg) => Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] {msg}");
    public static void Warn(string msg) => Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] WARN  {msg}");
    public static void Error(string msg) => Console.Error.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] ERROR {msg}");
}
