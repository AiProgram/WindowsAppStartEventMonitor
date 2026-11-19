using System.Diagnostics;
using System.Reflection;
using System.Text;
using AppObs.Probe.Common;
using Microsoft.Win32;

namespace Ident;

/// <summary>
/// 阶段 0 探针 3/3：身份解析链（主报告 §7 六级顺序，先到先得且逐级记录来源）。
/// 输入一个 PID（或 exe 路径），把「这是什么应用」走到能用的答案，并明确报告哪一级命中。
/// </summary>
internal static class Program
{
    private static int Main(string[] args)
    {
        Log.InitConsole();
        var opt = Options.Parse(args);
        if (opt.ShowHelp) { Options.PrintHelp(); return 0; }

        if (opt.Pid <= 0 && string.IsNullOrEmpty(opt.ExePath) && string.IsNullOrEmpty(opt.LnkPath))
        {
            Options.PrintHelp();
            return 1;
        }

        var result = new Dictionary<string, object?>
        {
            ["tool"] = "ident",
            ["input"] = opt.Pid > 0 ? $"pid:{opt.Pid}" : (opt.ExePath ?? opt.LnkPath),
        };

        var chain = new List<Dictionary<string, object?>>();
        result["levels"] = chain;

        var identity = new Dictionary<string, object?>
        {
            ["kind"] = "unknown",
            ["displayName"] = null,
            ["exePath"] = null,
            ["exeKey"] = null,
            ["packageFullName"] = null,
            ["aumid"] = null,
            ["productName"] = null,
            ["fileDescription"] = null,
            ["companyName"] = null,
            ["fileVersion"] = null,
        };
        result["appIdentity"] = identity;

        var missing = new List<string>();
        double confidence = 0;
        var note = new Dictionary<string, object?>();

        IntPtr hProcess = IntPtr.Zero;
        string? exePath = opt.ExePath;

        try
        {
            // ---- 第 1 级：ETW 事件自带的 PackageFullName（零句柄、零成本）----
            if (!string.IsNullOrEmpty(opt.PackageFullName))
            {
                identity["kind"] = "appx";
                identity["packageFullName"] = opt.PackageFullName;
                identity["aumid"] = opt.PackageRelativeAppId;
                chain.Add(new() { ["level"] = 1, ["source"] = "etw.ProcessStart", ["hit"] = true, ["value"] = opt.PackageFullName });
                confidence = 0.98;
                if (!string.IsNullOrEmpty(opt.ImagePath))
                {
                    exePath = PathNormalizer.Normalize(opt.ImagePath, out var u);
                    identity["exePath"] = exePath;
                    note["devicePathUnresolved"] = u;
                }
            }
            else
            {
                chain.Add(new() { ["level"] = 1, ["source"] = "etw.ProcessStart", ["hit"] = false, ["reason"] = "事件未携带 PackageFullName（未打包或未提供）" });
            }

            if (opt.Pid > 0 && identity["kind"] as string != "appx")
            {
                hProcess = Native.OpenProcess(Native.PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)opt.Pid);
                if (hProcess == IntPtr.Zero)
                {
                    var err = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                    result["handleOpen"] = "denied";
                    result["handleOpenError"] = err;
                    chain.Add(new() { ["level"] = 2, ["source"] = "OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)", ["hit"] = false, ["error"] = err });
                    missing.Add("processHandle");
                }
                else
                {
                    result["handleOpen"] = "ok";

                    // ---- 第 2 级：OpenProcess + GetPackageFullName / GetApplicationUserModelId ----
                    var pfn = TryGetPackageFullName(hProcess, out var pfnErr);
                    if (!string.IsNullOrEmpty(pfn))
                    {
                        identity["kind"] = "appx";
                        identity["packageFullName"] = pfn;
                        identity["aumid"] = TryGetAumid(hProcess);
                        chain.Add(new() { ["level"] = 2, ["source"] = "GetPackageFullName", ["hit"] = true, ["value"] = pfn });
                        confidence = 0.95;
                    }
                    else if (pfnErr == Native.APPMODEL_ERROR_NO_PACKAGE)
                    {
                        chain.Add(new() { ["level"] = 2, ["source"] = "GetPackageFullName", ["hit"] = false, ["reason"] = "APPMODEL_ERROR_NO_PACKAGE(15700) → 非打包应用" });
                    }
                    else
                    {
                        chain.Add(new() { ["level"] = 2, ["source"] = "GetPackageFullName", ["hit"] = false, ["error"] = pfnErr });
                    }

                    // ---- 第 3 级：QueryFullProcessImageNameW ----
                    var full = TryGetImagePath(hProcess);
                    if (!string.IsNullOrEmpty(full))
                    {
                        exePath = PathNormalizer.Normalize(full, out var unresolved);
                        note["devicePathUnresolved"] = unresolved;
                        chain.Add(new() { ["level"] = 3, ["source"] = "QueryFullProcessImageNameW", ["hit"] = true, ["value"] = exePath });
                        if (TryGetProcessCreateTime(hProcess, out var createTime))
                            result["processCreateTimeUtc"] = DateTime.FromFileTimeUtc(createTime).ToString("O");
                    }
                    else
                    {
                        var err = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                        chain.Add(new() { ["level"] = 3, ["source"] = "QueryFullProcessImageNameW", ["hit"] = false, ["error"] = err });
                    }
                }
            }

            // ---- 第 4 级：版本资源（展示名；按 (path,size,mtime) 缓存是生产要求，这里单次调用）----
            if (!string.IsNullOrEmpty(exePath) && File.Exists(exePath))
            {
                var vi = TryVersionInfo(exePath);
                if (vi is not null)
                {
                    identity["fileDescription"] = vi.FileDescription;
                    identity["productName"] = vi.ProductName;
                    identity["companyName"] = vi.CompanyName;
                    identity["fileVersion"] = vi.FileVersion;
                    var display = FirstNonEmpty(vi.FileDescription, vi.ProductName, vi.OriginalFilename);
                    if (!string.IsNullOrEmpty(display))
                    {
                        identity["displayName"] = display;
                        chain.Add(new() { ["level"] = 4, ["source"] = "GetFileVersionInfoW", ["hit"] = true, ["value"] = display });
                        if (confidence < 0.9) confidence = 0.9;
                    }
                    else
                    {
                        missing.Add("versionInfo.displayName");
                        chain.Add(new() { ["level"] = 4, ["source"] = "GetFileVersionInfoW", ["hit"] = false, ["reason"] = "版本资源存在但 FileDescription/ProductName/OriginalFilename 全空" });
                    }
                }
                else
                {
                    missing.Add("versionInfo");
                    chain.Add(new() { ["level"] = 4, ["source"] = "GetFileVersionInfoW", ["hit"] = false, ["reason"] = "无版本资源或读取失败" });
                }
            }

            // ---- 第 5 级：Shell 层兜底（.lnk 解析、App Paths）----
            var shell = new Dictionary<string, object?>();
            if (!string.IsNullOrEmpty(opt.LnkPath))
            {
                var target = TryResolveLnk(opt.LnkPath);
                shell["lnkTarget"] = target;
                if (!string.IsNullOrEmpty(target))
                {
                    exePath = target;
                    chain.Add(new() { ["level"] = 5, ["source"] = "IShellLink/.lnk", ["hit"] = true, ["value"] = target });
                    if (confidence < 0.85) confidence = 0.85;
                }
            }
            if (!string.IsNullOrEmpty(exePath))
            {
                var appPath = TryAppPaths(PathNormalizer.FileNameOf(exePath));
                if (!string.IsNullOrEmpty(appPath))
                {
                    shell["appPaths"] = appPath;
                    chain.Add(new() { ["level"] = 5, ["source"] = "App Paths", ["hit"] = true, ["value"] = appPath });
                }
            }
            if (shell.Count > 0) result["shellLayer"] = shell;

            // ---- 第 6 级：兜底（不猜、不用窗口标题）----
            if (string.IsNullOrEmpty(identity["displayName"] as string) && !string.IsNullOrEmpty(exePath))
            {
                identity["displayName"] = PathNormalizer.FileNameOf(exePath);
                chain.Add(new() { ["level"] = 6, ["source"] = "filename", ["hit"] = true, ["value"] = identity["displayName"] });
            }
            if (confidence == 0) confidence = 0.3;

            if (!string.IsNullOrEmpty(exePath))
            {
                identity["exePath"] = exePath;
                identity["exeKey"] = PathNormalizer.Key(exePath);
                if (identity["kind"] as string == "unknown") identity["kind"] = IsAppxFriendly(exePath) ? "appx-host" : "win32";
            }
        }
        finally
        {
            if (hProcess != IntPtr.Zero) Native.CloseHandle(hProcess);
        }

        identity["confidence"] = Math.Round(confidence, 2);
        result["missing"] = missing;
        result["pathNotes"] = note;
        result["existsOnDisk"] = !string.IsNullOrEmpty(exePath) && File.Exists(exePath);

        var json = System.Text.Json.JsonSerializer.Serialize(result,
            new System.Text.Json.JsonSerializerOptions
            {
                WriteIndented = true,
                Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            });

        if (!string.IsNullOrEmpty(opt.OutPath))
        {
            var dir = Path.GetDirectoryName(Path.GetFullPath(opt.OutPath));
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            File.AppendAllText(opt.OutPath, System.Text.Json.JsonSerializer.Serialize(result,
                new System.Text.Json.JsonSerializerOptions { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping }) + Environment.NewLine);
        }

        Console.WriteLine(json);
        return identity["kind"] as string is "unknown" ? 4 : 0;
    }

    private static bool IsAppxFriendly(string path) =>
        path.Contains(@"\WindowsApps\", StringComparison.OrdinalIgnoreCase) ||
        path.Contains(@"\ApplicationFrameHost.exe", StringComparison.OrdinalIgnoreCase);

    private static string? FirstNonEmpty(params string?[] values) =>
        values.FirstOrDefault(v => !string.IsNullOrWhiteSpace(v));

    private static string? TryGetPackageFullName(IntPtr hProcess, out int error)
    {
        error = 0;
        uint len = 0;
        var rc = Native.GetPackageFullName(hProcess, ref len, null);
        if (rc == Native.APPMODEL_ERROR_NO_PACKAGE) { error = rc; return null; }
        if (rc != Native.ERROR_INSUFFICIENT_BUFFER && rc != 0) { error = rc; return null; }
        if (len == 0) { error = rc; return null; }

        var sb = new StringBuilder((int)len);
        rc = Native.GetPackageFullName(hProcess, ref len, sb);
        if (rc != 0) { error = rc; return null; }
        return sb.ToString();
    }

    private static string? TryGetAumid(IntPtr hProcess)
    {
        uint len = 0;
        var rc = Native.GetApplicationUserModelId(hProcess, ref len, null);
        if (rc != Native.ERROR_INSUFFICIENT_BUFFER && rc != 0) return null;
        if (len == 0) return null;
        var sb = new StringBuilder((int)len);
        rc = Native.GetApplicationUserModelId(hProcess, ref len, sb);
        return rc == 0 ? sb.ToString() : null;
    }

    private static string? TryGetImagePath(IntPtr hProcess)
    {
        var sb = new StringBuilder(1024);
        uint size = (uint)sb.Capacity;
        return Native.QueryFullProcessImageNameW(hProcess, 0, sb, ref size) ? sb.ToString() : null;
    }

    private static bool TryGetProcessCreateTime(IntPtr hProcess, out long fileTime)
    {
        fileTime = 0;
        if (!Native.GetProcessTimes(hProcess, out var c, out _, out _, out _)) return false;
        fileTime = c;
        return true;
    }

    private static FileVersionInfo? TryVersionInfo(string path)
    {
        try { return FileVersionInfo.GetVersionInfo(path); }
        catch { return null; }
    }

    /// <summary>第 5 级：.lnk 解析（生产要求用 IShellLink，这里用 WScript.Shell 快速等价实现）。</summary>
    private static string? TryResolveLnk(string lnkPath)
    {
        try
        {
            var type = Type.GetTypeFromProgID("WScript.Shell");
            if (type is null) return null;
            var shell = Activator.CreateInstance(type);
            if (shell is null) return null;
            var shortcut = type.InvokeMember("CreateShortcut", BindingFlags.InvokeMethod, null, shell, [lnkPath]);
            var target = shortcut?.GetType().InvokeMember("TargetPath", BindingFlags.GetProperty, null, shortcut, null) as string;
            return string.IsNullOrWhiteSpace(target) ? null : target;
        }
        catch { return null; }
    }

    /// <summary>第 5 级：App Paths 反查（HKCU 优先于 HKLM）。</summary>
    private static string? TryAppPaths(string exeName)
    {
        if (string.IsNullOrEmpty(exeName)) return null;
        foreach (var hive in new[] { RegistryHive.CurrentUser, RegistryHive.LocalMachine })
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
                using var key = baseKey.OpenSubKey($@"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{exeName}");
                if (key?.GetValue(null) is string v && !string.IsNullOrWhiteSpace(v)) return v;
            }
            catch { /* 忽略 */ }
        }
        return null;
    }
}

internal sealed class Options
{
    public int Pid;
    public string? ExePath;
    public string? LnkPath;
    public string? PackageFullName;
    public string? PackageRelativeAppId;
    public string? ImagePath;
    public string OutPath = "out/ident.jsonl";
    public bool ShowHelp;

    public static Options Parse(string[] args)
    {
        var o = new Options();
        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--pid" or "-p": o.Pid = int.Parse(args[++i]); break;
                case "--exe" or "-e": o.ExePath = args[++i]; break;
                case "--lnk": o.LnkPath = args[++i]; break;
                case "--pfn": o.PackageFullName = args[++i]; break;
                case "--praid": o.PackageRelativeAppId = args[++i]; break;
                case "--image": o.ImagePath = args[++i]; break;
                case "--out" or "-o": o.OutPath = args[++i]; break;
                case "--help" or "-h" or "/?": o.ShowHelp = true; break;
                default:
                    if (int.TryParse(args[i], out var pid)) { o.Pid = pid; break; }
                    if (args[i].EndsWith(".lnk", StringComparison.OrdinalIgnoreCase)) { o.LnkPath = args[i]; break; }
                    if (args[i].EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) { o.ExePath = args[i]; break; }
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
            ident —— 阶段 0 探针：六级身份解析链

            用法:
              ident <pid>
              ident --pid <pid> [--pfn <PackageFullName>] [--praid <AppId>] [--image <路径>]
              ident --exe <exe 路径>
              ident --lnk <快捷方式路径>

            选项:
              -p, --pid <pid>    目标进程 ID
              -e, --exe <路径>   直接给 exe 路径（跳过 1–3 级）
                  --lnk <路径>   解析快捷方式（第 5 级）
                  --pfn <名>     模拟第 1 级：用 ETW 事件里已有的 PackageFullName
                  --praid <id>   配合 --pfn 的 PackageRelativeAppId
                  --image <路径> 配合 --pfn 的镜像路径
              -o, --out <路径>   追加 JSONL 结果（默认 out/ident.jsonl）
              -h, --help         显示本帮助
            """);
    }
}
