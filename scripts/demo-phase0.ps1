# 阶段 0 演示：同时跑 etw-proc（需管理员）+ win-evt（当前会话），中间自动打开几个应用，
# 然后生成「信号覆盖率表」。用途是让"探针是否有效"这件事可以被眼睛直接确认。

param(
    [int]$DurationSeconds = 45,
    [string]$OutDir = "out"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$config = "Release"
$etw = Join-Path $root "src\etw-proc\bin\$config\net11.0-windows\etw-proc.exe"
$win = Join-Path $root "src\win-evt\bin\$config\net11.0-windows\win-evt.exe"
$rep = Join-Path $root "src\probe-report\bin\$config\net11.0-windows\probe-report.exe"

foreach ($p in @($etw, $win, $rep)) {
    if (-not (Test-Path $p)) { throw "缺少构建产物: $p（先执行 dotnet build AppObs.Probe.slnx -c Release）" }
}

if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }
$out = (Resolve-Path $OutDir).Path

$etwOut = Join-Path $out "etw-proc.jsonl"
$winOut = Join-Path $out "win-evt.jsonl"
$etwCounters = Join-Path $out "etw-proc.counters.json"
$winCounters = Join-Path $out "win-evt.counters.json"
$etwLog = Join-Path $out "etw-proc.log"
$winLog = Join-Path $out "win-evt.log"

Write-Host "=== 1/4 启动 etw-proc（需要 UAC 提权，请在弹窗点“是”） ==="
$etwProc = Start-Process -FilePath $etw `
    -ArgumentList @("-d", "$DurationSeconds", "-o", $etwOut, "--counters", $etwCounters, "--dump-first", "20") `
    -Verb RunAs -PassThru
if (-not $etwProc) { throw "etw-proc 启动失败（UAC 是否被取消？）" }
Start-Sleep -Seconds 2

Write-Host "=== 2/4 启动 win-evt（当前用户会话，不需要提权） ==="
$winProc = Start-Process -FilePath $win `
    -ArgumentList @("-d", "$DurationSeconds", "-o", $winOut, "--counters", $winCounters) `
    -PassThru -NoNewWindow -RedirectStandardOutput $winLog
Start-Sleep -Seconds 2

Write-Host "=== 3/4 逐个打开应用（模拟用户双击） ==="
$launches = @(
    @{ name = "记事本（Win32 新实例）";              cmd = { Start-Process notepad.exe } },
    @{ name = "计算器（UWP）";                       cmd = { Start-Process "calc.exe" } },
    @{ name = "设置（UWP）";                         cmd = { Start-Process "ms-settings:" } },
    @{ name = "资源管理器（单实例复用）";            cmd = { Start-Process explorer.exe } },
    @{ name = "再次打开设置（应判复用/热启动）";     cmd = { Start-Process "ms-settings:" } },
    @{ name = "Edge（多进程归并测试）";              cmd = { Start-Process "msedge.exe" } },
    @{ name = "再次打开记事本（新实例，非复用）";    cmd = { Start-Process notepad.exe } },
    @{ name = "控制面板（控制面板宿主）";            cmd = { Start-Process control.exe } },
    @{ name = "字符映射表（System32 小工具）";        cmd = { Start-Process charmap.exe } },
    @{ name = "截图工具（MSIX 打包）";                cmd = { Start-Process "snippingtool.exe" } },
    @{ name = "命令提示符（控制台进程）";            cmd = { Start-Process cmd.exe } },
    @{ name = "Windows PowerShell（控制台进程）";    cmd = { Start-Process powershell.exe } }
)

foreach ($l in $launches) {
    Write-Host ("  -> 打开 " + $l.name)
    try { & $l.cmd } catch { Write-Host ("     启动失败: " + $_.Exception.Message) }
    Start-Sleep -Seconds 4
}

Write-Host "=== 4/4 等待采集结束 ==="
$winProc.WaitForExit(($DurationSeconds + 25) * 1000) | Out-Null
try { $etwProc.WaitForExit(($DurationSeconds + 25) * 1000) | Out-Null } catch { }

# 兜底：若探针因故未退出，强制结束，避免文件锁
foreach ($p in @($winProc, $etwProc)) {
    try { if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } } catch { }
}
Start-Sleep -Milliseconds 500

# 清理演示期间打开的窗口，避免影响后续
Get-Process notepad, charmap, snippingtool -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "=== 生成覆盖率报告 ==="
& $rep --etw $etwOut --win $winOut -o (Join-Path $out "coverage.md")

if (Test-Path $etwLog) { Write-Host "`n--- etw-proc 日志 ---"; Get-Content $etwLog -Encoding UTF8 -ErrorAction SilentlyContinue }
