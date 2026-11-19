# 专门测试 Edge 的多进程扇出：先确保没有残留 msedge，再冷启动一次浏览器，
# 采集 30 秒后输出 GPU/renderer/network 等子进程的扇出情况。

param(
    [int]$DurationSeconds = 30,
    [string]$OutDir = "out"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$etw = Join-Path $root "src\etw-proc\bin\Release\net11.0-windows\etw-proc.exe"
$win = Join-Path $root "src\win-evt\bin\Release\net11.0-windows\win-evt.exe"
$rep = Join-Path $root "src\probe-report\bin\Release\net11.0-windows\probe-report.exe"
foreach ($p in @($etw, $win, $rep)) {
    if (-not (Test-Path $p)) { throw "缺少构建产物: $p" }
}

if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }
$out = (Resolve-Path $OutDir).Path

Write-Host "=== 0/4 清空残留 Edge ==="
$killed = 0
Get-Process msedge -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.Id -Force; $killed++ }
Start-Sleep -Seconds 2
Write-Host "  已结束 $killed 个 msedge 进程，当前剩余 $((Get-Process msedge -ErrorAction SilentlyContinue | Measure-Object).Count)"

$etwOut = Join-Path $out "edge-etw.jsonl"
$winOut = Join-Path $out "edge-win.jsonl"
$etwCounters = Join-Path $out "edge-etw.counters.json"
$winCounters = Join-Path $out "edge-win.counters.json"

Write-Host "=== 1/4 启动 etw-proc（UAC 提权） ==="
$etwProc = Start-Process -FilePath $etw `
    -ArgumentList @("-d", "$DurationSeconds", "-o", $etwOut, "--counters", $etwCounters, "--dump-first", "30") `
    -Verb RunAs -PassThru
Start-Sleep -Seconds 2

Write-Host "=== 2/4 启动 win-evt ==="
$winProc = Start-Process -FilePath $win `
    -ArgumentList @("-d", "$DurationSeconds", "-o", $winOut, "--counters", $winCounters) `
    -PassThru -NoNewWindow
Start-Sleep -Seconds 2

Write-Host "=== 3/4 冷启动 Edge（第一次动作） ==="
$before = Get-Process msedge -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count
Start-Process "msedge.exe" | Out-Null
Start-Sleep -Seconds 10
$afterFirst = Get-Process msedge -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count
Write-Host "  msedge 进程数：$before -> $afterFirst（一次动作的扇出）"

Write-Host "=== 3b/4 再开一个标签页（第二次动作，应复用浏览器主进程） ==="
Start-Process "msedge.exe" -ArgumentList "about:blank" | Out-Null
Start-Sleep -Seconds 10
$afterSecond = Get-Process msedge -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count
Write-Host "  msedge 进程数：$afterFirst -> $afterSecond"

Write-Host "=== 4/4 等待采集结束 ==="
$winProc.WaitForExit(($DurationSeconds + 25) * 1000) | Out-Null
try { $etwProc.WaitForExit(($DurationSeconds + 25) * 1000) | Out-Null } catch { }
foreach ($p in @($winProc, $etwProc)) {
    try { if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } } catch { }
}
Start-Sleep -Milliseconds 500

Write-Host ""
Write-Host "=== 生成报告 ==="
& $rep --etw $etwOut --win $winOut -o (Join-Path $out "coverage-edge.md")
