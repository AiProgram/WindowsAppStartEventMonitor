# 阶段 0 · 信号覆盖率实测

> 生成时间：2026-11-19T19:43:56.5508767+08:00　|　ETW 记录：`out\edge-etw.jsonl`　|　WinEvent 记录：`out\edge-win.jsonl`

## 1. 覆盖结论

| 指标 | 值 | 说明 |
|---|---|---|
| 用户动作（T0 去重后） | 2 | Foreground + Shell 激活，同 hwnd 300ms 去重 |
| A 级命中（ETW+WinEvent 同 PID） | 1 | 强证据，可直接判「用户发起」 |
| B 级命中（窗口有、PID 不同） | 0 | 宿主归并 / 子进程归因 |
| C 级（仅窗口，无进程事件） | 1 | 复用/热启动，或 ETW 漏报 |
| 进程创建总数 | 20 | 含系统进程 |
| 应用级进程创建 | 13 | 已剔除基础设施进程 |
| 未见窗口的进程创建 | 12 | 系统拉起 / 后台任务 / 窗口事件未捕获 |
| **A 级覆盖率** | **50%** | A / 用户动作 |
| **多报动作数（时间窗内 >1 个应用进程）** | **1 / 2** | 一次动作被记成多次打开的规模 |
| 单次动作最大进程扇出 | 11 | 多进程归并要处理的量级 |

## 1.5 ProcessStart 实际字段（本机实测）

| 序 | 字段名 |
|---|---|
| 0 | `ProcessID` |
| 1 | `ProcessSequenceNumber` |
| 2 | `CreateTime` |
| 3 | `ParentProcessID` |
| 4 | `ParentProcessSequenceNumber` |
| 5 | `SessionID` |
| 6 | `Flags` |
| 7 | `ProcessTokenElevationType` |
| 8 | `ProcessTokenIsElevated` |

> 实测：本机 v4 的 ProcessStart **不含** `ImageFileName` / `PackageFullName` / `MandatoryLabel`。
> 镜像路径与包身份只能靠 `OpenProcess` + `QueryFullProcessImageNameW` + `GetPackageFullName` 补齐。

## 2. ETW 侧计数器
| 计数器 | 值 |
|---|---|
| `tool` | etw-proc |
| `sessionMode` | manifest |
| `sessionName` | AppObsProbe |
| `durationMs` | 33971.6 |
| `eventsTotal` | 26 |
| `processStart` | 20 |
| `processStop` | 6 |
| `processDCStart` | 0 |
| `imageLoad` | 0 |
| `otherEvents` | 0 |
| `byProvider.Microsoft-Windows-Kernel-Process` | 26 |
| `byEventName.ProcessStart/开始#1v4` | 20 |
| `byEventName.ProcessStop/停止#2v2` | 6 |
| `etwEventsLost` | 1 |
| `buffersWritten` | 0 |
| `freeBuffers` | 138412288 |
| `realTimeBuffersLost` | 1024 |
| `countersQueryRc` | 0 |
| `handleProbeOk` | 18 |
| `handleProbeDenied` | 2 |
| `parseNsP50` | 711600 |
| `parseNsP99` | 71360200 |
| `deliveryLagMsP50` | 1878.2 |
| `deliveryLagMsP99` | 2977.1 |
| `parseFailures` | 0 |
| `recordsWritten` | 46 |
| `recordsDropped` | 0 |
| `clockFrequency` | 10000000 |

## 3. 窗口侧计数器

| 计数器 | 值 |
|---|---|
| `durationMs` | 30000 |
| `recordsWritten` | 72 |
| `dropped` | 0 |
| `objectEvents` | 53 |
| `distinctWindows` | 39 |
| `hooks.foreground` | True |
| `hooks.objects` | True |
| `hooks.shellHook` | True |
| ObjCreate | 35 |
| Event0x800B | 3 |
| ShellMonitorChanged | 6 |
| ShellRedraw | 7 |
| Event0x800C | 4 |
| ShellWindowCreated | 1 |
| ObjShow | 1 |
| Foreground | 2 |
| ShellWindowActivated | 2 |
| Event0x800A | 2 |
| ObjCloaked | 3 |
| ObjDestroy | 5 |
| ShellWindowDestroyed | 1 |

## 4. 时间线（前 60 个动作）

| # | T0 (本地) | 窗口类 | 窗口 pid | 应用 | 结论 | T1a−T0 (ms) |
|---|---|---|---|---|---|---|
| 1 | 19:42:08.151 | Chrome_WidgetWin_1 | 18796 | Microsoft Edge | A：ETW+WinEvent 同 PID | -403 |
| 2 | 19:42:28.664 | Chrome_WidgetWin_1 | 14784 | - | C：仅 WinEvent，无进程事件 | - |

## 5. 未见窗口的进程创建（前 40，按时间）

| 时间 | pid | ppid | 应用 |
|---|---|---|---|
| 19:42:07.816 | 16780 | 18796 | msedge.exe |
| 19:42:07.894 | 4036 | 18796 | msedge.exe |
| 19:42:07.900 | 10096 | 18796 | msedge.exe |
| 19:42:07.949 | 18944 | 18796 | msedge.exe |
| 19:42:08.093 | 1640 | 18796 | msedge.exe |
| 19:42:08.093 | 7112 | 18796 | msedge.exe |
| 19:42:11.030 | 20516 | 18796 | msedge.exe |
| 19:42:11.907 | 18768 | 18796 | msedge.exe |
| 19:42:11.967 | 13540 | 18796 | identity_helper.exe |
| 19:42:12.917 | 2780 | 18796 | msedge.exe |
| 19:42:17.832 | 18556 | 18796 | msedge.exe |
| 19:42:18.978 | 7300 | 1316 | smartscreen.exe |

## 6. 进程创建的按应用分布（多进程归并的输入）

| 应用 | 进程数 | exe |
|---|---|---|
| Microsoft Edge | 11 | msedge.exe |
| PWA Identity Proxy Host | 1 | identity_helper.exe |
| Microsoft Defender SmartScreen | 1 | smartscreen.exe |

## 7. 父进程归并（同一 ppid 的进程组 = 一次动作）

| ppid | 子进程数 | 子进程 exe |
|---|---|---|
| 18796 | 11 | msedge.exe, identity_helper.exe |
| 7912 | 1 | msedge.exe |
| 1316 | 1 | smartscreen.exe |
