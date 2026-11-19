# WindowsAppStartEventMonitor

**Windows 10/11 桌面应用「用户发起打开」观测与启动耗时测量** —— 低开销采集架构与工程落地文档集。

本仓库以**架构与判定规则文档**为主体，并包含**阶段 0 可行性探针**的可运行实现（`src/`）。它回答两个彼此独立、且都不存在单一官方 API 可以直接回答的问题：

1. **用户打开了哪个应用？**（用户意图归因）
2. **它多久才出来？**（启动耗时分层测量，附置信度）

## 文档索引

| 文档 | 内容 | 篇幅 |
|---|---|---|
| [Windows应用启动与窗口行为监测.md](./Windows应用启动与窗口行为监测.md) | 主报告：问题定性、信号源能力盘点与硬边界、推荐架构、归因判决表、生命周期状态机、T0/T1 里程碑定义、性能估算、语言选型、分阶段路线、测试矩阵、合规、风险清单、引用来源 | 15 章 |
| [冷热启动判定规则.md](./冷热启动判定规则.md) | 主报告第六·补章的独立落地版：决策树、判据优先级（短路求值）、ETW 判定伪代码、输出字段增量、与启动耗时的正交关系、已知边界 | 6 节 |
| [docs/阶段0-可行性探针.md](./docs/阶段0-可行性探针.md) | **阶段 0 实现说明与实测结论**：三个探针工具、四个必须修正的前提假设（事件名本地化、时间戳时区、2 秒投递延迟、字段缺失）、实测覆盖率、已知缺陷 | 7 节 |
| [docs/阶段0-实测-覆盖率.md](./docs/阶段0-实测-覆盖率.md) | 阶段 0 的一次完整实测样本（12 应用、覆盖率表、时间线原始数据） | 实测报告 |
| [docs/阶段0-实测-Edge扇出.md](./docs/阶段0-实测-Edge扇出.md) | Edge 冷启动的多进程扇出专项实测（12 个进程 / 一次动作、ppid 归并、OpenProcess 拒绝） | 实测报告 |

## 核心结论（摘要）

**结论一：不存在单一 API 能同时回答"用户打开了哪个应用"和"它多久才出来"。** 必须做双层融合：内核 ETW 的 `Microsoft-Windows-Kernel-Process`（GUID `{22FB2CD6-0E7B-422B-A0C7-2fad-1fd0e716}`，keyword `0x10`）提供**不漏进程**的事实底座；而"用户发起"这一语义只能由用户会话内的辅助进程，用 WinEvent（`EVENT_SYSTEM_FOREGROUND`）+ Shell hook + UIA 焦点事件去推断——Session 0 服务在架构上被禁止触碰用户桌面。

**结论二：默认最低损耗方案 = 常驻服务只跑一个非内核 ETW 会话（Process keyword `0x10` + Image keyword `0x40`），加每会话一个 Medium IL 辅助进程。** 服务侧零 GUI、零注入、零轮询；辅助进程只订阅 WinEvent 与 `RegisterShellHookWindow`，把 `(hwnd, tid, pid, 时间戳)` 通过命名管道回传。

**结论三：启动耗时只能分层定义，其中"第一帧"在没有应用配合时不可准确观测。** 可准确观测的是 T1 进程创建与主窗口创建；"首次可见/绘制"只能得到**上界近似**。因此输出是**带置信度的区间**，不是一个看似精确的毫秒数。

**结论四：不要优先采用轮询、全局窗口钩子、DLL 注入或内核驱动。** 轮询必然漏掉毫秒级进程（架构缺陷，非调参问题）；`SetWindowsHookEx` 跨桌面无效且 `WINEVENT_INCONTEXT` 会向每个 GUI 进程注入 DLL；AMSI 与"打开应用观测"完全无关；内核驱动换来的是 EV 签名 + HLK + HVCI 的长期成本。

**结论五：语言选型上，服务用 C++ 或 Rust，辅助进程用 C#/.NET。** 服务侧要求零 GC 抖动、可控回调路径、直接面对 `EVENT_RECORD`；辅助进程要调 UIA/MSAA、COM、WinForms 消息泵。

## 推荐架构

```
Session 0（SYSTEM / 服务）                     Session 1..N（交互会话）
┌──────────────────────────┐                  ┌────────────────────────────┐
│ 采集服务（C++ / Rust）    │                  │ 辅助进程 Agent（C#/.NET）   │
│  ETW 会话 A：Kernel-Process│                  │  SetWinEventHook OUTOFCONTEXT│
│  ETW 会话 B：按需动态加挂  │◄── 命名管道 ────│  RegisterShellHookWindow     │
│  环形缓冲 + 线程池解析     │   会话 ID 命名    │  UIA：WindowOpened/Focus     │
│  身份解析（AUMID/版本资源）│   消息认证+序号   │  候选窗口探测 / DWM 属性     │
│  关联引擎 + 生命周期状态机 │                  └────────────────────────────┘
│  输出：事件流 / 指标 / 存储│                   服务用 CreateProcessAsUser 拉起
└──────────────────────────┘
```

**分层职责必须严格**：服务层持有 ETW 会话、解析 `EVENT_RECORD`、跑关联状态机，**不调用任何 user32/GDI/UIA/COM UI 接口**；辅助进程层只做一件事——把"用户语义"变成带时间戳的结构化元组，跑在 Medium IL、不提权，崩溃由服务重启。

## 启动温度三态判定

冷/温/热不是二分，而是三态 + 细分。判据按优先级短路求值：

| 序 | 信号源 | 判据 | 结论 |
|---|---|---|---|
| 1 | `Kernel-Process / ProcessStart` | T0 窗口内是否有目标 exe 的新进程 | 有 → 冷/温；无 → 热 |
| 2 | `Immersive-Shell` / 应用 ETW | `Resuming`/`Activated` 且无新实例 | 热 / 挂起恢复 |
| 3 | `AppInstance` 重定向、互斥量、`WM_COPYDATA`、命名管道 | 转交已有实例 + 前台切换无新进程 | 热 / 实例重定向 |
| 4 | 进程 `CreateTime` vs `T0` | `CreateTime < T0 - PRELAUNCH_EPSILON` | 热 / 预启动转正 |
| 5 | `Kernel-Memory / HardFault` + `Kernel-File / DiskRead` | Hard Fault 高 / 磁盘读取显著 | 冷 / 温 |
| 6 | `Kernel-Boot` / `Kernel-General` | `BootType`、`FastStartup`、`Hiberboot` | 追加 `bootContext` 分桶 |

阈值自适应：取该应用最近 N 次（N ≥ 20）冷启动的 Hard Fault P50 作为基线，判定阈值 = 0.7 × 基线，跨应用不共享阈值。

温度分类与启动耗时里程碑（T1a–T1f）**正交，必须分别记录**：不可用温度推断里程碑，也不可用里程碑反推温度。

## 阶段 0 探针（已实现）

```powershell
dotnet build AppObs.Probe.slnx -c Release

# 一次完整演示：etw-proc 提权采集 + win-evt 并行采集 + 自动生成覆盖率报告
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\demo-phase0.ps1 -DurationSeconds 60
```

| 工具 | 职责 | 提权 |
|---|---|---|
| `etw-proc` | Kernel-Process ETW（Process `0x10` / Image `0x40`），打印字段、句柄探测与计数器 | 是 |
| `win-evt` | WinEvent(out-of-context) + Shell hook | 否 |
| `ident` | 六级身份解析链 | 否 |
| `probe-report` | 生成信号覆盖率表 | 否 |

实测要点（详细数据见 [docs/阶段0-可行性探针.md](./docs/阶段0-可行性探针.md)）：

- **事件名不能用来判类型**：本机 `EventName` 是 `ProcessStart/开始`，必须按 `ProviderGuid + EventID` 判定。
- **事件时间戳是本地时间**：当成 UTC 换算会让两个探针的 QPC 差 8 小时，配对全错。
- **实时投递延迟约 2 秒**（P50 1998ms）：用回调时刻当 `T1a` 会系统性高估。
- **`ProcessStart` v4 不含镜像路径与包身份**：必须 `OpenProcess` + `QueryFullProcessImageNameW` + `GetPackageFullName` 补齐（实测拒绝率 0/21）。
- **覆盖率**：12 个用户动作中 A 级（ETW 与窗口同 PID）25–38%，其余为宿主归并（B）与复用/热启动（C）。
- **多报是数量级问题**：Edge 一次冷启动产生 **12 个应用级进程**（11 × `msedge.exe` + 1 × `identity_helper.exe`），全部挂在同一主进程下；不归并就是 12 次「打开应用」。

## 适用范围与免责

- 资料核实截止日期：**2026-09-01**。文中标注为「实验性/非官方」的能力（如 DWM 私有 provider GUID、`Microsoft-Windows-Shell-Core` 逆向所得 GUID）均缺乏 Microsoft 正式文档承诺，**不得作为生产契约**。
- 本文口径为工程约定，需与产品侧对齐分桶命名。
- Windows 桌面应用（Win32）无统一的官方冷/温/热判定 API；UWP 的 `LaunchActivated`/`Activated` 语义仅供参考。

## 许可

[MIT](./LICENSE)
