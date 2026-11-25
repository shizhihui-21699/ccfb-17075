# PipeSec — Windows 命名管道安全检查与加固工具

PipeSec 是一个面向防御安全团队和 C++ 开发团队的 Windows 命名管道审计工具与安全封装库。它可以：

- 枚举 `\\.\pipe\` 下当前所有命名管道；
- 读取所有者、DACL、SACL、强制完整性标签和 SDDL；
- 通过系统句柄表被动定位持有管道句柄的进程、PID、访问掩码和句柄值；
- 查询进程镜像、账户、是否提权、是否为 SYSTEM、所属 Windows 服务和进程创建时间；
- 尝试从对象元数据读取对象创建时间，并通过轮询/状态文件记录 first-seen；
- 枚举服务及其 `ServiceDll`，从二进制中提取命名管道字符串和 `ImpersonateNamedPipeClient` 导入提示；
- 识别 NULL DACL、Everyone/Anonymous/Authenticated Users/Builtin Users 宽权限、
  `FILE_CREATE_PIPE_INSTANCE` 暴露、低完整性标签、服务 PID 不匹配、可预测名称当前缺失等风险；
- 提供 `watch` 模式发现动态创建/消失的管道；
- 提供 `harden` 命令进行 SDDL 备份、dry-run、应用和健康检查失败回滚；
- 提供可直接集成到产品中的 `SecurePipe.h` 服务端/客户端安全封装。

> 这是防御性审计与加固工具，不会创建抢占管道、不会发送协议数据，也不会结束第三方进程。
> 句柄归属通过复制已有句柄查询，不向管道写入业务数据。完整功能需要管理员权限；
> 未提权时仍可枚举名称和部分 SD，但许多进程令牌/句柄信息会缺失。

## 目录结构

```text
include/pipesec/types.h        公共数据模型
include/pipesec/SecurePipe.h   安全服务端/客户端 C++ 封装
src/                           审计、句柄、SD、服务、监视、报告和加固实现
examples/                      secure_server.cpp / secure_client.cpp
cmake/mingw-w64-x86_64.cmake   macOS/Linux MinGW 交叉编译工具链
```

## 编译

### Visual Studio 2022 / CMake

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

产物：

```text
build\Release\pipe-audit.exe
build\Release\secure_server.exe
build\Release\secure_client.exe
```

### MinGW 交叉编译（已在 macOS + x86_64-w64-mingw32 验证）

```bash
cmake -S . -B build-mingw \
  -DCMAKE_TOOLCHAIN_FILE=cmake/mingw-w64-x86_64.cmake \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build-mingw -j
```

## 快速使用

建议在**管理员终端**中运行。

### 1. 完整审计，输出人类可读报告

```powershell
.\pipe-audit.exe audit
```

只看 HIGH/CRITICAL 详细发现：

```powershell
.\pipe-audit.exe audit --min-severity high
```

只看名称包含 `docker` 的管道：

```powershell
.\pipe-audit.exe audit --name docker
```

### 2. 输出 JSON 并用于 CI/资产平台

```powershell
.\pipe-audit.exe audit --json --out report.json
```

如果存在 HIGH 及以上发现则返回退出码 `2`：

```powershell
.\pipe-audit.exe audit --json --out report.json --fail-on high
echo $LASTEXITCODE
```

JSON 中包含：

- 管道 SDDL、owner、ACE、完整性标签；
- 句柄 PID、granted access；
- 进程路径、账户、提权状态、服务名；
- 对象创建时间、进程创建时间；
- 服务二进制中的管道名引用；
- 每条风险的代码、详情和修复建议。

### 3. 监视动态管道

持续输出文本事件：

```powershell
.\pipe-audit.exe watch --interval-ms 500
```

输出 JSON Lines，方便采集：

```powershell
.\pipe-audit.exe watch --jsonl --state .\pipesec-state.tsv --out events.jsonl
```

运行 60 秒并让首轮也输出所有现存管道：

```powershell
.\pipe-audit.exe watch --duration-sec 60 --emit-existing
```

状态文件保存 `<first-seen-unix-time>\t<lower-pipe-name>`，便于多次运行之间保留首次发现时间。

### 4. 服务/二进制字符串扫描

默认会枚举服务并扫描服务镜像及 `Parameters\ServiceDll` 指向的 DLL。若只需要快速快照：

```powershell
.\pipe-audit.exe audit --no-binary-scan
```

若系统服务很多，可限制单文件扫描大小：

```powershell
.\pipe-audit.exe audit --max-binary-mb 16
```

字符串扫描是启发式能力：它能发现明文和 UTF-16 管道名，但可能漏掉加密/运行时拼接的名称，也可能把客户端字符串误报为当前可抢占服务端。报告使用 `PREDICTABLE_NAME_ABSENT` 和 `SERVICE_PID_MISMATCH` 等代码明确标注需要人工复核的推断。

### 5. 学习合法主体并生成候选 SDDL

短轮询期间请运行业务客户端和健康检查；工具会聚合该管道句柄上的进程账户，把服务主体标为 `GA`、普通客户端主体标为 `GRGW`：

```powershell
.\pipe-audit.exe learn --name ExistingPipe --duration-sec 60 --interval-ms 250 `
  --out .\ExistingPipe.candidate.sddl
```

这是**候选白名单**，不是可直接批量应用的最终策略：短连接可能漏采，特定用户 SID 也可能不适合大规模部署。
应优先把客户端替换为专用域/本地组 SID，然后在预生产用健康检查验证。

### 6. 查看加固 SDDL 模板

```powershell
.\pipe-audit.exe presets
```

内置模板：

| Preset | SDDL | 兼容性 |
|---|---|---|
| `strict` / `system-admins` | `D:P(A;;GA;;;SY)(A;;GA;;;BA)` | 仅 SYSTEM 和管理员，最严格 |
| `high-integrity` | `D:P(A;;GA;;;SY)(A;;GA;;;BA)S:(ML;;NW;;;HI)` | 仅高完整性/SYSTEM 客户端 |
| `users` | `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;BU)` | 保留普通 Users 读写，移除 Everyone/Anonymous |
| `interactive` | 额外加入 `IU` | 交互式用户兼容模板 |

### 7. Dry-run 与应用外部 SDDL

先 dry-run：

```powershell
.\pipe-audit.exe harden --name ExistingPipe --preset users
```

确认旧 SDDL 已记录后再应用，并备份：

```powershell
.\pipe-audit.exe harden `
  --name ExistingPipe `
  --sddl "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;S-1-5-21-1-2-3-1001)" `
  --apply `
  --backup .\ExistingPipe.sddl.bak
```

带业务健康检查；如果命令返回非 0，工具自动恢复旧 SDDL：

```powershell
.\pipe-audit.exe harden `
  --name ExistingPipe `
  --preset users `
  --apply `
  --health-check "C:\App\check-pipe-health.exe --pipe ExistingPipe" `
  --backup .\ExistingPipe.sddl.bak
```

> **不要不加测试地批量加固第三方管道。** 外部 `SetNamedSecurityInfo` 可能只影响当前对象/实例，
> 第三方服务重启或创建新实例时可能恢复其内置 SD；过严 DACL 会导致合法服务与客户端通信中断。
> 推荐流程是：审计 → `watch`/学习合法 PID 与账户 → 在预生产用 `--apply --health-check` 验证 →
> 推动厂商使用安全封装永久修复。

## 主要风险代码

| Code | 含义 |
|---|---|
| `NULL_DACL` | NULL/缺失 DACL，通常等于完全开放 |
| `BROAD_OWNER` | 所有者是 Everyone/Anonymous/Users 等宽泛主体，可自行改 ACL |
| `BROAD_WRITE_OWNERSHIP` | 宽泛主体有 WriteDac/WriteOwner/GenericAll |
| `BROAD_CREATE_PIPE_INSTANCE` | 普通用户可创建同名额外实例，可能截获客户端 |
| `BROAD_WRITE_ACCESS` | 宽泛主体可连接/写入管道 |
| `BROAD_READ_ACCESS` | 宽泛主体可读取 IPC 数据 |
| `LOW_INTEGRITY_LABEL` | 完整性标签过低 |
| `NON_ELEVATED_OWNER_PROCESS` | 非提权进程持有/创建管道，存在抢占可能 |
| `SERVICE_PID_MISMATCH` | 当前管道句柄 PID 与引用该名称的服务 PID 不一致，可能已被抢占 |
| `PREDICTABLE_NAME_ABSENT` | SYSTEM 服务引用的名称当前不存在，存在启动前抢占窗口 |
| `REMOTE_CLIENTS_NOT_EXPLICITLY_REJECTED` | 未观察到 `PIPE_REJECT_REMOTE_CLIENTS` |
| `ACL_UNREADABLE` | 权限不足，不能据此认为安全 |

## 安全编码要点

### 服务端

1. 使用显式、受保护的 SDDL，不使用默认 SD 或 NULL DACL。
2. 第一个实例加 `FILE_FLAG_FIRST_PIPE_INSTANCE`，让抢占者已经建名时服务快速失败，而不是继续使用错误名称。
3. DACL 中不要给普通用户 `FILE_CREATE_PIPE_INSTANCE`。
4. 加 `PIPE_REJECT_REMOTE_CLIENTS`。
5. 每次连接后 `ImpersonateNamedPipeClient`，查询线程令牌并做主体/组成员/`AccessCheck` 授权；不要只依赖客户端传来的用户名。
6. 模拟结束立即 `RevertToSelf`；`ClientImpersonation` RAII 已处理。
7. 对消息长度、缓冲区和协议状态机做校验，避免把管道变成越权读写原语。

示例：`examples/secure_server.cpp`。

### 客户端：为什么默认使用 `SECURITY_IDENTIFICATION`

典型 SYSTEM 提权场景是：

1. 攻击者在高权限服务/客户端启动前创建可预测名称的流氓管道服务端；
2. 高权限客户端用默认 QOS 连接，并允许 `SecurityImpersonation`；
3. 流氓服务端立即调用 `ImpersonateNamedPipeClient`、打开线程令牌并 `DuplicateTokenEx` 保存 SYSTEM/高权限令牌；
4. 即使客户端随后检查 PID，令牌可能已经被复制。

因此 `SecurePipe.h` 的客户端默认：

- 带 `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`，流氓服务端只能识别主体，不能获得可用于访问对象的模拟令牌；
- 连接后调用 `GetNamedPipeServerProcessId`；
- 校验进程路径、账户、是否 SYSTEM/提权；
- 可选校验期望镜像路径或 Windows 服务 PID。

如果合法服务端确实需要模拟客户端，应同时满足：

- 管道 DACL 仅允许受信任服务 SID/SYSTEM/BA 创建实例；
- 已消除服务启动前名称空窗，或客户端在服务就绪前不使用 `SecurityImpersonation` 重连；
- 最好先以 Identification 连接并完成服务端身份验证，再通过受控的第二连接/认证协议决定是否授予更高模拟级别；
- 明确知道“先以 Impersonation 连接再检查 PID”存在被抢跑复制令牌的风险。

示例：`examples/secure_client.cpp`。

## 不能影响正常通信：推荐落地流程

1. **只读取证**：先在生产旁路运行 `audit --json`，不执行 harden。
2. **动态学习**：用 `watch --jsonl --state` 覆盖服务重启、登录、客户端启动高峰和更新窗口。
3. **建立合法关系**：记录每个管道的服务 PID、客户端 PID、账户、镜像路径和签名；为每个业务管道确定应允许的服务 SID 与客户端组。
4. **预生产验证 SDDL**：优先使用 `users` 等兼容性模板，再收敛到专用组/SID。
5. **带健康检查应用**：使用 `harden --apply --health-check ... --backup ...`，失败自动回滚。
6. **推动代码修复**：把 `SecurePipe.h/.cpp` 集成到自有组件；第三方组件要求厂商设置严格 SD、first instance 和 reject-remote。
7. **持续监控**：通过 PipeSec watch、Sysmon Event ID 17/18 或 ETW 对新管道、异常 owner/PID、弱 SDDL 告警。

## 限制

- Windows 没有简单的公开 Win32 API 直接给出“管道创建时间 + 所属 PID”。PipeSec 组合使用命名管道枚举、扩展系统句柄表、重复句柄和 `NtQueryObject`；受保护进程和权限不足时会有缺口。
- 句柄表很大时扫描会消耗 CPU，建议按 1–5 秒以上间隔监视，或只做定时审计。
- 对象创建时间来自未文档化 NT 结构，个别版本/对象可能返回 0；工具同时提供轮询 first-seen 和进程创建时间。
- 二进制字符串扫描可能漏报动态拼接/加密名称，也可能产生客户端字符串误报。
- 外部 SDDL 加固不是第三方代码修复；服务重建实例后可能恢复弱 SD。
- 本仓库代码已通过 MinGW x86_64 交叉编译验证；在真实 Windows 环境首次部署前，仍应在测试机运行完整功能和健康检查。

## 参考

- Microsoft Learn: [`GetNamedSecurityInfoW`](https://learn.microsoft.com/windows/win32/api/aclapi/nf-aclapi-getnamedsecurityinfow)
- Microsoft Learn: [`SE_OBJECT_TYPE`](https://learn.microsoft.com/windows/win32/api/accctrl/ne-accctrl-se_object_type)
- Microsoft Learn: [`CreateNamedPipeW`](https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-createnamedpipew)
- Microsoft Learn: [`ImpersonateNamedPipeClient`](https://learn.microsoft.com/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
- Microsoft Learn: [Sysmon Event ID 17/18 PipeEvent](https://learn.microsoft.com/sysinternals/downloads/sysmon)
