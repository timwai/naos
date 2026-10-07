# naos 设计文档

> 跨平台 NAS 管理面板：把任意文件夹通过 SMB / WebDAV / NFS 共享，带多用户、目录级权限与统一审计。  
> 版本 **v0.5 · Draft** · 后端 Rust · 前端 React/TypeScript

---

## 0. v0.5 变更摘要

v0.5 调整 SMB 路线：**现阶段不自研 SMB Server**，不由 `naosd` 直接监听 TCP/445。Linux / macOS / Windows 均优先复用系统已有 SMB 能力，并把“445 端口归属、已有 SMB 服务、已有共享配置”作为正式的 preflight 与冲突检测项。

| # | 决策 | 影响 |
| --- | --- | --- |
| 1 | 暂停 builtin `naos-smb-server` 实现 | 当前版本不开发 SMB wire protocol、NTLMv2、signing、lease/lock 等协议栈 |
| 2 | `naosd` **不监听 TCP/445** | 避免与 Windows Server service、macOS File Sharing、Linux Samba 等已有服务争抢端口 |
| 3 | SMB 统一走 **system provider adapter** | Linux 以 Samba 为主要 provider；Windows 使用系统 SMB Server；macOS 优先复用可管理的系统 SMB provider |
| 4 | 445 冲突检测进入 Doctor / Apply preflight | 识别 listener PID/service/provider，不能识别或不属于可管理 provider 时拒绝 Apply |
| 5 | 不自动停止未知/用户管理的 SMB 服务 | naos 不通过“抢端口”解决冲突，也不擅自关闭系统 File Sharing 或第三方 Samba |
| 6 | 只维护 naos 自己的 share/config scope | Linux/macOS Samba 使用独立 include/标记块；Windows 只管理带 naos 标识的 shares/users |
| 7 | 已有系统 SMB 可安全接入时复用 | 若 445 已由目标 system provider 占用，视为“服务已运行”，而不是端口冲突 |
| 8 | SMB 权限继续通过系统账号 + FS ACL 落地 | `acl-engine` 仍是 desired semantics，SMB adapter 负责把规则转换并 Verify |
| 9 | 自研 SMB P0 文档保留但标记 **Deferred** | 作为未来研究资料，不进入当前 roadmap、CI gate 或 Definition of Done |
| 10 | 当前交付优先级回到 control plane + system SMB + WebDAV + NFS | 减少协议栈并发开发风险，先把跨平台 NAS 主流程做完整 |

v0.3 已确定的 React/OpenAPI/REST/SSE/Operation/分层架构继续有效；v0.4 的自研 SMB 方案不删除，但降级为未来候选路线。

---

## 1. 目标与范围

| 项 | 内容 |
| --- | --- |
| 平台 | Linux / macOS / Windows |
| 协议 | SMB、WebDAV、NFSv3 |
| 能力 | 任意目录共享、多用户、用户组、子目录级权限、统一审计、权限模拟 |
| 形态 | 单二进制守护进程 `naosd` + 内嵌 Web SPA |
| 管理方式 | Web UI + REST API + SSE；CLI 仅承担安装/初始化/诊断辅助 |
| 非目标 | RAID/磁盘管理、快照、备份编排、LDAP/AD、FTP/AFP/iSCSI、媒体转码、服务端文件预览 |

核心原则：

1. **控制面与数据面分离**：管理 UI/API 不参与 SMB/NFS 数据转发；WebDAV 因协议实现原因与 `naosd` 同进程。
2. **声明式状态**：数据库保存 desired state，Reconciler 负责 render → diff → apply → verify → rollback。
3. **唯一权限语义**：`acl-engine` 是权限计算唯一实现；协议层不得各自解释权限。
4. **最小特权边界**：系统账号、文件 ACL、系统服务管理集中在 `naos-platform`。
5. **默认安全**：管理 UI 默认只监听 `127.0.0.1`；对外监听必须启用 TLS。
6. **同一事实只有一个来源**：前端不复制后端 ACL、校验、权限推导逻辑。
7. **接口先于页面实现**：UI 所需数据必须通过稳定 DTO 暴露，不允许页面直接依赖数据库字段。

---

## 2. 总体架构

### 2.1 运行时拓扑

```text
                         ┌──────────────────── Browser ────────────────────┐
                         │ React SPA                                       │
                         │ REST / SSE / multipart download-upload          │
                         └──────────────────────┬───────────────────────────┘
                                                │ HTTPS
                                                ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│ naosd (Rust / tokio, root or SYSTEM)                                         │
│                                                                               │
│  Control Plane                                                               │
│  axum API · auth/session · RBAC · reconciler · audit · doctor · verify       │
│                  │                    │                    │                   │
│                  ▼                    ▼                    ▼                   │
│             naos-core            naos-platform          naos-smb              │
│             acl-engine           accounts/FS ACL        system provider       │
│                  │                                         adapter             │
│                  │                                           │                 │
│                  ├──────────── WebDAV / NFS ────────────────┤                 │
└──────────────────┼───────────────────────────────────────────┼─────────────────┘
                   │                                           │
                   ▼                                           ▼
             host filesystem                         OS/system SMB service
                                                      │
                                     ┌────────────────┼─────────────────┐
                                     ▼                ▼                 ▼
                                  Linux             macOS             Windows
                                  Samba        system SMB/Samba     SMB Server
                                     │                │                 │
                                     └────────────────┴─────────────────┘
                                                      │ TCP/445
                                                      ▼
                                                  SMB clients
```

**关键边界：`naosd` 自身不 bind TCP/445。**

### 2.2 SMB provider 与端口归属

SMB 在当前版本是“管理系统 SMB 服务”，不是“运行 SMB 服务”。

启动、创建共享或协议 Apply 前先执行：

```text
detect platform
→ inspect TCP/445 listener
→ identify provider/service/process
→ inspect provider capabilities
→ inspect existing managed/unmanaged shares
→ determine: reusable | install_required | stopped | conflict | unsupported
```

判定规则：

- 445 未监听，目标 provider 已安装：允许通过 Operation 启动 provider；
- 445 已由**同一个可管理 system provider**监听：正常复用，不视为冲突；
- 445 已由其它 SMB provider、容器、VM、第三方进程或无法识别的进程监听：标记 `port_conflict`，禁止自动抢占；
- naos 不自动 kill 监听进程，不自动关闭用户开启的 macOS File Sharing，不自动停止未知 Samba instance；
- 如果可证明现有 Samba instance 支持安全 include 且用户允许接管 naos 专属 include，可 attach；否则只读报告冲突；
- Windows 使用系统 SMB Server service，不再启动第二个 445 listener。

### 2.3 平台 provider

| 平台 | 首选 provider | 说明 |
| --- | --- | --- |
| Linux | Samba | 检测 distro/service/config；通过 naos 专属 include 管理 shares |
| macOS | 系统 SMB/File Sharing provider；无法安全管理时可选 Samba | 优先避免与系统 `smbd` 抢占 445；第三方 Samba 启动前必须确认端口空闲 |
| Windows | Windows SMB Server / LanmanServer | 使用 PowerShell/系统 API 创建 share 与 ACL；不自行 bind 445 |

Provider detection 输出至少：

```text
provider
installed
running
service_name
listener_445
listener_pid (可获得时)
listener_owner
config_mode
managed_by_naos
conflict_reason
```

### 2.4 控制面与数据面

**控制面**包括 Web UI、REST API、用户/共享/ACL 管理、协议启停、系统诊断、审计查询和 Reconciler。

**数据面**：

- SMB：由操作系统/system provider 直接处理；
- WebDAV/NFS：由 naos 内置协议实现处理；
- 管理 API 永远不转发 SMB/NFS 文件数据。

`acl-engine` 保存统一 desired semantics。WebDAV/NFS 直接调用；SMB 通过系统账号、share permission 和文件系统 ACL 映射实现，并由 Verify 检查漂移。

### 2.5 技术选型

| 层 | 选型 | 说明 |
| --- | --- | --- |
| Rust runtime | `tokio` | 异步网络、进程管理、任务调度 |
| HTTP API | `axum` + `tower` | Router、middleware、限速、trace |
| 序列化 | `serde` / `serde_json` | API 与持久化 DTO |
| OpenAPI | `utoipa`（或等价方案） | Rust DTO/route 生成 API 契约 |
| DB | `sqlx` + SQLite | migrations、事务、离线可部署 |
| 密码 | `argon2id` | naos 登录密码；系统 SMB 凭据同步由 platform/provider adapter 完成 |
| Session | 随机 opaque session + DB hash | 可注销、可撤销、可统一失效 |
| SMB | **system provider adapter** | Linux Samba；Windows SMB Server；macOS 复用可管理 system provider，必要时 Samba |
| WebDAV | `dav-server` | 注入 ACL 与真实用户身份 |
| NFS | 自研 ONC-RPC/XDR + NFSv3/MOUNT/NLM | v1 只做 NFSv3 |
| 前端 | React + TypeScript + Vite | SPA，静态产物嵌入 Rust |
| 前端请求 | TanStack Query | server state、缓存、失效、轮询 |
| 表单 | React Hook Form + Zod | UX 校验；后端仍为最终校验来源 |
| 路由 | React Router | 页面路由与权限门卫 |
| CSS | CSS Variables + CSS Modules | 复用现有原型 design tokens |
| 前端 API 类型 | OpenAPI 自动生成 | 禁止手写重复 DTO |
| 静态资源 | `rust-embed` | 单二进制管理面部署 |
| 日志 | `tracing` + `tracing-subscriber` | request_id / operation_id 贯通 |

> “单二进制”指 naos 管理面自身仍为单 `naosd`；SMB 数据面依赖平台系统服务，不再把“所有协议均内置”作为当前版本目标。

---

## 3. 前端实现设计

### 3.1 从原型到正式 SPA

现有 `docs/naos 管理页面原型.html` 作为以下内容的参考：

- 页面信息架构；
- 暗色/亮色主题 token；
- Dashboard、文件浏览器、共享、用户与用户组、权限模拟器、审计、设置、个人安全页；
- ACL 编辑和 NFS 绑定的交互；
- 对危险操作的确认方式。

正式实现**不复制原型中的内存状态 `S`、Mock 文件系统、前端 ACL 求值和模拟数据逻辑**。所有业务数据由 API 提供，ACL 模拟结果由后端 `acl-engine` 返回。

### 3.2 前端目录结构

```text
web/
├─ package.json
├─ vite.config.ts
├─ tsconfig.json
├─ index.html
├─ scripts/
│  └─ generate-api.mjs
└─ src/
   ├─ app/
   │  ├─ App.tsx
   │  ├─ router.tsx
   │  ├─ providers.tsx
   │  └─ layout/
   │     ├─ AppShell.tsx
   │     ├─ Sidebar.tsx
   │     └─ Header.tsx
   ├─ pages/
   │  ├─ LoginPage.tsx
   │  ├─ DashboardPage.tsx
   │  ├─ FilesPage.tsx
   │  ├─ SharesPage.tsx
   │  ├─ ShareDetailPage.tsx
   │  ├─ UsersPage.tsx
   │  ├─ AclSimulatorPage.tsx
   │  ├─ AuditPage.tsx
   │  ├─ SettingsPage.tsx
   │  └─ ProfilePage.tsx
   ├─ features/
   │  ├─ auth/
   │  ├─ dashboard/
   │  ├─ files/
   │  ├─ shares/
   │  ├─ acl/
   │  ├─ users/
   │  ├─ groups/
   │  ├─ nfs/
   │  ├─ protocols/
   │  ├─ audit/
   │  └─ system/
   ├─ components/
   │  ├─ ui/
   │  ├─ data-table/
   │  ├─ form/
   │  └─ feedback/
   ├─ lib/
   │  ├─ api/
   │  │  ├─ client.ts
   │  │  ├─ generated.ts
   │  │  ├─ queryKeys.ts
   │  │  └─ errors.ts
   │  ├─ sse/
   │  │  └─ operationStream.ts
   │  ├─ format/
   │  └─ validation/
   ├─ hooks/
   ├─ styles/
   │  ├─ tokens.css
   │  ├─ global.css
   │  └─ utilities.css
   ├─ test/
   │  ├─ handlers.ts
   │  └─ server.ts
   └─ main.tsx
```

分层约束：

- `pages/` 只负责页面编排，不直接拼 URL。
- `features/*` 封装业务组件、query/mutation hook 和表单。
- `lib/api/generated.ts` 完全由 OpenAPI 生成，禁止手工修改。
- `components/ui/` 不依赖具体业务实体。
- 不允许在 React 组件内实现 ACL 判定、系统路径校验、NFS 身份映射等后端规则。

### 3.3 页面路由

| 路由 | 页面 | 角色 |
| --- | --- | --- |
| `/login` | 登录 | anonymous |
| `/` | Dashboard | admin |
| `/files` | 文件浏览器 | admin/user |
| `/shares` | 共享列表 | admin |
| `/shares/:id` | 共享详情/ACL/NFS | admin |
| `/users` | 用户与用户组 | admin |
| `/acl-simulator` | 权限模拟器 | admin |
| `/audit` | 统一审计 | admin |
| `/settings` | 系统设置/Doctor/Verify | admin |
| `/profile` | 当前用户安全设置 | admin/user |

普通用户的文件页只展示**当前用户可访问的共享**。前端隐藏管理入口只是 UX；最终授权必须由后端 RBAC 和 ACL 决定。

### 3.4 状态管理

状态分三类：

1. **Server State**：用户、共享、ACL、审计、协议状态、系统信息。统一使用 TanStack Query。
2. **URL State**：页码、筛选、当前共享、审计过滤条件，尽量放 query string，便于刷新和分享链接。
3. **Ephemeral UI State**：弹窗开关、表格选择、表单草稿、主题等，使用组件 state/context。

不引入全局 Redux。只有出现跨页面且无法由 Query/Router 表达的纯 UI 状态时，才考虑轻量 store。

### 3.5 Query Key 规范

```ts
queryKeys.auth.session()
queryKeys.dashboard.summary()
queryKeys.shares.list(filters)
queryKeys.shares.detail(shareId)
queryKeys.shares.acl(shareId)
queryKeys.users.list()
queryKeys.groups.list()
queryKeys.protocols.all()
queryKeys.audit.list(filters)
queryKeys.system.doctor()
```

Mutation 成功后只失效相关 key。例如创建共享成功并 Apply 完成：

```text
invalidate shares.list
invalidate dashboard.summary
invalidate protocols.all
invalidate audit.list
```

### 3.6 表单与校验

前端 Zod 校验负责快速反馈，后端验证是最终权威。

例如新建共享前端只做：

- 名称字符范围；
- 路径非空；
- 至少启用一个协议；
- ACL 行字段完整；
- CIDR/UID 基础格式。

以下校验**只能由后端完成**：

- 路径真实存在；
- canonicalize 后是否落入黑名单；
- 是否与其它共享嵌套冲突；
- 文件系统是否支持 ACL；
- SMB system provider 是否可用、TCP/445 当前由谁监听、现有 provider 是否可安全复用、是否存在 unmanaged 冲突；
- NFS 端口/特权能力是否可用。

后端 `422` 可返回字段级错误：

```json
{
  "code": "VALIDATION_FAILED",
  "message": "请求参数校验失败",
  "request_id": "req_01J...",
  "field_errors": {
    "path": ["路径位于系统黑名单中"],
    "name": ["共享名已存在"]
  }
}
```

### 3.7 加载、空态与错误态

每个主要数据区必须实现：

- skeleton/loading；
- empty state；
- permission denied；
- network error；
- stale conflict；
- operation failed；
- retry。

禁止用单一 `alert()` 覆盖所有错误。危险写操作使用 Confirm Dialog，并显示影响范围。

### 3.8 Design System

沿用原型中的 token 思路，抽离到 `tokens.css`：

```css
:root {
  --bg: #f8fafc;
  --card: #ffffff;
  --border: #e2e8f0;
  --tx-main: #0f172a;
  --tx-muted: #64748b;
  --primary: #4f46e5;
  --success: #10b981;
  --warning: #f59e0b;
  --danger: #ef4444;
  --radius-md: 12px;
}

[data-theme="dark"] {
  --bg: #090d16;
  --card: #131a2c;
  --border: #1e293b;
  --tx-main: #f8fafc;
  --tx-muted: #94a3b8;
  --primary: #6366f1;
}
```

组件不直接写业务色值，优先使用 token。可复用组件至少包括：

- `Button`
- `Input` / `Select`
- `Switch`
- `Dialog`
- `Toast`
- `Badge`
- `Card`
- `DataTable`
- `Pagination`
- `EmptyState`
- `ErrorState`
- `OperationProgress`
- `PermissionBadge`

### 3.9 前端构建与内嵌

构建链：

```text
cargo build
   └─ xtask/build.rs
      ├─ npm ci / pnpm install --frozen-lockfile
      ├─ npm run generate:api
      ├─ npm run build
      └─ web/dist → rust-embed → naosd
```

开发模式：

```text
Vite dev server :5173
        │ proxy /api /dav
        ▼
naosd :8443
```

生产模式只暴露 `naosd`。SPA 路由未知路径回落到 `index.html`，但 `/api/*`、`/dav/*`、NFS/SMB 不参与回落。

---

## 4. 前后端交互方式

### 4.1 传输协议

| 场景 | 方式 |
| --- | --- |
| CRUD / 查询 | HTTPS JSON REST |
| Apply/Doctor/Verify 进度 | SSE |
| Dashboard 状态 | REST 轮询，默认 5~10 秒 |
| 审计列表 | REST 分页查询 |
| 文件上传 | `multipart/form-data` 流式上传 |
| 文件下载 | HTTP streaming，支持 Range |
| 大型导出 | 流式 CSV |
| WebDAV 数据面 | `/dav/<share>/...`，不复用管理 API |
| WebSocket | v1 不使用 |

选择 SSE 而不是 WebSocket 的原因：管理控制台主要需要服务端单向推送，SSE 实现、重连、代理兼容和调试成本更低。

### 4.2 同源与 Cookie Session

管理 UI 和 API 默认同源：

```text
https://host:8443/            Web SPA
https://host:8443/api/v1/...  管理 API
https://host:8443/dav/...     WebDAV
```

登录成功后设置：

```text
Set-Cookie: naos_session=<opaque>; HttpOnly; Secure; SameSite=Strict; Path=/
```

Session token：

- 使用 CSPRNG 生成至少 256 bit 随机值；
- 浏览器只保存 opaque token；
- DB 只保存 token hash；
- `logout` 删除服务端 session；
- 修改本人密码后默认撤销其它 session；
- 管理员禁用用户时立即撤销该用户全部 session。

### 4.3 CSRF

对 `POST/PUT/PATCH/DELETE` 管理 API 要求 `X-CSRF-Token`。

登录或恢复 session 时：

```http
GET /api/v1/auth/session
```

返回：

```json
{
  "authenticated": true,
  "user": {
    "id": "usr_01J...",
    "username": "admin",
    "role": "admin"
  },
  "csrf_token": "..."
}
```

CSRF token 只保存在前端内存，不写 `localStorage`。页面刷新后重新调用 `/auth/session` 获取。

### 4.4 API Client

`client.ts` 统一处理：

- `credentials: "same-origin"`；
- JSON encode/decode；
- `X-CSRF-Token`；
- `X-Request-ID` 可选透传；
- `401` → 清 session query，并跳登录页；
- `403` → 权限错误页面/Toast；
- `412` → 并发冲突提示并刷新资源；
- `429` → 读取 `Retry-After`；
- 网络错误与 HTTP 错误统一转换为 `ApiError`。

业务组件禁止直接调用裸 `fetch()`。

### 4.5 异步 Operation 模型

涉及系统配置落地的操作包括：

- 创建/修改/删除共享；
- 修改共享 ACL；
- 修改 NFS binding；
- 创建/禁用/删除用户；
- 协议 start/stop/reload；
- System Verify；
- 部分 Settings 修改。

这些接口返回：

```http
HTTP/1.1 202 Accepted
Location: /api/v1/operations/op_01J...
```

```json
{
  "operation": {
    "id": "op_01J...",
    "kind": "share.update",
    "state": "queued",
    "resource": {
      "type": "share",
      "id": "shr_01J..."
    },
    "created_at": "2026-10-04T08:20:00Z"
  }
}
```

前端随后订阅：

```http
GET /api/v1/operations/op_01J.../events
Accept: text/event-stream
```

SSE：

```text
id: 1
event: progress
data: {"phase":"validate","step":"path","percent":10,"message":"路径校验通过"}

id: 2
event: progress
data: {"phase":"apply","step":"filesystem_acl","percent":45,"message":"正在同步文件 ACL"}

id: 3
event: progress
data: {"phase":"apply","step":"smb_reload","percent":70,"message":"正在重载 SMB"}

id: 4
event: completed
data: {"state":"succeeded","percent":100}
```

失败：

```text
event: failed
data: {
  "state":"failed",
  "error":{
    "code":"APPLY_FAILED",
    "message":"Samba 重载失败",
    "detail":{"stderr":"...","rollback":"succeeded"}
  }
}
```

客户端断线后可以携带 `Last-Event-ID` 重连；operation 的最终状态也必须可由 REST 查询，SSE 不是唯一事实来源。

### 4.6 幂等提交

支持产生副作用的 `POST` 接受：

```http
Idempotency-Key: <uuid>
```

服务端在限定时间内缓存 `(user, route, key)` 对应结果，防止用户双击、浏览器重试造成重复创建。

对天然幂等的 `PUT` 不强制要求该 header。

### 4.7 并发更新

可变资源包含 `generation`，响应同时给 ETag：

```http
ETag: "7"
```

更新时：

```http
If-Match: "7"
```

版本不一致：

```http
412 Precondition Failed
```

前端提示“该资源已被其它会话修改”，重新获取最新数据，不静默覆盖。

---

## 5. REST API 设计

Base URL：

```text
/api/v1
```

Content-Type：

```text
application/json; charset=utf-8
```

时间统一使用 UTC RFC3339，例如：

```text
2026-10-04T08:30:12.531Z
```

ID 使用不可猜测的字符串 ID，例如 `usr_...`、`shr_...`、`op_...`。内部数据库可继续使用整数主键，但 API 不暴露自增规律。

### 5.1 通用错误格式

```json
{
  "code": "SHARE_PATH_CONFLICT",
  "message": "共享路径与现有共享冲突",
  "request_id": "req_01J...",
  "detail": {
    "conflict_share_id": "shr_01J...",
    "conflict_path": "/data/media"
  },
  "field_errors": null
}
```

`detail` 只能包含可安全展示的信息，不返回 SQL、堆栈、密码、session、完整系统命令参数中的敏感值。

### 5.2 HTTP 状态码

| 状态 | 用途 |
| --- | --- |
| `200` | 查询/同步更新成功 |
| `201` | 创建仅数据库对象且无需 Apply 时 |
| `202` | 已受理异步 Operation |
| `204` | 无响应体成功 |
| `400` | 协议层请求错误 |
| `401` | 未登录/Session 失效 |
| `403` | RBAC/ACL 拒绝 |
| `404` | 资源不存在 |
| `409` | 资源状态冲突/唯一键冲突 |
| `412` | ETag / generation 冲突 |
| `422` | 字段或业务校验失败 |
| `429` | 登录限速/请求限速 |
| `500` | 未分类内部错误 |
| `503` | 系统依赖暂不可用 |

### 5.3 分页与过滤

列表统一：

```http
GET /api/v1/audit?page=1&page_size=50&protocol=SMB&result=deny
```

返回：

```json
{
  "items": [],
  "page": 1,
  "page_size": 50,
  "total": 1324
}
```

`page_size` 默认 50，最大 200。

审计数据量增长后可切换 cursor pagination，但 v1 先保持易用的页码分页。

### 5.4 Auth / Bootstrap

| Method | Path | 角色 | 说明 |
| --- | --- | --- | --- |
| GET | `/setup/status` | anonymous | 是否完成首次初始化 |
| POST | `/setup/admin` | anonymous + loopback + one-shot | 首次创建管理员 |
| POST | `/auth/login` | anonymous | 登录 |
| GET | `/auth/session` | anonymous | 当前会话与 CSRF |
| POST | `/auth/logout` | logged-in | 注销 |
| POST | `/auth/password` | logged-in | 修改本人密码 |
| GET | `/auth/sessions` | logged-in | 查看本人 session |
| DELETE | `/auth/sessions/{id}` | logged-in | 撤销某 session |

首次初始化规则：

- 仅系统还没有管理员时开放；
- 默认仅允许 loopback；
- 成功后永久关闭 bootstrap endpoint；
- 初始化请求写安全审计。

### 5.5 Dashboard

```http
GET /api/v1/dashboard/summary
```

示例：

```json
{
  "hostname": "naos-nas",
  "uptime_seconds": 1045680,
  "shares": {
    "total": 3,
    "degraded": 0
  },
  "users": {
    "enabled": 3,
    "total": 4
  },
  "connections": {
    "smb": 4,
    "webdav": 2,
    "nfs": 1
  },
  "audit_today": {
    "deny": 2
  },
  "protocols": [
    {"protocol":"smb","state":"running"},
    {"protocol":"webdav","state":"running"},
    {"protocol":"nfs","state":"running"}
  ]
}
```

资源指标：

```http
GET /api/v1/system/metrics?window=5m
```

用于 CPU、内存、网络、磁盘使用趋势。默认前端 5 秒轮询，页面不可见时暂停。

### 5.6 Users

| Method | Path | 说明 |
| --- | --- | --- |
| GET | `/users` | 用户列表 |
| POST | `/users` | 创建用户 + 系统账号，异步 Operation |
| GET | `/users/{id}` | 用户详情 |
| PUT | `/users/{id}` | 更新角色/启用状态/描述 |
| DELETE | `/users/{id}` | 删除用户 + 系统账号清理 |
| POST | `/users/{id}/password` | 管理员重置密码 |
| GET | `/users/{id}/groups` | 用户所属组 |

创建：

```json
{
  "username": "alice",
  "password": "initial-password",
  "role": "user",
  "enabled": true,
  "group_ids": ["grp_family"]
}
```

响应中**永远不返回**密码或 hash。

### 5.7 Groups

| Method | Path | 说明 |
| --- | --- | --- |
| GET | `/groups` | 组列表 |
| POST | `/groups` | 创建组 |
| GET | `/groups/{id}` | 组详情 |
| PUT | `/groups/{id}` | 更新组 |
| DELETE | `/groups/{id}` | 删除组 |
| PUT | `/groups/{id}/members` | 原子替换成员 |

成员更新：

```json
{
  "user_ids": ["usr_alice", "usr_bob"]
}
```

### 5.8 Shares

| Method | Path | 说明 |
| --- | --- | --- |
| GET | `/shares` | 当前角色可见共享 |
| POST | `/shares` | 创建共享，异步 Apply |
| GET | `/shares/{id}` | 共享详情 |
| PUT | `/shares/{id}` | 修改共享，异步 Apply |
| DELETE | `/shares/{id}` | 删除共享，异步 Apply |
| GET | `/shares/{id}/status` | desired/applied 状态 |
| POST | `/shares/{id}/verify` | 单共享一致性检查 |

DTO：

```json
{
  "id": "shr_media",
  "name": "media",
  "path": "/data/media",
  "comment": "家庭影音多媒体共享库",
  "enabled": true,
  "protocols": {
    "smb": true,
    "webdav": true,
    "nfs": true
  },
  "generation": 12,
  "applied_generation": 12,
  "apply_state": "in_sync",
  "created_at": "2026-10-04T07:00:00Z",
  "updated_at": "2026-10-04T08:00:00Z"
}
```

`apply_state`：

```text
in_sync | pending | applying | degraded | disabled
```

### 5.9 ACL

| Method | Path | 说明 |
| --- | --- | --- |
| GET | `/shares/{id}/acl` | ACL 规则 |
| PUT | `/shares/{id}/acl` | 原子替换规则集，异步 Apply |
| POST | `/shares/{id}/acl/simulate` | 调用后端 acl-engine 模拟 |
| GET | `/shares/{id}/acl/effective` | 查询指定用户/路径有效权限 |

ACL 规则：

```json
{
  "id": "acl_...",
  "rel_path": "/private",
  "subject": {
    "type": "group",
    "id": "grp_family",
    "name": "family"
  },
  "permission": "none",
  "inherit": true
}
```

模拟请求：

```json
{
  "user_id": "usr_bob",
  "rel_path": "/private/notes.txt",
  "operation": "read"
}
```

模拟响应：

```json
{
  "permission": "none",
  "allowed": false,
  "matched_depth": 1,
  "matched_rules": [
    {
      "rel_path": "/private",
      "subject": "group:family",
      "permission": "none",
      "reason": "explicit_deny"
    }
  ],
  "explanation": "命中最近层级 /private 的显式拒绝规则"
}
```

前端权限模拟器必须直接展示该结果，不自行重算。

### 5.10 NFS Bindings / Kerberos

| Method | Path | 说明 |
| --- | --- | --- |
| GET | `/shares/{id}/nfs-bindings` | L1/L2 绑定 |
| POST | `/shares/{id}/nfs-bindings` | 添加绑定 |
| PUT | `/shares/{id}/nfs-bindings/{binding_id}` | 修改 |
| DELETE | `/shares/{id}/nfs-bindings/{binding_id}` | 删除 |
| GET | `/nfs/principals` | L3 principal |
| POST | `/nfs/principals` | 绑定 principal |
| DELETE | `/nfs/principals/{id}` | 删除 principal |

L1：

```json
{
  "cidr": "192.168.1.0/24",
  "uid": null,
  "user_id": "usr_alice",
  "permission": "ro"
}
```

L2：

```json
{
  "cidr": "10.0.0.5/32",
  "uid": 1000,
  "user_id": "usr_admin",
  "permission": "rw"
}
```

### 5.11 文件浏览与文件操作

普通用户文件 API **不接受宿主机任意绝对路径**。

```http
GET /api/v1/shares/{share_id}/files?path=/photos
```

返回：

```json
{
  "path": "/photos",
  "entries": [
    {
      "name": "2026",
      "kind": "directory",
      "size": null,
      "modified_at": "2026-10-03T08:10:00Z",
      "effective_permission": "rw"
    },
    {
      "name": "a.jpg",
      "kind": "file",
      "size": 3355443,
      "modified_at": "2026-10-03T08:10:00Z",
      "effective_permission": "ro"
    }
  ]
}
```

| Method | Path | 说明 |
| --- | --- | --- |
| GET | `/shares/{id}/files?path=` | 列目录 |
| POST | `/shares/{id}/directories` | 新建目录 |
| POST | `/shares/{id}/files/upload?path=` | 上传 |
| GET | `/shares/{id}/files/download?path=` | 下载 |
| POST | `/shares/{id}/files/move` | 移动/重命名 |
| DELETE | `/shares/{id}/files?path=` | 删除 |

目录 picker 只供管理员创建共享时使用：

```http
GET /api/v1/system/fs/directories?path=/data
```

该接口：

- admin-only；
- 只列目录；
- 不读文件内容；
- 受系统目录黑名单约束；
- 不允许 `..`、非法 UNC/设备路径等；
- 返回 canonical path 与 ACL capability。

“文件预览”仍是非目标。前端可展示文本/图片图标和元数据，但服务端不提供在线内容预览接口。

### 5.12 Protocols

```http
GET /api/v1/protocols
```

```json
{
  "items": [
    {
      "protocol": "smb",
      "available": true,
      "state": "running",
      "implementation": "system",
      "provider": "samba",
      "connections": 4,
      "message": null
    }
  ]
}
```

操作：

```http
POST /api/v1/protocols/smb/start
POST /api/v1/protocols/smb/stop
POST /api/v1/protocols/smb/reload
```

均返回 Operation。`stop` 必须二次确认，并明确会断开现有客户端。

### 5.13 Audit

```http
GET /api/v1/audit
  ?from=2026-10-01T00:00:00Z
  &to=2026-10-04T23:59:59Z
  &protocol=SMB
  &user_id=usr_bob
  &share_id=shr_media
  &result=deny
  &q=notes.txt  &page=1
  &page_size=50
```

导出：

```http
GET /api/v1/audit/export.csv?...same filters...
```

审计记录：

```json
{
  "id": "aud_...",
  "timestamp": "2026-10-04T08:15:57Z",
  "actor": {
    "type": "user",
    "id": "usr_bob",
    "name": "bob"
  },
  "protocol": "smb",
  "action": "delete",
  "share_id": "shr_media",
  "path": "/private/notes.txt",
  "client_ip": "192.168.1.40",
  "result": "deny",
  "detail": {
    "reason": "acl_explicit_deny"
  },
  "request_id": null,
  "operation_id": null
}
```

### 5.14 System / Settings

| Method | Path | 说明 |
| --- | --- | --- |
| GET | `/system/info` | OS、版本、hostname、uptime |
| GET | `/system/capabilities` | SMB provider/445 ownership、ACL、Kerberos 等能力 |
| POST | `/system/doctor` | 深度诊断，Operation |
| POST | `/system/verify` | desired/applied 一致性巡检，Operation |
| GET | `/settings` | 可编辑设置 |
| PUT | `/settings` | 更新设置，必要时异步 Apply |
| GET | `/operations/{id}` | 查询 Operation |
| GET | `/operations/{id}/events` | SSE 进度流 |

敏感设置如证书私钥、keytab **只返回是否已配置和路径摘要，不返回内容**。

---

## 6. 后端代码架构

### 6.1 Cargo Workspace

```text
naos/
├─ Cargo.toml
├─ crates/
│  ├─ naosd/             # 进程入口、依赖装配、监听器、生命周期
│  ├─ naos-api/          # axum routes/handlers/middleware
│  ├─ naos-contract/     # API DTO、错误码、OpenAPI schema
│  ├─ naos-core/         # domain + application services
│  ├─ naos-store/        # sqlx repositories + migrations
│  ├─ naos-platform/     # 用户/ACL/服务/文件系统/端口检测
│  ├─ naos-smb/          # system SMB provider adapters
│  │  ├─ linux_samba/
│  │  ├─ macos/
│  │  └─ windows/
│  ├─ naos-webdav/       # WebDAV server + ACL integration
│  ├─ naos-nfs/          # ONC-RPC/XDR/NFSv3/MOUNT/NLM/GSS
│  └─ naos-audit/        # 审计归一化、解析、retention
├─ web/
├─ docs/
├─ packaging/
└─ xtask/
```

当前 workspace **不创建** `naos-smb-protocol`、`naos-smb-server`、`naos-smbd`。未来若恢复自研 SMB，再按 Deferred 设计引入。

### 6.2 依赖方向

```text
naosd
  ├── naos-api
  ├── naos-core
  ├── naos-store
  ├── naos-platform
  ├── naos-smb
  ├── naos-webdav
  ├── naos-nfs
  └── naos-audit

naos-api ───────► naos-contract
naos-api ───────► naos-core
naos-store ─────► naos-core
naos-platform ──► naos-core
naos-smb ───────► naos-core + naos-platform
WebDAV/NFS ─────► naos-core
```

核心规则：

- `naos-core` 不依赖 `axum`、`sqlx`、PowerShell/Samba。
- `naos-api` 不直接执行 SQL 或系统命令。
- `naos-store` 不包含 HTTP DTO。
- `naos-smb` 只负责 system provider detect/render/apply/verify/audit integration。
- provider adapter 只能管理 naos 明确拥有的配置/share，不接管未知配置。
- 端口/process/service 检测放 `naos-platform`，业务判断放 `naos-smb` / Reconciler。

### 6.3 API 层

示例：

```rust
pub async fn update_share(
    State(app): State<AppState>,
    Auth(admin): AuthenticatedAdmin,
    Path(id): Path<ShareId>,
    IfMatch(generation): IfMatch,
    Json(input): Json<UpdateShareRequest>,
) -> ApiResult<AcceptedOperation> {
    let op = app
        .share_service
        .update_share(admin.actor(), id, generation, input.into())
        .await?;

    Ok(AcceptedOperation::new(op))
}
```

Handler 负责：

- HTTP 参数解析；
- auth/RBAC；
- DTO → command；
- 调 application service；
- domain error → HTTP error；
- 响应 header。

Handler 不负责：

- SQL；
- ACL 算法；
- path canonicalize；
- 系统命令；
- protocol apply。

### 6.4 Application Service

```rust
pub struct ShareService {
    shares: Arc<dyn ShareRepository>,
    users: Arc<dyn UserRepository>,
    operations: Arc<dyn OperationRepository>,
    reconciler: Arc<Reconciler>,
    audit: Arc<dyn AuditSink>,
}
```

职责：

- use case 编排；
- transaction boundary；
- domain 校验组合；
- operation 创建；
- audit；
- 调 reconciler。

### 6.5 Repository Traits

```rust
#[async_trait]
pub trait ShareRepository: Send + Sync {
    async fn get(&self, id: &ShareId) -> Result<Option<Share>>;
    async fn list(&self, filter: ShareFilter) -> Result<Vec<Share>>;
    async fn insert(&self, share: &Share) -> Result<()>;
    async fn update_if_generation(
        &self,
        share: &Share,
        expected_generation: u64,
    ) -> Result<UpdateOutcome>;
}
```

`sqlx` 实现位于 `naos-store`。

### 6.6 Platform Traits

```rust
#[async_trait]
pub trait AccountManager: Send + Sync {
    async fn create_user(&self, user: &SystemUserSpec) -> Result<SystemUser>;
    async fn disable_user(&self, account: &str) -> Result<()>;
    async fn set_password(&self, account: &str, password: SecretString) -> Result<()>;
    async fn delete_user(&self, account: &str) -> Result<()>;
}

#[async_trait]
pub trait FilesystemAclManager: Send + Sync {
    async fn probe(&self, path: &Path) -> Result<AclCapability>;
    async fn snapshot(&self, path: &Path) -> Result<AclSnapshot>;
    async fn apply(&self, plan: &FsAclPlan) -> Result<()>;
    async fn restore(&self, snapshot: &AclSnapshot) -> Result<()>;
}
```

平台实现按：

```rust
#[cfg(target_os = "linux")]
#[cfg(target_os = "macos")]
#[cfg(target_os = "windows")]
```

隔离。

### 6.7 ProtocolAdapter

```rust
#[async_trait]
pub trait ProtocolAdapter: Send + Sync {
    fn protocol(&self) -> Protocol;
    async fn detect(&self) -> Result<Capability>;
    async fn render(&self, desired: &DesiredState) -> Result<ProtocolPlan>;
    async fn snapshot(&self) -> Result<ProtocolSnapshot>;
    async fn apply(&self, plan: &ProtocolPlan) -> Result<()>;
    async fn verify(&self, desired: &DesiredState) -> Result<VerifyReport>;
    async fn rollback(&self, snapshot: &ProtocolSnapshot) -> Result<()>;
    async fn status(&self) -> Result<ProtocolStatus>;
}
```

SMB 是外部 system service adapter。其 `detect()` 还必须返回 provider 与 445 端口状态：

```rust
pub struct SmbCapability {
    pub provider: Option<SmbProvider>,
    pub installed: bool,
    pub running: bool,
    pub port_445: PortState,
    pub ownership: ProviderOwnership,
    pub config_mode: ConfigMode,
    pub can_manage: bool,
    pub conflict: Option<SmbConflict>,
}
```

Apply 规则：

- 任何 SMB write operation 先执行 detect/preflight；
- 445 被目标 provider 占用且 provider 可管理：继续；
- 445 被未知/其它 provider 占用：返回 `SMB_PORT_CONFLICT`；
- **禁止通过 stop/kill 未知服务来自动修复冲突**；
- rollback 只回滚 naos 自己改动的 share/config/ACL，不恢复用户原有外部配置的未知变化。

WebDAV/NFS 仍为进程内动态配置。

---

## 7. Reconciler 与一致性模型

### 7.1 Generation

每个需要 Apply 的资源包含：

```text
generation          DB 中 desired state 版本
applied_generation  最后一次验证成功的版本
```

状态：

```text
generation == applied_generation  => in_sync
generation > applied_generation   => pending/applying/degraded
```

### 7.2 写操作流程

以修改共享为例：

```text
1. API 校验 RBAC / If-Match
2. Application Service 做输入与 domain 校验
3. DB transaction:
   - 记录 before snapshot
   - 更新 desired state，generation + 1
   - 创建 operation(queued)
   - 写 management audit
4. commit
5. Operation worker 获取资源级锁
6. Reconciler:
   validate
   → render plan
   → snapshot external state
   → apply filesystem ACL
   → apply SMB/WebDAV/NFS
   → verify
7a. success:
   - applied_generation = generation
   - operation = succeeded
7b. failure:
   - reverse rollback external state
   - 如 rollback 全成功：补偿 DB 到 before snapshot
   - 如 rollback 不完整：资源标记 degraded
   - operation = failed
8. SSE 发布最终状态
```

> 例外：密码/credential 更新包含不可逆的外部密码变更，不套用“任何失败都恢复旧状态”的普通 rollback 假设；按 §9.2.6 使用 forward-recovery + degraded 状态。

### 7.3 锁

避免两个管理员同时变更同一资源：

- `share:<id>` 资源锁；
- `user:<id>` 资源锁；
- 协议全局 reload 使用 `protocol:<p>` 锁；
- 多资源 operation 按稳定顺序获取锁，避免死锁。

进程内锁用于避免同一实例并发；SQLite generation 用于保证持久化层乐观并发。

### 7.4 Apply 顺序

推荐顺序：

```text
validate
→ filesystem capability
→ account changes
→ filesystem ACL
→ SMB system provider desired state / naos-owned config
→ WebDAV route
→ NFS export/binding
→ protocol reload/hot swap
→ verify
```

Rollback 必须按反序执行。

---

## 8. 身份与权限

### 8.1 用户模型

naos 用户创建时同步创建真实系统账号，用于 SMB system provider 和文件 ownership。

| 平台 | 系统账号 | SMB 凭据 |
| --- | --- | --- |
| Linux | `useradd -M -s /usr/sbin/nologin -G naos-users naos_<name>` | Samba account / password sync |
| macOS | 隐藏的 `naos_<name>` 本地账号 | 由选定 system SMB provider 使用/同步 |
| Windows | 本地 `naos_<name>` + 拒绝交互登录 | Windows SMB 使用系统本地账号 |

约束：

- `naos_` 前缀保留；
- 只管理 naos 自己创建并登记的系统账号；
- 删除前检查文件 ownership 影响；
- 密码不写日志、不进入 operation detail；
- 创建/改密必须同步 naos verifier 与当前 SMB provider credential；
- 外部 provider 的密码更新可能不可逆，失败时采用 forward-recovery/degraded 语义，不伪装成完整 rollback；
- 外部命令只传参数数组，禁止 shell 字符串拼接。

### 8.2 RBAC

v1 角色：

```text
admin
user
```

`admin`：

- 可管理系统、共享、ACL、用户、协议、审计；
- **不自动拥有共享文件访问权限**。

`user`：

- 可登录 UI；
- 只能查看自身 profile；
- 只能在文件浏览器访问 ACL 授权共享；
- 可修改本人密码；
- 无权查看系统设置、其它用户、全部审计。

### 8.3 ACL 求值

规则：

```text
(share, rel_path, subject, permission, inherit)
permission ∈ none | ro | rw
```

1. 从共享根到目标路径收集匹配规则。
2. 最深层级优先。
3. 同一层级：
   - 显式 `none` 优先；
   - 否则用户直授和组授权取 `max(ro, rw)`。
4. 无匹配规则默认拒绝。
5. `admin` 角色不绕过文件 ACL。

`inherit=false` 仅对规则所在精确路径生效；对子路径不参与匹配。

### 8.4 文件操作映射

| 操作 | 最低权限 |
| --- | --- |
| list/stat/read/download | `ro` |
| create/upload/write | `rw` |
| mkdir | `rw` |
| rename/move | 源父目录与目标父目录均 `rw` |
| delete | 父目录 `rw` |

服务端统一把操作转成 ACL capability 检查，避免各协议语义分裂。

---

## 9. SMB / WebDAV / NFS

### 9.1 协议矩阵

| 协议 | Linux | macOS | Windows |
| --- | --- | --- | --- |
| SMB | Samba system provider | system SMB provider；必要时 Samba | Windows SMB Server |
| WebDAV | 内置 | 内置 | 内置 |
| NFSv3 | 内置 | 内置 | 内置 |

### 9.2 SMB 当前实现策略

当前版本**不实现 SMB wire protocol**。naos 只负责：

```text
desired share / users / ACL
        │
        ▼
naos-smb
        │
        ├─ detect provider + TCP/445 owner
        ├─ render naos-owned config/share changes
        ├─ apply through system API/service
        ├─ sync filesystem ACL / credentials
        ├─ reload/start only the selected provider
        └─ verify effective state
        │
        ▼
system SMB provider
        │
        ▼
SMB clients
```

### 9.2.1 445 端口冲突原则

naos 永不以“先停掉当前服务再试”为默认策略。

Preflight：

```text
1. inspect TCP/445
2. identify process/service/provider
3. detect whether provider is supported
4. detect whether provider configuration is safely manageable
5. compare desired provider with active provider
6. decide reusable / conflict / install_required / stopped
```

典型情况：

| 情况 | 行为 |
| --- | --- |
| 445 空闲 + Samba 已安装 | 可启动 Samba 后 Apply |
| 445 由当前受管 Samba 监听 | 正常复用 |
| 445 由用户自己的 Samba 监听，且支持安全 include 接入 | 明确授权后只挂载 naos include |
| 445 由用户自己的 Samba 监听，但配置不可安全接入 | 拒绝，显示 unmanaged conflict |
| 445 由 macOS File Sharing 监听 | 不启动第二个 Samba；优先使用/适配当前 provider，否则提示冲突 |
| 445 由 Windows SMB Server 监听 | 正常，直接使用 Windows provider |
| 445 由 VM/容器/第三方软件监听 | 拒绝 Apply，不 kill 进程 |
| 445 listener 无法识别 | 拒绝 Apply，Doctor 展示 PID/service 信息（如平台可获取） |

### 9.2.2 Linux / Samba

- 检测 `smbd` 与 service manager 状态；
- 检测 TCP/445 实际 listener，不只看 service “active”；
- naos 只维护独立 include，例如 `naos-shares.conf`；
- 主配置接入必须是可识别、幂等、可移除的 include；
- 不覆盖用户已有 share block；
- `testparm` 成功后才 reload；
- reload 优先，不无故 restart；
- 使用真实 `naos_*` 用户；
- 文件系统 ACL 强制子目录权限；
- `vfs_full_audit` 或可用审计能力采集 SMB 活动。

如果发现现有 Samba 不是 naos 安装/管理的：

- 默认 `managed_by_naos=false`；
- 只有确认其配置支持安全 include，才允许 attach；
- attach 后仍只拥有自己的 include 文件；
- 卸载 naos 只移除自身 include，不删除用户 Samba 配置/其它 shares。

### 9.2.3 macOS

macOS 的主要风险是系统 File Sharing 与额外 Samba 同时争用 445。

策略：

1. 先检测 TCP/445；
2. 识别是否为系统 SMB/File Sharing 服务；
3. 如果当前 provider 有受支持的管理接口，则直接适配它；
4. 如果当前系统 SMB 无法满足 naos 所需能力，则报告 capability limitation；
5. **不得为了启用 Homebrew Samba 自动关闭用户的 macOS File Sharing**；
6. 只有在 445 空闲且管理员显式选择 Samba provider 时，才允许启用第三方 Samba；
7. provider 发生变化时必须重新 Verify 全部 SMB shares。

因此 macOS provider 能力需要通过真实系统版本测试后逐步固化，不能假设 Linux Samba 的控制方式可直接复用。

### 9.2.4 Windows

Windows 只使用系统 SMB Server：

- 检测 LanmanServer/Server service；
- TCP/445 已由系统服务监听属于正常状态；
- 使用 PowerShell cmdlets / 系统 API 创建、更新、删除 naos-owned share；
- 共享级权限与 NTFS ACL 同步；
- 不创建第二个 SMB listener；
- 不修改非 naos share；
- Event Log / 审计策略用于统一审计；
- service 未运行时，可在明确 Operation 中启动；不替换系统 SMB 实现。

### 9.2.5 Provider ownership

所有 provider 资源区分：

```text
naos_owned
attached
unmanaged
```

- `naos_owned`：naos 创建，可完整修改/删除；
- `attached`：外部 provider，但通过明确安全边界接入，只能修改 naos scope；
- `unmanaged`：只检测，不写。

任何 `unmanaged` 冲突不得被 Reconciler 自动“修复”。

### 9.2.6 SMB Verify

Verify 至少检查：

- 目标 provider 与实际 provider 一致；
- TCP/445 listener 归属预期 service；
- naos share 在 provider 中存在；
- path 与 desired canonical path 一致；
- enabled/disabled 状态一致；
- system account/credential 已 provision；
- share permission 与 FS ACL 一致；
- Linux/macOS Samba include 未漂移；
- Windows share 不与用户同名 share 冲突；
- 审计能力是否开启/可读取。

### 9.2.7 自研 SMB 状态

`docs/naos SMB P0 实现设计.md` 当前状态为：

```text
DEFERRED / FUTURE RESEARCH
```

它不属于：

- 当前 workspace；
- 当前 delivery plan；
- 当前 CI；
- 当前 Definition of Done。

未来只有在 system provider 路线无法满足产品需求、且 445 共存/部署策略重新评估后，才重新启动自研 SMB ADR。

### 9.3 WebDAV

URL：

```text
/dav/<share-name>/...
```

认证：

- v1 使用 Basic over TLS；
- Basic credential 验证后映射 naos 用户；
- 对每个文件操作调用 `acl-engine`；
- 路径 canonicalize 并限制在 share root。

WebDAV 管理页面 Session 与 WebDAV Basic 是两套认证入口，不混用 Cookie。

### 9.4 NFSv3

| 等级 | 机制 | 说明 |
| --- | --- | --- |
| L1 | `CIDR/IP → user` | 整台客户端映射为一个用户 |
| L2 | `(CIDR, uid) → user` | 同一客户端多用户 |
| L3 | RPCSEC_GSS | 可选 Kerberos |

未命中 L1/L2/L3：

```text
MOUNT 阶段拒绝 + audit deny
```

L1/L2 只适合可信局域网或 VPN，UI 必须持续展示风险提示。

File handle 采用带 MAC 的 opaque 结构，至少绑定：

```text
share_id + filesystem identity + generation + nonce/version
```

避免客户端构造跨共享 handle。

NFSv3 数据面当前实现约束：

- `naos-nfs` 进程内实现 ONC-RPC v2 / XDR / TCP record marking、MOUNT v3 与 NFSv3；
- v1 的 **NFSv3/MOUNT 文件数据面仅提供 TCP**；为兼容 macOS/BSD 的 NFSv3 远程锁发现，NLMv4/NSMv1 辅助 RPC 同时监听 TCP 与 UDP，这不改变 NFS 文件读写仍为 TCP-only 的约束；
- `naosd` 默认 **不启用 NFS listener**，避免安装后无条件占用 NFS 相关端口；
- 启用后默认 NFS 端口为 `2049`、MOUNT 端口为 `20048`、NLM 端口为 `20049`、NSM 端口为 `20050`，均可配置；绑定失败直接启动失败，不自动停止/替换其它 listener；
- `rpcbind/portmapper` 注册是显式可选项，默认关闭；开启时仅向本机 `127.0.0.1:111` 发起 portmapper v2 SET/UNSET：NFSv3/MOUNTv3 注册 TCP，NLMv4/NSMv1 注册 TCP+UDP；NLM 异步结果回调查询客户端 lockd 端口时优先使用 RPCBIND v4/v3 GETADDR，并保留 portmapper v2 GETPORT fallback；
- naos **不自行监听 111**，也不启动、停止或覆盖系统 rpcbind；注册失败视为 NFS 启动失败；
- 不启用 rpcbind 时，客户端必须显式知道 NFS/MOUNT 端口；需要 NFSv3 远程锁的客户端还必须由部署层提供 NLM/NSM 等价服务发现，否则应显式使用 `nolock/nolocks`；
- 当前实现的 NFSv3 procedure 至少包含 `NULL/GETATTR/SETATTR/LOOKUP/ACCESS/READLINK/READ/WRITE/CREATE/MKDIR/SYMLINK/MKNOD/REMOVE/RMDIR/RENAME/LINK/READDIR/READDIRPLUS/FSSTAT/FSINFO/PATHCONF/COMMIT`；其中 `SYMLINK` 创建当前仅在 Unix 平台启用，Windows 返回 `NFS3ERR_NOTSUPP`，避免在 NFSv3 不提供目标类型信息时错误选择 Windows file/dir symlink API；`MKNOD` procedure 11 会完整校验对应 XDR union，但 naos 不开放远程 device/FIFO/socket special-file creation，因此对有效请求显式返回 `NFS3ERR_NOTSUPP`，而不是 RPC `PROC_UNAVAIL`；
- NLMv4（program `100021` / version `4`）已提供 TCP+UDP listener；同步 procedure 覆盖 `NULL/TEST/LOCK/CANCEL/UNLOCK/SHARE/UNSHARE/NM_LOCK/FREE_ALL`，并已支持 macOS/BSD 常用的 `TEST_MSG/LOCK_MSG/CANCEL_MSG/UNLOCK_MSG → *_RES` 异步结果回调；byte-range 锁表为进程内状态，支持共享/排他锁、64-bit range、部分解锁，并在 Unix 以 filesystem identity 统一 hard-link/rename 后的同一文件锁身份；DOS-style share reservation 同样为进程内状态，按 NLMv4 bit-encoded deny/access mask 判断冲突，支持 grace 内 reclaim、UNSHARE、FREE_ALL 与 peer reboot cleanup；
- NSMv1/status monitor（program `100024` / version `1`）已提供 TCP+UDP 端点，覆盖 `NULL/STAT/MON/UNMON/UNMON_ALL/SIMU_CRASH/NOTIFY`；协议层 monitor/private-cookie 仍属于当前进程运行期状态，`UNMON/UNMON_ALL` 真正撤销 monitor，`NOTIFY` 会记录 peer state-change 并通过 server event loop 通知 NLM 清理该 peer IP 的 held locks 与 blocked waiters，再重新尝试授予其它 waiter；NSM server up-state epoch 已持久化到 SQLite，首次启动为 1，后续 daemon restart 或持久化 `SIMU_CRASH` 按 3/5/7… 推进并保持奇数。通过身份/FH/ACL 校验的 NLM LOCK peer IP 另行持久化到 `nfs_nsm_peers`；daemon restart 后按新 epoch 通过 peer rpcbind 查询 NSMv1/UDP，按到该 peer 的实际路由选择本机源 IP 作为 reboot identity 并发送 `SM_NOTIFY`。只有收到匹配 xid 的成功 RPC reply 才删除 peer 记录；查询、发送、超时或 reply 校验失败都会有限重试并保留记录，供客户端 lockd/statd 可靠进入 reclaim；
- 阻塞 `LOCK(block=true)` 冲突现在返回 `NLM4_BLOCKED` 并进入等待队列；持有锁通过 `UNLOCK/FREE_ALL` 释放后，服务端按冲突顺序挑选可授予请求，预留锁后发送同步 `NLMPROC4_GRANTED` callback，只有客户端回复 `NLM4_GRANTED` 才保留锁，回调失败/拒绝则回滚预留；`CANCEL` 会删除对应等待请求。在线 peer reboot 的 `SM_NOTIFY → NLM lock cleanup` 已实现并有真实 server TCP 联动测试；naosd restart 后会进入 30 秒 NLM grace，普通新锁返回 `NLM4_DENIED_GRACE_PERIOD`，`reclaim=true` 才允许按现有身份/ACL/冲突规则重建 held-lock state。NFS handle HMAC secret 与 nonce→share/path registry、NSM epoch、参与过有效 NLM LOCK 的 peer IP 已持久化；server restart 后旧 child file handle 可继续解析，并会主动向持久 peer 发送新 epoch 的 `SM_NOTIFY` 以触发客户端 reclaim。当前 server TCP E2E 已覆盖“旧 FH 跨两次 restart 继续 GETATTR、restart grace 内普通 LOCK 被拒、reclaim LOCK 成功、NSM epoch 1→3→5→7”；held locks/waiters 与完整 NSM monitor/private-cookie 本身仍为进程内状态，最终 crash-recovery 仍依赖客户端按 NLM grace 语义 reclaim。真正的内核客户端自动 `SM_NOTIFY → reclaim` 互操作仍必须用分离 client/server 主机验证，因为同机 loopback 会让 server 与 macOS client lockd/statd 共用 port 111/RPC 注册空间。
- MOUNT v3 支持 `NULL/MNT/DUMP/UMNT/UMNTALL/EXPORT`；
- MOUNT 与 NFSv3 共用同一 file-handle table，rename 后已签发 handle 保持有效，delete 后对应 handle 变为 stale；
- file-handle HMAC secret 与 nonce→share/path registry 已持久化到 SQLite；同一 share/path 会复用 registry 中的 nonce，rename 会事务化更新相关 handle path，delete/rmdir 会删除对应 registry 项。只要 share generation 与 canonical root 未发生使 handle 失效的变化，`naosd` 重启后旧 handle 可继续使用；绝对宿主机路径仍不会直接编码进 wire handle；
- L1/L2 权限继续复用 `NfsBindingRepository + acl-engine + SafePathResolver`，协议层不得另写一套 ACL 规则；
- L3/RPCSEC_GSS 已开始协议基础层：RPC decoder 识别 flavor 6 的 credential wire fields（version/gss_proc/seq_num/service/context handle），保留 RPC verifier 与计算 header MIC 所需的“header through credential”原始字节；pre-dispatch gate 按 RFC 2203 校验 context-creation/data/destroy 的基本 wire shape（version、NULLPROC、handle、service、seq_num、verifier），并在尚未接入 GSS context 时以 RPC AUTH_ERROR 明确拒绝：INIT/CONTINUE_INIT 返回 AUTH_REJECTEDCRED，合法形状的 DATA/DESTROY 返回 RPCSEC_GSS_CREDPROBLEM，错误 verifier/credential 返回对应 auth_stat。因此 RPCSEC_GSS control message 不会误走普通 NFS/MOUNT NULLPROC 成功路径，也绝不回退到 L1 IP 身份。数据层已加入 integrity envelope codec（`opaque(seq_num + arguments) + opaque(checksum)`）与 GSS unwrap 后 plaintext 的 sequence-number 校验，并提供对应 encoder；握手层已加入 INIT/CONTINUE_INIT token 与 `rpc_gss_init_res` codec、带自定义 verifier 的 accepted reply encoder、`seq_window`/`seq_num` 的网络序 MIC 输入 helper，以及 RFC 2203 sliding sequence replay window 状态机；同时新增可插拔 `RpcSecGssSecurityContext` provider contract 与 context registry，负责 handle 生命周期和 per-context replay window；DATA 安全管线已经把 header VerifyMIC、`svc_none` 明文参数、`svc_integrity` body MIC、`svc_privacy` unwrap 串起来，并严格在所有密码学验证成功后才提交 replay window，避免伪造请求消耗 sequence slot。回复侧会生成对 `seq_num` 的 verifier MIC，并按 none/integrity/privacy 生成对应 reply body。SQLite 中既有的 `nfs_krb_principals` 已接入 repository principal→enabled naos user resolver；管理面已实现 admin-only 的 `GET/POST /api/v1/nfs/principals` 与 `DELETE /api/v1/nfs/principals/{id}`，支持 exact principal 映射、enabled user 校验、唯一性冲突与 CSRF 防护。NFSv3 与 MOUNTv3 DATA dispatch 均可在显式注入 context registry 时把通过 GSS 校验的 principal 转换为内部 L3 identity；MOUNT 命中 principal 映射后返回仅含 RPCSEC_GSS 的 auth flavor，NFS 数据面绕过 L1/L2 CIDR/UID binding cap 但继续复用同一 ACL engine。两条路径都会对 accepted reply 应用 sequence verifier 与 service body protection，replay/too-old request 按 RFC 2203 silent-drop。握手层进一步定义了平台无关的 `RpcSecGssAcceptor` contract 与 INIT/CONTINUE_INIT 状态机：creation request 的 seq/service 明确按 RFC 2203 忽略，CONTINUE handle 必须稳定；CONTINUE/COMPLETE 返回非空 handle + seq_window，GSS failure 强制返回空 handle/token；COMPLETE reply verifier 对 seq_window 做 MIC，并仅在完成后把 security context 注册进 DATA registry。NFSv3/MOUNTv3 dispatcher 已可在显式注入 acceptor + registry 时截获 NULLPROC 的 INIT/CONTINUE_INIT 控制消息并执行上述状态机，完成后同一 registry 直接服务后续 DATA；未注入 acceptor 时继续走原 fail-closed gate。RPCSEC_GSS_DESTROY 也已按 data-request 保护规则接入 NFSv3/MOUNTv3：NULLPROC + 有效 header MIC/sequence/body protection 校验成功后先生成受保护 SUCCESS reply，再从 registry 移除 context；重放/过旧 sequence 保持 silent-drop。DATA/DESTROY 的 RFC 2203 error class 同时收敛到安全层：未知 context/坏 header MIC → CREDPROBLEM，sequence 超 MAXSEQ → CTXPROBLEM，integrity/privacy body 校验或 unwrap/sequence-envelope 失败 → accepted GARBAGE_ARGS。Unix 生产路径已经通过 `system-gss` feature 接入系统 Kerberos/GSS acceptor，并由 `naosd` 的 service-principal 配置装配到共享 MOUNT/NFS RPCSEC_GSS registry；默认构建和未配置 Kerberos 的运行路径仍保持 fail-closed。Linux CI 使用临时 MIT Kerberos realm、service keytab 与真实 client credential，已经覆盖 INIT/CONTINUE、reply verifier、`svc_none`、`svc_integrity`、replay rejection，以及真实 TCP MOUNT → NFS GETATTR。privacy 进一步按 RFC 4121 校验 Wrap token `TOK_ID=05 04` 与 `Sealed` 标志：仅在 context 协商 `GSS_C_CONF_FLAG` 且每个 token 确认可加密时启用 `svc_privacy`/`krb5p`，旧格式或无法确认 confidentiality 的 token fail-closed。Windows 侧 `system-gss` 使用原生 Kerberos SSPI backend：使用进程/服务账户的 inbound credential 驱动 `AcceptSecurityContext`，完成后提取 client/server native principal，强制 server principal 与配置的完整 NFS service principal 匹配，并以 `MakeSignature/VerifySignature` 提供 `krb5/krb5i`。Windows `krb5p` 使用 `EncryptMessage` 的 TOKEN+DATA+PADDING 与 `DecryptMessage` 的 STREAM 互操作形态；仅在 `ASC_RET_CONFIDENTIALITY` 已协商且 RFC 4121 Wrap token 设置 `Sealed` 时开放 privacy，并拒绝 sign-only QOP。Windows feature CI 负责编译/Clippy/单测；由于 hosted runner 不在真实 AD 域内，分离真实主机/域环境的 Windows Kerberos 客户端端到端互操作仍是独立 gate；L3 继续作为独立 feature，不计入 L1/L2 基础数据面的完成条件。

对应运行参数：

```text
--nfs-enabled / NAOS_NFS_ENABLED
--nfs-listen  / NAOS_NFS_LISTEN
--nfs-port    / NAOS_NFS_PORT
--mount-port  / NAOS_MOUNT_PORT
--nlm-port    / NAOS_NLM_PORT
--nsm-port    / NAOS_NSM_PORT
--nfs-rpcbind / NAOS_NFS_RPCBIND
```

---

## 10. 数据模型

推荐 SQLite schema：

```sql
users(
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  pw_hash TEXT NOT NULL,
  role TEXT NOT NULL,
  enabled INTEGER NOT NULL,
  sys_account TEXT NOT NULL UNIQUE,
  sys_uid INTEGER,
  generation INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);


groups(
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  generation INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

group_members(
  group_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  PRIMARY KEY(group_id, user_id)
);

shares(
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  path TEXT NOT NULL,
  canonical_path TEXT NOT NULL,
  comment TEXT,
  enabled INTEGER NOT NULL,
  smb_on INTEGER NOT NULL,
  webdav_on INTEGER NOT NULL,
  nfs_on INTEGER NOT NULL,
  generation INTEGER NOT NULL DEFAULT 1,
  applied_generation INTEGER NOT NULL DEFAULT 0,
  apply_state TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

share_acl(
  id TEXT PRIMARY KEY,
  share_id TEXT NOT NULL,
  rel_path TEXT NOT NULL,
  subject_type TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  perm TEXT NOT NULL,
  inherit INTEGER NOT NULL,
  UNIQUE(share_id, rel_path, subject_type, subject_id)
);

nfs_bindings(
  id TEXT PRIMARY KEY,
  share_id TEXT NOT NULL,
  cidr TEXT NOT NULL,
  uid INTEGER,
  user_id TEXT NOT NULL,
  perm TEXT NOT NULL
);

nfs_krb_principals(
  id TEXT PRIMARY KEY,
  principal TEXT NOT NULL UNIQUE,
  user_id TEXT NOT NULL
);

sessions(
  id TEXT PRIMARY KEY,
  token_hash BLOB NOT NULL UNIQUE,
  user_id TEXT NOT NULL,
  csrf_hash BLOB NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  client_ip TEXT,
  user_agent TEXT
);

operations(
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  state TEXT NOT NULL,
  actor_user_id TEXT,
  resource_type TEXT,
  resource_id TEXT,
  request_id TEXT,
  idempotency_key TEXT,
  progress INTEGER NOT NULL DEFAULT 0,
  phase TEXT,
  error_code TEXT,
  error_detail_json TEXT,
  created_at TEXT NOT NULL,
  started_at TEXT,
  finished_at TEXT
);

operation_events(
  operation_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  event TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  ts TEXT NOT NULL,
  PRIMARY KEY(operation_id, seq)
);

audit_log(
  id TEXT PRIMARY KEY,
  ts TEXT NOT NULL,
  actor_type TEXT NOT NULL,
  actor_id TEXT,
  actor_name TEXT,
  protocol TEXT,
  action TEXT NOT NULL,
  share_id TEXT,
  path TEXT,
  client_ip TEXT,
  result TEXT NOT NULL,
  detail_json TEXT,
  request_id TEXT,
  operation_id TEXT
);

apply_history(
  id TEXT PRIMARY KEY,
  ts TEXT NOT NULL,
  target_type TEXT NOT NULL,
  target_id TEXT,
  desired_generation INTEGER,
  plan_json TEXT NOT NULL,
  status TEXT NOT NULL,
  rollback_json TEXT
);

settings(
  key TEXT PRIMARY KEY,
  value_json TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
```

索引至少包括：

```sql
CREATE INDEX idx_audit_ts ON audit_log(ts DESC);
CREATE INDEX idx_audit_user ON audit_log(actor_id, ts DESC);
CREATE INDEX idx_audit_share ON audit_log(share_id, ts DESC);
CREATE INDEX idx_audit_result ON audit_log(result, ts DESC);
CREATE INDEX idx_operations_state ON operations(state, created_at);
CREATE INDEX idx_sessions_user ON sessions(user_id);
```

---

## 11. 路径与文件系统安全

所有共享根在保存时执行：

```text
input path
→ platform-specific normalization
→ canonicalize
→ reject forbidden root
→ reject naos private data path
→ nested share conflict check
→ ACL capability probe
→ store canonical_path
```

黑名单至少：

```text
Linux: /
       /etc /proc /sys /dev /boot
macOS: /
       /System
Windows:
       C:\Windows
       C:\Program Files\naos
       device namespaces
naos data directory on every platform
```

每次文件操作仍需做 runtime containment check，不能只相信创建共享时的结果。必须防御：

- `..` traversal；
- symlink/junction escape；
- Windows reparse point；
- UNC/device path；
- TOCTOU。

能使用 descriptor/handle-relative API 时优先使用，减少“校验后路径被替换”的竞态。

---

## 12. 审计

### 12.1 来源

| 来源 | 实现 |
| --- | --- |
| 管理 API | middleware + application service |
| WebDAV | 进程内直接写 |
| NFS | 进程内直接写 |
| SMB Linux/macOS Samba | `vfs_full_audit` 等 provider 日志解析 |
| SMB macOS native | 使用系统可用审计来源；能力不足时 Doctor 明示 |
| SMB Windows | Event Log / Windows auditing |

SMB 审计属于 system-provider integration，必须允许“provider 可用但细粒度 audit capability 不完整”的 degraded 状态，不能伪造完整审计。

### 12.2 审计类别

```text
management.login
management.user.create
management.share.update
management.acl.update
protocol.read
protocol.write
protocol.delete
protocol.mount
security.deny
system.apply
system.rollback
system.verify
```

审计 detail 中不记录：

- 密码；
- password hash；
- Cookie/session token；
- CSRF token；
- Kerberos keytab 内容；
- TLS private key。

### 12.3 保留

默认 90 天。后台低优先级任务每天清理；清理动作本身写 system audit。

---

## 13. 安全设计

| 威胁 | 对策 |
| --- | --- |
| 管理面公网暴露 | 默认 loopback；非 loopback 必须 TLS |
| Session 被窃取 | HttpOnly + Secure + SameSite=Strict + DB revoke |
| CSRF | per-session CSRF + mutation header |
| 暴力破解 | IP + username 双维度限速 |
| 密码泄露 | Argon2id；provider credential 只经受限接口同步；日志 redaction |
| 路径穿越 | canonicalize + containment + handle-relative IO |
| Symlink/Junction 逃逸 | runtime 校验 + 平台安全 API |
| 命令注入 | `Command::args`，绝不使用 shell 拼接 |
| 覆盖用户 SMB 配置 | 只维护 naos-owned include/share；attached provider 最小写入 |
| **TCP/445 冲突** | preflight 识别 listener/provider；未知 owner 时拒绝；naos 不抢占端口 |
| 擅自停止用户 SMB | **禁止**自动 stop/kill unmanaged provider |
| Samba 配置错误 | render 到临时文件 → `testparm` → atomic replace/reload |
| Windows 非 naos share 被误改 | share ownership/tag/registry 记录 + before/after verify |
| SMB ACL 漂移 | desired generation + FS ACL/provider Verify + Doctor |
| NFS AUTH_SYS 伪造 | L1/L2 仅可信网络；敏感环境使用 L3 |
| 异步状态漂移 | generation/applied_generation + verify |
| 管理员并发覆盖 | ETag / If-Match |
| 双击创建 | Idempotency-Key |
| Secret 输出 | 结构化 redaction + SecretString |
| root/SYSTEM 攻击面 | platform 模块集中、依赖最小、严格审计 |

建议 HTTP 安全头：

```text
Content-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'none'
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

---

## 14. 可观测性

### 14.1 日志

结构化日志至少包含：

```text
timestamp
level
target/module
request_id
operation_id
user_id
share_id
protocol
duration_ms
error_code
```

不要把完整密码、Cookie、Authorization header 写入日志。

### 14.2 Request ID

每个 HTTP 请求：

- 接受合法 `X-Request-ID` 或服务端生成；
- 响应 `X-Request-ID`；
- audit 和 operation 关联同一个 request_id。

### 14.3 Health

本地 health endpoint：

```http
GET /health/live
GET /health/ready
```

- live：进程事件循环存活；
- ready：DB migration 完成，核心依赖初始化完成。

默认不暴露敏感系统细节。

---

## 15. 系统配置

配置优先级：

```text
CLI flags > environment > config file > defaults
```

示例：

```toml
[server]
listen = "127.0.0.1"
port = 8443
tls = true
cert = "/etc/naos/tls/cert.pem"
key = "/etc/naos/tls/key.pem"

[security]
session_minutes = 30
max_login_failures = 5
lock_minutes = 5
min_password_length = 12

[audit]
retention_days = 90

[protocols]
smb_enabled = true
webdav_enabled = true
nfs_enabled = true

[smb]
provider = "auto"           # auto | samba | macos_native | windows_native
conflict_policy = "refuse" # 当前只允许 refuse
attach_existing = false     # 外部 provider 需显式授权后才能 attach

[nfs]
kerberos_enabled = false
```

Secret 值优先从受限文件读取，不建议通过普通环境变量长期保存。

---

## 16. 部署

| 平台 | Service | 包 |
| --- | --- | --- |
| Linux | systemd | deb / rpm / 静态二进制 |
| macOS | launchd | pkg / Homebrew |
| Windows | Windows Service | MSI |

数据目录：

```text
Linux   /var/lib/naos
macOS   /Library/Application Support/naos
Windows %ProgramData%\naos
```

配置目录与数据目录权限仅 root/SYSTEM 和 naos 服务可读写。

SQLite：

- WAL 模式；
- 定期 checkpoint；
- schema migration 启动时执行；
- migration 失败则服务进入 not-ready，不继续管理协议。

---

## 17. OpenAPI 与前后端契约

Rust DTO：

```rust
#[derive(Serialize, Deserialize, ToSchema)]
pub struct ShareDto {
    pub id: ShareId,
    pub name: String,
    pub path: String,
    pub protocols: ShareProtocolsDto,
    pub generation: u64,
    pub applied_generation: u64,
    pub apply_state: ApplyState,
}
```

CI 生成：

```text
cargo run -p naosd -- export-openapi > web/openapi.json
npm run generate:api
git diff --exit-code
```

原则：

- OpenAPI 是前后端契约，不是手写文档副本；
- TypeScript 类型从 OpenAPI 生成；
- breaking API 变更必须同时修改 backend、schema、frontend；
- `/api/v1` 内不做无兼容处理的字段删除/语义替换。

---

## 18. 测试策略

### 18.1 Rust 单元测试

重点：

- ACL 求值；
- path normalization / containment；
- CIDR/UID binding；
- DTO ↔ domain 转换；
- error mapping；
- config renderer golden tests；
- operation state machine。

### 18.2 API Integration

使用临时 SQLite + fake platform/protocol adapter：

```text
login
→ create user
→ create share
→ set ACL
→ simulate ACL
→ operation complete
→ audit exists
```

覆盖：

- 401/403；
- CSRF；
- If-Match；
- Idempotency-Key；
- 422 field errors；
- failed apply + rollback；
- SSE reconnect。

### 18.3 前端测试

- Vitest：纯函数/hooks；
- React Testing Library：表单、错误态、权限门卫；
- MSW：API mock；
- Playwright：核心 E2E。

核心 E2E：

```text
首次初始化
→ admin 登录
→ 创建用户
→ 创建共享
→ 设置 ACL
→ 等待 operation 成功
→ 权限模拟
→ 普通用户登录
→ 文件浏览访问允许/拒绝
```

### 18.4 协议一致性测试

同一 ACL case matrix 对三个协议执行：

```text
user × group × path × operation × expected_permission
```

SMB/WebDAV/NFS 结果必须一致。

### 18.5 SMB system provider integration

重点不测试 SMB packet parser，而测试 provider 管理边界：

**Port / Provider detection**

- 445 空闲；
- 445 由目标 provider 占用；
- 445 由未知进程占用；
- service active 但 445 未监听；
- 445 listener 存在但 service 状态异常；
- provider 在 apply 期间发生变化。

**Ownership**

- naos-owned share 可增删改；
- unmanaged share 不修改；
- 同名 unmanaged share 拒绝创建；
- 卸载/rollback 不删除用户 share；
- Samba 主配置已有其它 include 时保持不变。

**Apply / Verify**

- `testparm` 失败不 reload；
- reload 失败可恢复 naos-owned config snapshot；
- Windows share 创建后 Verify path/ACL；
- macOS provider capability 不足时明确 degraded/unsupported；
- provider 漂移能被 Doctor 发现。

**Client interoperability**

最终仍使用真实客户端验证：

- Windows Explorer / `net use`；
- macOS Finder / `mount_smbfs`；
- Linux `mount.cifs` / `smbclient`；
- create/read/write/rename/delete；
- ACL allow/deny；
- 大文件与 Unicode filename。

### 18.6 NFS

- Linux `nfs-utils`：专用 self-hosted runner 可执行本地真实 NFSv3 smoke，也可在分离 server 拓扑下执行 NLMv4 record-lock 与 restart/reclaim smoke；
- macOS client；
- Windows NFS client：专用 self-hosted runner 使用系统 Client for NFS，覆盖 mount/create/truncate/read/write、Unicode filename/content、2 MiB binary + forced flush/hash verify、rename/delete；另有分离 server 的远程 NLMv4 smoke，使用两个独立 PowerShell 进程做 byte-range lock 冲突，并以 direct NLM TEST 从 wire 验证服务端锁状态，可选验证 restart 后自动 reclaim；
- `pynfs` 子集；
- RPC/XDR fuzz；
- malformed packet；
- forged handle；
- UID/CIDR spoof case。

### 18.7 安全测试

- traversal；
- symlink/reparse escape；
- CSRF；
- session fixation；
- login brute force；
- header injection；
- command argument injection；
- stale ETag overwrite；
- duplicate POST；
- rollback failure；
- TCP/445 unknown-listener conflict；
- unmanaged SMB provider 不被自动停止/覆盖；
- Samba config injection/escaping；
- provider command argument injection；
- provider/service 状态漂移；
- unmanaged share 同名冲突。

---

## 19. CI/CD

建议 GitHub Actions：

```text
lint
├─ cargo fmt --check
├─ cargo clippy --all-targets --all-features
├─ npm lint
└─ npm typecheck

test
├─ rust unit/integration
├─ frontend unit
└─ contract generation check

platform
├─ ubuntu-latest
├─ macos-latest
└─ windows-latest

e2e
├─ browser E2E
├─ SMB system-provider integration
├─ SMB 445 conflict/ownership scenarios
├─ WebDAV protocol smoke tests
├─ NFS in-process TCP smoke: MOUNT root handle → NFS GETATTR
└─ NFS privileged/client-mount smoke（专用 runner）

package
├─ linux
├─ macOS
└─ Windows
```

对 NFS root/privileged 测试使用专门 runner 或能力受控的集成环境，不能假设普通 GitHub hosted runner 可完成全部 mount 场景。

当前仓库的 `.github/workflows/nfs-real-smoke.yml` 在 push 上使用 macOS hosted runner 做同机 NFSv3 基础数据面 smoke，并显式保持 `nolocks`，避免把 loopback portmapper/lockd 冲突误判成服务器 NLM 缺陷；Linux/Windows 真实客户端仍通过专用 self-hosted runner 手动执行。Windows runner 脚本会先验证本机 portmapper 与完整 NFS/MOUNT/NLM/NSM 注册，再用系统 Client for NFS 做基础数据面、Unicode 名称/内容和多块 binary + forced flush/hash 校验；普通 Windows CI 只做 PowerShell syntax gate，不伪装成真实 Client for NFS 验证。远程锁互操作对 Linux/macOS 共用 `scripts/ci/nfs-remote-lock-smoke.sh`，Windows 使用 `scripts/ci/windows-nfs-remote-lock-smoke.ps1`：三者都要求分离 client/server 拓扑、先确认远端 NLMv4/NSMv1 UDP 注册，再由两个独立进程制造真实锁冲突，并构建 `nfs-nlm-probe` 直接执行 `MOUNT → NFS LOOKUP → NLM TEST`，从 wire 上确认服务端 lock table 状态，避免把客户端本地锁表误当成服务端证据。远程 macOS NLM job 默认保持启用（`remote_macos_nlm=true`）以兼容现有流程，但可显式关闭；Linux 与 Windows 远程 NLM job 默认关闭，分别通过 workflow_dispatch 的 `remote_linux_nlm=true` / `remote_windows_nlm=true` 显式启用，因此可以按 self-hosted runner 实际可用情况任意组合三类客户端。Windows 使用系统 Client for NFS 默认启用的 locking，不传 `nolock`。可选 `remote_nlm_restart_target=user@host` 会让 macOS/Windows 远程锁 smoke 进入 restart/reclaim 模式：holder 保持锁不退出，通过固定的 `ssh + sudo systemctl restart <validated-service>` 重启远端 naosd，等待 NLM/NSM RPC 注册恢复并超过 30 秒 grace 后，本地 contender 与 direct NLM TEST 仍必须证明原锁已 reclaim；holder 主动解锁后两者都必须转为 unlocked。两个远程 NLM job 使用同一 concurrency group，避免对同一 server 并发 restart。self-hosted runner 需要预先配置 Client for NFS/NFS 工具、BatchMode SSH/host key 与该 service 的免交互 restart 权限。

---

## 20. 交付计划

当前 roadmap 不包含自研 SMB。

| 阶段 | 工作流 | 出口标准 |
| --- | --- | --- |
| 1 | workspace + contract + store + api 骨架 | OpenAPI、migration、health 可用 |
| 2 | auth/session/CSRF/RBAC | 登录、注销、会话撤销、安全测试通过 |
| 3 | core + ACL + path validation | ACL/path 单测矩阵全绿 |
| 4 | platform 三平台账号/FS ACL + service/port detection | 账号/ACL 幂等；可识别 TCP/445 owner |
| 5 | operations + reconciler | SSE、generation、rollback/degraded 完整 |
| 6 | **SMB Linux Samba adapter** | 安全 include、445 preflight、ACL、reload/verify、真机读写 |
| 7 | **SMB Windows native adapter** | Windows share/account/ACL、445/service verify、真机读写 |
| 8 | **SMB macOS provider adapter** | 先检测系统 File Sharing；无端口抢占；支持路径明确 |
| 9 | SMB Doctor / conflict UX | UI 展示 provider、445 owner、冲突原因和可执行修复建议 |
| 10 | WebDAV | ACL 一致性矩阵通过 |
| 11 | NFS L1/L2 | 基础数据面 + in-process/真实 TCP smoke 已完成；NLMv4 同步 range-lock、DOS SHARE/UNSHARE reservation、异步 *_MSG/*_RES、BLOCKED→GRANTED、CANCEL、RPCBIND v4/v3 callback discovery 与 NSMv1 peer reboot cleanup 已接入；file-handle secret + nonce/path registry、NSM epoch、有效 NLM peer IP 已持久化，daemon restart grace/reclaim 与带 RPC acknowledgement 的 restart `SM_NOTIFY` 已实现，server E2E 覆盖旧 FH 跨两次 restart、reclaim 与 NSM epoch 1→3→5→7。分离主机远程 NLM smoke harness 已覆盖 Linux、macOS 与 Windows Client for NFS 的 record-lock，并支持可选 server restart/reclaim；剩余关键 gate 是在已配置真实分离 client/server 的 self-hosted runner 上实际跑绿三类客户端的自动 `SM_NOTIFY → reclaim`；macOS 基础内核 NFS 数据面继续自动化通过 |
| 12 | NFS L3（feature） | RPCSEC_GSS wire/control/DATA、replay window、context registry、principal→enabled user、MOUNT/NFS L3 dispatch、DESTROY 与 RFC 2203 error mapping 已完成；Unix `system-gss` 已接 MIT/Heimdal/macOS GSS，Linux 临时 MIT realm CI 已真实跑通 `krb5/krb5i/krb5p` 与 MOUNT→NFS TCP。Windows `system-gss` 已接原生 Kerberos SSPI，完成 inbound credential、`AcceptSecurityContext`、client/server principal 校验、`MakeSignature/VerifySignature` 与 `EncryptMessage/DecryptMessage` privacy/QOP，当前开放 `krb5/krb5i/krb5p` 并对未协商 confidentiality / 未 sealed token fail-closed。剩余关键 gate：分离真实主机/企业 Kerberos realm 的 Windows/macOS/Linux 内核客户端互操作验证 |
| 13 | React Web UI | **进行中**：正式 Vite/React SPA 骨架、OpenAPI 类型生成、Session/CSRF、首次初始化/登录、Dashboard、个人安全、Settings/Doctor/Verify、NFS Kerberos principal、Users / Shares 目录、Operation-backed Share 创建/修改/删除、Share Detail + NFS L1/L2 binding CRUD、ACL 规则查看与后端权限模拟、分页/筛选 Audit 页面已接真实 API；剩余用户写操作、ACL 原子写入、Files 等核心页面 API 化 |
| 14 | 审计/Doctor/Verify | 可检索、可导出、漂移可发现 |
| 15 | 打包/E2E/安全测试 | 三平台可安装、升级、卸载 |

自研 SMB 重新进入 roadmap 必须先通过新的 ADR，明确：

- 为什么 system provider 已不能满足产品目标；
- Windows/macOS/Linux 445 coexistence 策略；
- 安装/升级时如何避免现有 SMB 服务中断；
- 自研协议的安全维护成本与测试预算。

---

## 21. 关键实现约束

实现过程中以下规则视为架构红线：

1. React 组件内不得复制 ACL 求值逻辑。
2. API handler 不得直接调用 SQL 或系统命令。
3. `naos-core` 不得依赖 `axum`/`sqlx`/PowerShell/Samba。
4. 所有宿主机文件路径在信任前必须 canonicalize/containment 检查。
5. 外部命令不得通过 shell 拼接。
6. 密码、session、keytab、TLS 私钥不得进入普通日志或 API response。
7. 所有会改变外部系统状态的操作必须走 Reconciler/Operation。
8. 变更共享/ACL/协议后必须有 Verify。
9. 资源更新必须使用 generation/ETag 防止静默覆盖。
10. 前端不得把管理 session token 放入 `localStorage`。
11. 文件 API 对普通用户只能接受 `share_id + rel_path`。
12. SMB/WebDAV/NFS 权限结果必须由同一套用例矩阵验证一致。
13. **当前版本的 `naosd` 不得监听 TCP/445。**
14. **不得自动 stop/kill 未识别或 unmanaged 的 445 listener。**
15. **不得覆盖用户已有 Samba/macOS/Windows SMB shares/config。**
16. SMB Apply 必须先完成 provider + port ownership preflight。
17. Linux/macOS Samba 只能写 naos-owned include/config scope。
18. Windows 只能修改 naos-owned share/account/ACL scope。
19. provider 无法安全管理时宁可返回 conflict/unsupported，也不进行破坏性自动修复。
20. 自研 SMB Deferred 文档不能被当成当前实现任务。

---

## 22. 风险与开放问题

| 风险/问题 | 影响 | 当前建议 |
| --- | --- | --- |
| **TCP/445 已被占用** | SMB 无法启动或错误接管用户服务 | provider-aware preflight；可识别同 provider 则复用，否则拒绝 |
| Linux 已有用户 Samba | 配置覆盖/服务中断 | attach 必须显式授权；只插入 naos include，不改其它 share |
| macOS File Sharing 与 Samba 冲突 | 两个 provider 无法同时绑定 445 | 优先检测/复用当前 provider；不自动关闭 File Sharing |
| Windows SMB 是系统服务 | 不适合替换 listener | 只通过系统 SMB API 管理 naos shares |
| system SMB 外部状态与 DB 漂移 | 权限/可用性异常 | generation + Verify + Doctor + 定时巡检 |
| provider 能力跨 OS/版本不同 | macOS/Linux/Windows 行为不一致 | capability model，不假设完全等价；UI 展示 unsupported/degraded |
| 文件系统不支持 ACL | 子目录权限失效 | 创建共享时拒绝或明确降级 |
| Windows/macOS 审计能力差异 | SMB 统一审计可能不完整 | Doctor 检测 audit capability，明确 degraded |
| 外部密码变更不可逆 | rollback 无法恢复旧 credential | forward-recovery + degraded + 重新 reset password |
| 自研 NFS 兼容性工作量 | 工期风险 | 仅 NFSv3；持续 fuzz/interop |
| NLM crash-recovery 仍依赖客户端 reclaim | daemon restart 会丢失进程内 held/waiting locks 与完整 NSM monitor/private-cookie | 已持久化 handle identity、NSM epoch 与有效 NLM peer IP，并在 restart 后主动 `SM_NOTIFY` + grace/reclaim；继续用分离主机 runner 验证真实 lockd/statd 自动 reclaim、异常掉线、通知失败重试与 grace 边界，不把单机 loopback 当作最终互操作证据 |
| NFS L1/L2 可被同网段伪造 | 越权 | 明示风险；敏感环境使用 VPN/隔离网/L3 |
| root/SYSTEM 运行 | 攻击面 | 特权逻辑集中、依赖最小、严格审计 |
| SQLite 高量审计增长 | 查询/空间 | 索引 + retention + 可选归档 |
| 多实例 | 锁/状态一致性 | v1 只支持单实例管理同一主机 |
| 前端 API schema 漂移 | 构建失败/运行错误 | OpenAPI codegen + CI diff gate |

### 22.1 暂定设计结论

- v1 不做多实例 HA。
- v1 不使用 WebSocket。
- v1 不做 server-side 文件内容预览。
- v1 不做 NFSv4。
- v1 不接 LDAP/AD。
- UI 与 API 同源为默认且推荐部署。
- OpenAPI 由后端生成，前端只消费。
- React 原型重构时优先保留现有交互与视觉语言。
- **当前版本不自研 SMB Server。**
- **`naosd` 不监听 445。**
- **SMB 依赖 platform system provider，并把 445 ownership 检测作为硬前置条件。**
- **不通过关闭用户已有 SMB 服务来解决冲突。**
- **自研 SMB P0 设计保留为 Deferred，未来通过新 ADR 决定是否重启。**
- 系统账号映射与文件系统 ACL 继续作为 SMB 权限落地基础。

---

## 23. Definition of Done

v0.5 当前设计落地的最低标准：

- `cargo build` 能构建后端，生产构建包含 Web SPA；
- OpenAPI 可稳定生成，前端类型全部由契约生成；
- 首次初始化、登录、Session、CSRF 完整；
- 用户/组/共享/ACL/NFS binding CRUD 可用；
- 共享和 ACL 写操作返回 Operation 并通过 SSE 展示进度；
- Apply 失败可回滚或明确进入 degraded；
- Dashboard/文件/共享/用户/模拟器/审计/设置/个人页均脱离 mock；
- Linux 可通过 Samba provider 创建并访问 naos share；
- Windows 可通过系统 SMB Server 创建并访问 naos share；
- macOS 能正确识别当前 SMB provider，且**不会因 naos 启动第二个 445 listener**；
- 445 被未知/第三方进程占用时，Apply 被安全拒绝并给出 Doctor 诊断；
- naos 不修改/删除 unmanaged SMB shares；
- Samba 配置 apply 前有 `testparm` 等验证且只修改 naos-owned scope；
- SMB FS ACL 与 desired ACL 的 Verify 能发现漂移；
- 三协议 ACL 一致性用例通过；
- Linux/macOS/Windows 至少完成安装、服务启动与核心 smoke test；
- 关键安全测试通过；
- 管理 API、协议操作、拒绝访问均有审计记录。

自研 SMB 不属于当前 Definition of Done。