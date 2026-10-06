# naos 设计文档

> 跨平台 NAS 管理面板：把任意文件夹通过 SMB / WebDAV / NFS 共享，带多用户、目录级权限与统一审计。  
> 版本 **v0.4 · Draft** · 后端 Rust · 前端 React/TypeScript

---

## 0. v0.4 变更摘要

v0.4 在 v0.3 的前后端实现规范基础上，正式加入 **内置 SMB2/SMB3 Server** 的长期架构路线。当前系统 SMB（Samba / Windows SMB）保留为迁移期 fallback，自研 SMB 先以同仓库独立 crates 和 standalone 测试程序推进，成熟后嵌入 `naosd`。

| # | 决策 | 影响 |
| --- | --- | --- |
| 1 | SMB 长期改为 **Rust 内置 SMB Server** | Linux / macOS / Windows 最终不再依赖 Samba 或 Windows SMB Server，真正满足单二进制数据面 |
| 2 | `naos-smb` **先不拆独立 Git 仓库** | 使用 monorepo + 独立 crate 边界，降低协议早期迭代与联调成本；稳定后可无痛拆仓 |
| 3 | SMB 拆为 `naos-smb-protocol` / `naos-smb-server` / `naos-smb-adapter` | wire protocol、server state machine、naos 业务集成三层隔离 |
| 4 | `naos-smb-protocol` / `naos-smb-server` 不依赖 `naos-core` | 协议实现保持可复用；只有 adapter 知道 naos 用户、ACL、审计和文件系统 |
| 5 | 自研 SMB 初始仅 Direct TCP/445，**禁止 SMB1** | 首先完成 SMB2.1 基线互操作，再补 SMB3.1.1、安全与高级能力 |
| 6 | SMB signing 为首期必须能力 | 兼容现代 Windows 默认安全策略；不能以关闭客户端签名作为正常使用前提 |
| 7 | NTLMv2 credential 与 Web 登录 Argon2 verifier 分离 | Argon2 hash 无法直接验证 NTLM challenge；需维护加密的 SMB password-equivalent material |
| 8 | 自研 SMB 直接调用 `acl-engine` 与统一文件后端 | 三协议共享权限语义，逐步消除“naos ACL ↔ 系统 SMB ACL”漂移 |
| 9 | 迁移期保留 `system` SMB 实现 | builtin 未成熟前不阻塞 naos；可按全局 `builtin/system` 切换并支持失败回滚 |
| 10 | 新增 standalone `naos-smbd` 开发工具 | 可在不启动完整 naos 的情况下做 Windows/macOS/Linux SMB 互操作和 fuzz 测试 |

v0.3 已确定的 React/OpenAPI/REST/SSE/Operation/分层架构继续有效；本版重点只改变 SMB 的长期实现方式与相关身份、权限、审计和交付路径。

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

### 2.1 目标运行时拓扑

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
│  ┌────────────── Control Plane ──────────────┐                                │
│  │ axum API                                  │                                │
│  │ auth/session · CSRF · RBAC                │                                │
│  │ application services                     │                                │
│  │ operation manager / SSE                  │                                │
│  │ reconciler                               │                                │
│  │ audit / doctor / verify                  │                                │
│  └──────────────────┬───────────────────────┘                                │
│                     │                                                        │
│             ┌───────▼────────┐                                               │
│             │ naos-core      │                                               │
│             │ domain models  │                                               │
│             │ acl-engine     │                                               │
│             │ validation     │                                               │
│             └───────┬────────┘                                               │
│                     │                                                        │
│       ┌─────────────┼───────────────────────────────────────────┐            │
│       ▼             ▼                         ▼                 ▼            │
│  naos-store    naos-platform          naos-smb-adapter    WebDAV / NFS       │
│  SQLite        user/fs/backend              │               servers           │
│                                             ▼                                 │
│                                      naos-smb-server                          │
│                                             │                                 │
│                                      TCP :445 (SMB2/3)                        │
└───────────────────────────────────────────────────────────────────────────────┘
                     │                         │                 │
                     ▼                         ▼                 ▼
              host filesystem             SMB clients      DAV/NFS clients
```

### 2.2 迁移期拓扑

自研 SMB 未达到生产准入标准前，`naosd` 仍支持系统 SMB fallback：

```text
                         SMB implementation (global)
                                  │
                       ┌──────────┴──────────┐
                       ▼                     ▼
                 builtin SMB            system SMB
              naos-smb-server      Samba / Windows SMB
                       │                     │
                       └──────────┬──────────┘
                                  ▼
                           host filesystem
```

同一时刻只能有一个实现监听 TCP/445。切换实现必须走 Operation：

```text
preflight
→ stop current implementation
→ bind/start target
→ verify negotiate + share visibility
→ success

failure
→ stop target
→ restore previous implementation
→ verify rollback
```

### 2.3 控制面与数据面

**控制面**包括 Web UI、REST API、用户/共享/ACL 管理、协议启停、系统诊断、审计查询和 Reconciler。控制面数据量小，但安全要求高。

**数据面**包括 SMB、WebDAV 和 NFS 的真实文件读写。数据面不得经过管理 API。

目标状态下三协议均在进程内或通过受控文件后端调用统一 `acl-engine`。其中：

- SMB：`naos-smb-server → naos-smb-adapter → acl-engine/FileBackend/AuditSink`；
- WebDAV：协议 handler → `acl-engine` → FileBackend；
- NFS：RPC handler → identity mapping → `acl-engine` → FileBackend；
- 系统 SMB fallback：仍依赖真实系统用户 + 文件系统 ACL 强制执行，并通过 Verify 检查与 naos ACL 的一致性。

### 2.4 技术选型

| 层 | 选型 | 说明 |
| --- | --- | --- |
| Rust runtime | `tokio` | 异步网络、进程管理、任务调度 |
| HTTP API | `axum` + `tower` | Router、middleware、限速、trace |
| 序列化 | `serde` / `serde_json` | API 与持久化 DTO |
| OpenAPI | `utoipa`（或等价方案） | Rust DTO/route 生成 API 契约 |
| DB | `sqlx` + SQLite | migrations、事务、离线可部署 |
| 密码 | `argon2id` | Web/UI、WebDAV Basic 等可直接校验明文密码的入口 |
| SMB credential | NTLM verifier material + AEAD at rest | 仅 SMB auth 使用，视作 password-equivalent secret |
| Session | 随机 opaque session + DB hash | 可注销、可撤销、可统一失效 |
| SMB | 自研 `naos-smb-protocol` + `naos-smb-server` | 目标内置；迁移期保留 Samba/Windows SMB fallback |
| WebDAV | `dav-server` | 注入 ACL 与真实用户身份 |
| NFS | 自研 ONC-RPC/XDR + NFSv3/MOUNT/NLM | v1 只做 NFSv3 |
| 前端 | React + TypeScript + Vite | SPA，静态产物嵌入 Rust |
| 前端请求 | TanStack Query | server state、缓存、失效、轮询 |
| 表单 | React Hook Form + Zod | UX 校验；后端仍为最终校验来源 |
| 路由 | React Router | 页面路由与权限门卫 |
| CSS | CSS Variables + CSS Modules | 复用现有原型 design tokens，不绑定大型 UI 框架 |
| 前端 API 类型 | OpenAPI 自动生成 | 禁止手写重复 DTO |
| 静态资源 | `rust-embed` | 单二进制部署 |
| 日志 | `tracing` + `tracing-subscriber` | request_id / operation_id / smb session 关联 |

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
- 当前选择的 SMB implementation 是否可用：builtin 检查 TCP/445、crypto/auth capability；system fallback 检查 Samba/PowerShell 依赖；
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
      "implementation": "builtin",
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
| GET | `/system/capabilities` | builtin SMB、system SMB fallback、ACL、Kerberos 等能力 |
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
│  ├─ naosd/                 # 进程入口、依赖装配、监听器、生命周期
│  ├─ naos-api/              # axum routes/handlers/middleware
│  ├─ naos-contract/         # API DTO、错误码、OpenAPI schema
│  ├─ naos-core/             # domain + application services
│  ├─ naos-store/            # sqlx repositories + migrations
│  ├─ naos-platform/         # 用户/FS ACL/安全文件操作/系统服务
│  │
│  ├─ naos-smb-protocol/     # SMB2/3 wire codec、常量、packet、crypto primitives
│  ├─ naos-smb-server/       # connection/session/tree/open/lease 状态机
│  ├─ naos-smb-adapter/      # naos identity/ACL/FileBackend/Audit ↔ SMB
│  │                         # + system SMB fallback（迁移期）
│  ├─ naos-webdav/           # WebDAV server + ACL integration
│  ├─ naos-nfs/              # ONC-RPC/XDR/NFSv3/MOUNT/NLM/GSS
│  └─ naos-audit/            # 审计归一化、retention
├─ tools/
│  └─ naos-smbd/             # standalone SMB interoperability 开发工具
├─ web/
├─ docs/
├─ packaging/
└─ xtask/
```

### 6.2 依赖方向

```text
naos-smb-protocol
       ▲
       │
naos-smb-server
       ▲
       │
naos-smb-adapter ─────► naos-core / naos-platform / naos-audit
       ▲
       │
     naosd

naosd
  ├── naos-api
  ├── naos-core
  ├── naos-store
  ├── naos-platform
  ├── naos-smb-adapter
  ├── naos-webdav
  ├── naos-nfs
  └── naos-audit

naos-api ───────► naos-contract
naos-api ───────► naos-core
naos-store ─────► naos-core
naos-platform ──► naos-core (只实现 trait，不把 OS 细节反灌 core)
WebDAV/NFS ─────► naos-core
```

核心规则：

- `naos-core` 不依赖 `axum`、`sqlx`、PowerShell/Samba。
- `naos-api` 不直接执行 SQL。
- `naos-api` 不直接调用 `Command`。
- `naos-store` 不包含 HTTP DTO。
- API DTO 与 domain entity 分离，转换显式实现。
- **`naos-smb-protocol` 不依赖任何 `naos-*` 业务 crate。**
- **`naos-smb-server` 不依赖 `naos-core`、`naos-store` 或 `naos-platform`。**
- 只有 `naos-smb-adapter` 可以把 SMB 请求映射为 naos identity、share、ACL、file operation 和 audit。
- `naos-smbd` 只能依赖通用 SMB crates + 测试 backend，不允许成为正式运行时依赖。

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

`ProtocolAdapter` 是**控制面生命周期接口**，不是数据面文件访问接口。

- builtin SMB：`apply` 更新内存 share registry / listener policy；通常不需要生成 Samba 配置。
- system SMB fallback：`apply` 渲染 Samba 配置或调用 Windows SMB cmdlets。
- WebDAV/NFS：`apply` 更新进程内路由/export/binding。
- SMB implementation 的切换属于 host 级 Operation，不能按单个 share 同时混用两个监听 TCP/445 的实现。

### 6.8 SMB 数据面 contracts

`naos-smb-server` 只依赖通用 callback/trait：

```rust
#[async_trait]
pub trait SmbFileSystem: Send + Sync {
    async fn open(&self, ctx: &SmbRequestContext, path: &SmbPath, opts: OpenOptions)
        -> SmbResult<FileHandle>;
    async fn read(&self, ctx: &SmbRequestContext, handle: &FileHandle, offset: u64, len: u32)
        -> SmbResult<Bytes>;
    async fn write(&self, ctx: &SmbRequestContext, handle: &FileHandle, offset: u64, data: Bytes)
        -> SmbResult<u32>;
    async fn query_directory(&self, ctx: &SmbRequestContext, handle: &FileHandle, query: DirQuery)
        -> SmbResult<Vec<DirEntry>>;
    async fn set_info(&self, ctx: &SmbRequestContext, handle: &FileHandle, info: SetInfo)
        -> SmbResult<()>;
    async fn close(&self, ctx: &SmbRequestContext, handle: FileHandle)
        -> SmbResult<()>;
}

#[async_trait]
pub trait SmbAuthProvider: Send + Sync {
    async fn begin(&self, request: AuthBegin) -> SmbResult<AuthChallenge>;
    async fn step(&self, request: AuthStep) -> SmbResult<AuthResult>;
}

pub trait SmbAuditSink: Send + Sync {
    fn emit(&self, event: SmbAuditEvent);
}
```

这些 trait 中不得出现：

- `sqlx` connection；
- naos DB entity；
- host absolute path；
- `AclEngine` concrete type；
- Samba / PowerShell 类型。

`naos-smb-adapter` 提供 `NaosSmbFs` / `NaosSmbAuth` / `NaosSmbAudit` 实现，在调用真实文件系统前执行 ACL 和 containment 检查。

### 6.9 Monorepo 与未来拆仓

v0.4 阶段 **不新建 `naos-smb` Git 仓库**。独立性由 crate 依赖边界保证。

只有满足以下至少一项时再考虑拆仓：

- SMB server 已稳定，可被 naos 之外的项目复用；
- 需要独立 crates.io release；
- SMB 有独立维护/发布周期；
- protocol/server API 已基本稳定，不再跟随 naos domain 高频变化。

未来拆仓只移动：

```text
naos-smb-protocol
naos-smb-server
```

`naos-smb-adapter` 永远留在 naos 仓库。

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
→ SMB desired state（builtin share registry / listener policy；fallback 为系统 SMB config）
→ WebDAV route
→ NFS export/binding
→ protocol reload/hot swap
→ verify
```

Rollback 必须按反序执行。

---

## 8. 身份与权限

### 8.1 用户模型

naos 用户仍同步创建真实系统账号，但 **builtin SMB 的认证不再依赖系统账号密码**。系统账号主要承担文件 ownership、宿主机 ACL、防御纵深和 system SMB fallback。

| 平台 | 系统账号 | builtin SMB 凭据 | system SMB fallback |
| --- | --- | --- | --- |
| Linux | `useradd -M -s /usr/sbin/nologin -G naos-users naos_<name>` | naos SMB credential store | `smbpasswd` |
| macOS | `sysadminctl` / `dscl` 隐藏账号 | naos SMB credential store | Homebrew Samba `smbpasswd` |
| Windows | 本地 `naos_<name>` 账号 + 拒绝交互登录 | naos SMB credential store | Windows 本地账号/SMB |

约束：

- `naos_` 前缀保留；
- 只管理 naos 自己创建并登记的系统账号；
- builtin SMB 登录成功后得到 `NaosUserId`，再映射到 `sys_account/sys_uid/SID` 用于 ownership；
- 删除用户前检查文件 ownership 影响；
- 密码不写日志、不进入 operation detail；
- 用户创建、本人改密、管理员重置密码必须同时刷新 Web verifier 与 SMB credential material；
- system SMB fallback 已安装/已配置时，即使当前运行 builtin，也应同步系统 SMB credential，尽量保持 fallback ready；
- 密码更新属于**部分不可逆外部操作**：一旦 Windows/Samba credential 已成功更新，不承诺自动恢复旧密码；后续步骤失败时优先 forward recovery，无法恢复则标记 degraded 并要求管理员重新执行密码重置；
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

目标状态：

| 协议 | Linux | macOS | Windows |
| --- | --- | --- | --- |
| SMB2/SMB3 | **内置 naos-smb** | **内置 naos-smb** | **内置 naos-smb** |
| WebDAV | 内置 | 内置 | 内置 |
| NFSv3 | 内置 | 内置 | 内置 |

迁移期 SMB fallback：

| 实现 | Linux | macOS | Windows |
| --- | --- | --- | --- |
| `system` | Samba | Homebrew Samba | Windows SMB cmdlets |
| `builtin` | naos-smb | naos-smb | naos-smb |

SMB implementation 是**主机级设置**，不允许 share A 用 builtin、share B 用 system 并同时争用 445 端口。

### 9.2 自研 SMB Server

#### 9.2.1 目标

自研 SMB 的目标不是完整复刻 Windows File Server，而是提供 naos NAS 场景所需的、安全且可验证的 SMB2/SMB3 文件服务：

```text
SMB client
   │
   ▼
naos-smb-protocol
   │ decode / encode / signing / crypto
   ▼
naos-smb-server
   │ connection / session / tree / open state
   ▼
naos-smb-adapter
   ├─ identity → naos user
   ├─ tree name → share_id
   ├─ acl-engine
   ├─ FileBackend
   └─ AuditSink
   │
   ▼
host filesystem
```

协议 crate 只实现 SMB 语义，不知道 SQLite、naos ACL、系统账号和实际共享绝对路径。

#### 9.2.2 路径边界

客户端路径：

```text
\\server\media\photos\2026\a.jpg
```

在 SMB 层只表达为：

```text
tree = "media"
relative_path = "/photos/2026/a.jpg"
```

禁止 `naos-smb-server` 构造：

```text
/data/media/photos/2026/a.jpg
D:\Media\photos\2026\a.jpg
```

绝对路径映射只能由 `naos-smb-adapter/FileBackend` 完成，并执行 runtime containment、symlink/reparse-point 防逃逸检查。

Share name 在 SMB namespace 中按 case-insensitive 规则保证唯一；创建共享时必须拒绝仅大小写不同的重名。

#### 9.2.3 规范基线

实现以 Microsoft Open Specifications 为协议权威来源：

- `[MS-SMB2]`：SMB Protocol Versions 2 and 3；
- `[MS-SPNG]`：SPNEGO；
- `[MS-NLMP]`：NTLM；
- 后续 Kerberos 对接参考 `[MS-KILE]`。

v0.4 设计时的 `[MS-SMB2]` published revision 为 **88.0（2026-09-28）**。实际开始协议开发时，在 `docs/protocol/smb-spec-baseline.md` 固定使用的 revision，后续升级规范必须经过兼容性回归。

参考入口：

```text
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/
```

#### 9.2.4 Dialect 与功能分阶段

> P0 的 packet framing、状态机、NEGOTIATE/SESSION_SETUP/TREE_CONNECT/CREATE、FileBackend、share-mode、LOCK、credit、NTSTATUS、fuzz 与编码顺序详见 [naos SMB P0 实现设计](naos%20SMB%20P0%20%E5%AE%9E%E7%8E%B0%E8%AE%BE%E8%AE%A1.md)。本节只保留产品级能力边界。

**明确禁止 SMB1。**

P0 — standalone 可读写：

| 能力 | 要求 |
| --- | --- |
| Transport | Direct TCP，默认 445；开发工具允许非特权端口 |
| Dialect | SMB 2.1 baseline |
| Signing | **必须支持** HMAC-SHA256 signing；客户端要求签名时可正常连接 |
| Auth | SPNEGO + NTLMv2，本地 naos 用户 |
| Commands | NEGOTIATE、SESSION_SETUP、LOGOFF、TREE_CONNECT、TREE_DISCONNECT、CREATE、CLOSE、FLUSH、READ、WRITE、QUERY_DIRECTORY、QUERY_INFO、SET_INFO、LOCK、CANCEL、ECHO |
| Compound | 支持常见 related compound request，不能假设一 TCP frame 只有一个命令 |
| Credits | 正确处理基础 credit accounting，设置明确上限 |
| 文件语义 | create/open/disposition、rename/delete、目录枚举、EOF/basic info |
| Guest | 默认不支持 |

P1 — builtin experimental：

| 能力 | 要求 |
| --- | --- |
| Dialect | SMB 3.1.1 |
| Negotiate contexts | pre-auth integrity、signing/cipher capability negotiation |
| Signing | AES-CMAC / AES-GMAC 按 dialect/capability 协商 |
| Encryption | 至少 AES-128-GCM；可配置 share/server require encryption |
| Oplock/Lease | 先做保守语义，以正确性优先于客户端缓存性能 |
| Lock | P0 已有基础 byte-range lock；P1 补等待/异步与更完整客户端兼容语义 |
| Change Notify | 满足 Explorer/Finder 常用目录刷新场景 |
| IOCTL | 只实现客户端互操作必需子集，其余显式 `STATUS_NOT_SUPPORTED` |

P2 — production hardening：

- Kerberos/GSSAPI；
- durable handle v2；
- reconnect / network interruption recovery；
- 更完整 lease/oplock break；
- large MTU / 多 credit 性能；
- cancellation / async command 压测；
- metadata/xattr/ACL 映射细化；
- Windows/macOS/Linux 大文件和并发压力测试。

首期明确**不做**：

- SMB1；
- SMB over QUIC；
- SMB Direct / RDMA；
- SMB Multichannel；
- DFS namespace；
- clustered/persistent handles；
- printer sharing；
- 通用 named pipe server；
- AD Domain Controller 能力。

任何未实现 capability 都不得在 NEGOTIATE 中宣称支持。

#### 9.2.5 Signing 与 Encryption

signing 是 P0，而不是可选“增强项”。原因：

- 现代 Windows 可以默认要求 SMB signing；
- 如果客户端要求 signing，服务端必须能够正确签名和校验；
- 不允许把“让用户关闭 Windows signing”作为正常兼容方案。

配置建议：

```toml
[smb.security]
signing = "required"       # required | enabled
encryption = "enabled"     # disabled | enabled | required
```

在只支持 SMB2.1 的阶段，`encryption` 必须报告 unavailable；不能静默接受配置。

进入 SMB3.1.1 后再开放 encryption。加密后的消息不重复依赖普通 message signing 语义，具体按 negotiated dialect/spec 执行。

#### 9.2.6 NTLMv2 与 credential storage

现有：

```text
password → Argon2id → pw_hash
```

只能用于“服务端拿到明文密码再验证”的认证入口，**不能从 Argon2 hash 反推出 NTLMv2 challenge 所需 key material**。

因此 builtin SMB 需要单独保存 SMB credential material：

```text
user sets password
        │
        ├─ Argon2id ─────────────► users.pw_hash
        │
        └─ NTLM key derivation ──► encrypt(AEAD, machine_master_key)
                                   └► smb_credentials
```

安全要求：

- SMB credential material 视为 **password-equivalent secret**；
- DB 中只能存 AEAD ciphertext，不存明文 NT hash；
- API 永远不返回；
- 日志、panic、trace、operation detail 永远不打印；
- 解密只发生在 SMB authentication 所需的最短生命周期内；
- machine master key 不与 SQLite 放在同一明文安全边界；
- Linux 默认 root-only `0600` secret file，可后续接 systemd credentials；
- macOS 优先 Keychain/受限系统存储；
- Windows 优先 DPAPI machine scope；
- key 带 `key_version`，支持轮换；
- 关闭 builtin SMB 后仍可保留密文，删除用户时必须删除。

用户创建/密码更新流程：

```text
validate password
→ derive Argon2 hash
→ derive SMB credential material
→ encrypt SMB material
→ persist/update naos verifiers
→ if system fallback provider is configured: sync system SMB credential
→ verify every configured credential provider
→ success | degraded(forward recovery required)
```

不能出现“UI 密码更新成功，但某个已配置 SMB provider 仍使用旧密码”的静默部分成功。

密码变更与普通 share/ACL Apply 不同：系统账号密码通常无法在没有旧明文密码的情况下安全回滚。因此该 Operation 使用 **forward-recovery** 语义：

- 若外部 credential 尚未改变，失败可回退 DB verifier；
- 若任一外部 credential 已成功改变，后续失败不得伪装成完整 rollback；
- operation 标记 `degraded`，UI 明确要求重新提交同一新密码或执行一次新的密码重置；
- plaintext password 只在当前 Operation 内存生命周期存在，完成后 zeroize，不为自动恢复而落盘保存。

默认不支持 guest/anonymous SMB。

#### 9.2.7 SMB 状态模型

`naos-smb-server` 自己维护协议状态：

```text
Server
└─ Connection
   ├─ negotiated dialect/capabilities
   ├─ credits
   └─ Sessions
      └─ Session
         ├─ authenticated identity
         ├─ signing/encryption keys
         └─ Trees
            └─ Tree
               ├─ share_id (opaque to protocol core)
               └─ Opens
                  └─ Open/FileHandle
```

约束：

- client-supplied ID 永不直接作为数组索引或裸指针；
- SessionId / TreeId / FileId 使用不可预测或受状态表验证的标识；
- 所有 table 设置硬上限与 idle timeout，防止内存 DoS；
- connection 关闭时清理 session/channel/open 引用；
- open handle 由 server 分配，不能编码宿主机绝对路径；
- parser 对长度/offset/compound next-command 做 checked arithmetic。

#### 9.2.8 ACL、文件 ownership 与审计

builtin SMB 请求流程：

```text
SMB CREATE/READ/WRITE/SET_INFO
        │
        ▼
authenticated SmbIdentity
        │
        ▼
tree → share_id
relative SMB path
        │
        ▼
naos-smb-adapter
        │
        ├─ acl-engine.check(...)
        ├─ FileBackend operation
        ├─ ownership/sys-account mapping
        └─ AuditSink.emit(...)
```

ACL 拒绝必须在实际文件 IO 之前发生。

builtin SMB 下文件系统 ACL 仍保留，作用变为：

1. 防御纵深；
2. 保证宿主机本地访问的 ownership/ACL 语义；
3. 保持 system SMB fallback 随时可切回；
4. 与 WebDAV/NFS 创建文件保持 owner 一致。

因此 v0.4 **不删除系统账号映射和 FS ACL 同步**，但 SMB 的最终授权不再依赖系统 SMB 自己解释规则。

builtin SMB 审计直接写统一 `AuditSink`，不再需要解析 Samba/Event Log；fallback 模式继续使用旧审计采集路径。

#### 9.2.9 system fallback

迁移期实现：

Linux/macOS：

- naos 维护 Samba 独立 include；
- `testparm` 成功才 reload；
- `wide links = no`；
- 文件系统 ACL 强制权限；
- `vfs_full_audit` 采集审计。

Windows：

- PowerShell cmdlet 使用结构化参数；
- share ACL + NTFS ACL；
- Event Log 获取 SMB 审计。

配置：

```toml
[smb]
implementation = "system" # system | builtin
listen = "0.0.0.0:445"
```

切换到 `system` 前必须 preflight：

- 系统 SMB provider 已安装且可启动；
- enabled users 的 system SMB credential 已 provision；
- 文件系统 ACL 已通过 Verify；
- TCP/445 可被目标 provider 获取。

若某些用户在 builtin-only 环境创建/改密，而系统 provider 当时未安装，naos **不能从 Argon2 hash 或 NT hash 安全还原 Windows/Samba 所需的用户明文密码**。此时 `system` 切换必须被阻止，并要求管理员对受影响用户执行 credential reprovision/password reset；不得偷偷保存用户明文密码来换取 fallback。

在 builtin 达到 production gate 前，release 默认值保持 `system`；达到 gate 后新安装默认改为 `builtin`，升级安装不自动切换，必须由管理员显式确认。

#### 9.2.10 standalone `naos-smbd`

开发工具：

```text
tools/naos-smbd
   │
   ├─ StaticAuthProvider / test credential store
   ├─ LocalFsBackend
   ├─ ConsoleAuditSink
   └─ naos-smb-server
```

示例：

```bash
cargo run -p naos-smbd -- \
  --listen 127.0.0.1:1445 \
  --root ./target/smb-fixture \
  --user alice
```

用途：

- Wireshark 抓包；
- Windows/macOS/Linux client 联调；
- protocol regression；
- fuzz corpus 生成；
- 不启动 SQLite/REST/UI 即可开发 SMB。

`naos-smbd` **不是正式部署组件**，发布包默认不安装。

#### 9.2.11 builtin 切换准入标准

builtin SMB 成为默认实现前必须满足：

- Windows 11 当前版本：认证、签名、Explorer copy/rename/delete、share-mode 与 Office 常见文件锁场景；
- macOS 当前版本：Finder mount/copy/rename/delete；
- Linux kernel cifs：mount/read/write/rename；
- 1 B、空文件、4 KiB、1 MiB、1 GiB+ 文件；
- Unicode、空格、长文件名、深目录；
- 断连/reconnect 不造成已确认写入的数据损坏；
- 并发 open/write/rename/delete 行为可解释且有测试；
- signing required 客户端可连接；
- malformed packet/fuzz 无 panic、OOM、越界；
- ACL consistency matrix 与 WebDAV/NFS 一致；
- soak test 24h 无 handle/session 泄漏；
- fallback 切换与 rollback 测试通过。

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

// SMB NTLM verifier material。该字段为 password-equivalent secret，永不通过 API 返回。
smb_credentials(
  user_id TEXT PRIMARY KEY,
  nt_hash_ciphertext BLOB NOT NULL,
  nonce BLOB NOT NULL,
  key_version INTEGER NOT NULL,
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
| SMB builtin | `naos-smb-adapter → AuditSink`，直接产生结构化事件 |
| SMB system Linux/macOS | Samba `vfs_full_audit` 解析 |
| SMB system Windows | Event Log 订阅 |

builtin SMB 审计额外关联：

```text
connection_id
session_id
tree_id/share_id
open_id (如适用)
dialect
signed/encrypted
```

这些 ID 只用于关联，不记录 signing/encryption key 或 NTLM secret。

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
| 暴力破解 | IP + username 双维度限速；指数退避/短期锁定 |
| 密码泄露 | Argon2id；日志 redaction；API 永不回传 |
| 路径穿越 | canonicalize + containment + handle-relative IO |
| Symlink/Junction 逃逸 | runtime 校验 + 平台安全 API |
| 命令注入 | `Command::args`，绝不使用 shell 拼接 |
| 配置覆盖用户文件 | naos 只维护自己的 include/config block |
| NFS AUTH_SYS 伪造 | L1/L2 仅可信网络；敏感环境使用 L3 |
| SMB parser / state machine 漏洞 | checked parsing、资源上限、fuzz、协议状态约束、无 unsafe 为默认 |
| SMB downgrade/中间人 | 禁 SMB1；signing P0；SMB3.1.1 pre-auth integrity；不宣称未实现 capability |
| NTLM verifier 泄露 | password-equivalent secret 单独 AEAD 加密；master key 分离；永不 API/log 输出 |
| SMB session/handle DoS | connection/session/tree/open/credit 上限 + idle timeout + backpressure |
| 异步状态漂移 | generation/applied_generation + verify |
| 管理员并发覆盖 | ETag / If-Match |
| 双击创建 | Idempotency-Key |
| Secret 输出 | 结构化 redaction + SecretString |
| root/SYSTEM 攻击面 | platform 模块集中、依赖最小化、无第三方插件加载 |

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
implementation = "system" # migration: system | builtin
listen = "0.0.0.0:445"
workgroup = "WORKGROUP"

[smb.security]
signing = "required"
encryption = "enabled" # SMB3.1.1 可用后生效

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

### 18.5 SMB

分四层：

**codec / parser unit**

- 每个 request/response structure round-trip；
- offset/length/align；
- compound `NextCommand`；
- malformed/truncated/oversized packet；
- crypto test vector；
- SMB2 header flags/status mapping。

**state machine**

- negotiate → session setup → tree connect → create/read/write/close；
- invalid SessionId/TreeId/FileId；
- credit exhaustion/replenish；
- duplicate/replayed request；
- connection close cleanup；
- timeout/resource limit。

**interoperability**

- Windows 11；
- macOS Finder；
- Linux kernel cifs；
- signing required；
- Unicode/long filename；
- 1 GiB+ streaming；
- rename/delete while handles are open；
- common Office temporary-file/lock behavior。

**fuzz**

- packet parser；
- negotiate contexts；
- security blob/SPNEGO envelope；
- CREATE contexts；
- QUERY/SET_INFO；
- compound messages；
- encryption transform header（支持后）。

所有网络 parser fuzz target 必须满足：

```text
no panic
no OOM from attacker-controlled allocation
no integer overflow
bounded CPU per bounded input
```

### 18.6 NFS

- Linux `nfs-utils`；
- macOS client；
- Windows NFS client；
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
- SMB unsigned request when signing required；
- SMB invalid signature；
- SMB invalid encrypted transform；
- SMB auth replay / malformed NTLM；
- SMB connection/session/open exhaustion；
- SMB share/path case collision。

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
├─ SMB builtin interoperability smoke
├─ SMB system fallback integration
└─ WebDAV/NFS protocol smoke tests

package
├─ linux
├─ macOS
└─ Windows
```

对 NFS root/privileged 测试使用专门 runner 或能力受控的集成环境，不能假设普通 GitHub hosted runner 可完成全部 mount 场景。

---

## 20. 交付计划

SMB 自研不与 naos 主线“绑死”：system fallback 始终提供可运行出口，builtin 按 gate 逐步晋级。

| 阶段 | 工作流 | 出口标准 |
| --- | --- | --- |
| 1 | workspace + contract + store + api 骨架 | OpenAPI 生成、migration、health 可用 |
| 2 | auth/session/CSRF/RBAC | 登录、注销、会话撤销、安全测试通过 |
| 3 | core + ACL + path validation + FileBackend | ACL/path 单测矩阵全绿，协议可共享文件后端 |
| 4 | platform 三平台账号/FS ACL | 增删改幂等、rollback 可验证 |
| 5 | operations + reconciler | SSE、generation、rollback、degraded 状态完整 |
| 6 | **SMB system fallback** | Samba/Windows SMB 三平台真机读写/拒绝通过，保证主线可用 |
| 7 | **naos-smb P0 standalone** | SMB2.1 + NTLMv2 + signing；Windows/macOS/Linux 基础 copy/rename/delete |
| 8 | **naos-smb adapter integration** | builtin SMB 直接接 identity/ACL/FileBackend/Audit；不依赖系统 SMB |
| 9 | **naos-smb P1 / SMB3.1.1** | pre-auth、现代 signing、encryption、lock/lease/change notify 基线通过 |
| 10 | builtin SMB experimental | UI 可显式切 builtin/system；失败自动 rollback；system 仍默认 |
| 11 | WebDAV | ACL 一致性矩阵通过 |
| 12 | NFS L1/L2 | 三系统客户端 mount/read/write |
| 13 | NFS L3（feature） | Linux/macOS krb5 测试通过 |
| 14 | React Web UI | 原型核心页面全部 API 化，不再依赖 mock |
| 15 | 审计/Doctor/Verify | 可检索、可导出、漂移可发现 |
| 16 | builtin SMB production gate | §9.2.11 全部通过，安全 fuzz/soak/interop 达标 |
| 17 | 打包/E2E/安全测试 | 三平台可安装、升级、卸载 |
| 18 | builtin SMB 默认化 | 新安装默认 builtin；升级用户显式迁移；system 继续作为 fallback |

---

## 21. 关键实现约束

实现过程中以下规则视为架构红线：

1. React 组件内不得复制 ACL 求值逻辑。
2. API handler 不得直接调用 SQL 或系统命令。
3. `naos-core` 不得依赖 `axum`/`sqlx`/PowerShell/Samba。
4. 所有宿主机文件路径在信任前必须 canonicalize/containment 检查。
5. 外部命令不得通过 shell 拼接。
6. 密码、session、SMB credential、keytab、TLS 私钥不得进入普通日志或 API response。
7. 所有会改变外部系统状态的操作必须走 Reconciler/Operation。
8. 变更共享/ACL/协议后必须有 Verify。
9. 资源更新必须使用 generation/ETag 防止静默覆盖。
10. 前端不得把管理 session token 放入 `localStorage`。
11. 文件 API 对普通用户只能接受 `share_id + rel_path`，不得接受任意绝对路径。
12. SMB/WebDAV/NFS 权限结果必须由同一套用例矩阵验证一致。
13. **`naos-smb-protocol` / `naos-smb-server` 不得依赖 `naos-core`、DB 或 host absolute path。**
14. **SMB protocol core 不得自行实现一套 naos ACL。**
15. **SMB1 永不启用。**
16. **未实现的 SMB capability 不得在 NEGOTIATE 中 advertise。**
17. **不得要求用户关闭 SMB signing 来换取兼容。**
18. **NTLM verifier material 按 password-equivalent secret 处理。**
19. attacker-controlled SMB length/count 不得直接决定无上限 allocation。
20. system/builtin SMB 切换必须可 rollback，且同一时刻只能有一个实现占用 445。

---

## 22. 风险与开放问题

| 风险/问题 | 影响 | 当前建议 |
| --- | --- | --- |
| **自研 SMB 兼容性与数据正确性** | 新的最大工程风险；错误可能导致文件损坏 | 分 P0/P1/P2；system fallback 不移除；interop + fuzz + soak 作为 production gate |
| SMB NTLM credential 是 password-equivalent secret | DB/主机泄露风险增加 | 独立 AEAD 加密、master key 分离、严格 redaction、后续优先 Kerberos |
| SMB lock/lease/oplock 语义复杂 | Office/Finder/Explorer 兼容与缓存一致性 | 首先保守实现；正确性优先；高级缓存能力不提前 advertise |
| SMB 大小写/Unicode 文件名语义 | Linux/macOS/Windows 行为不一致 | 建立专门 compatibility matrix；share 名 case-insensitive unique；目录查找策略在 P0 interop 后固化 |
| SMB system → builtin 迁移 | 连接中断/行为变化 | host-level Operation、preflight、显式确认、自动 rollback；升级不自动切 |
| 自研 NFS 兼容性工作量 | 工期风险 | 仅 NFSv3；先 Linux，再 macOS/Windows；持续 fuzz |
| NFS L1/L2 可被同网段伪造 | 越权 | 明示风险；敏感环境使用 VPN/隔离网/L3 |
| Windows L3 GSS 路径复杂 | L3 跨平台不一致 | v1 L3 仅 Linux/macOS |
| system SMB 外部状态与 DB 漂移 | 权限/可用性异常 | generation + verify + 定时巡检；builtin 默认化后显著降低 |
| 文件系统不支持 ACL | 子目录权限防御纵深下降 | 创建共享时拒绝或明确降级；builtin 仍必须执行 acl-engine |
| Windows system SMB 审计依赖策略 | fallback 审计不完整 | Doctor 检测；builtin SMB 使用直接 AuditSink |
| root/SYSTEM 运行 | 攻击面 | 特权逻辑集中、依赖最小、严格审计；网络 parser 尽量无 unsafe |
| SQLite 高量审计增长 | 查询/空间 | 索引 + retention + 可选归档 |
| 多实例 | 锁/状态一致性 | v1 明确只支持单实例管理同一主机 |
| 前端 API schema 漂移 | 构建失败/运行错误 | OpenAPI codegen + CI diff gate |

### 22.1 暂定设计结论

- v1 不做多实例 HA。
- v1 不使用 WebSocket。
- v1 不做 server-side 文件内容预览。
- v1 不做 NFSv4。
- v1 不接 LDAP/AD。
- UI 与 API 同源为默认且推荐部署。
- OpenAPI 由后端生成，前端只消费。
- React 原型重构时优先保留现有交互与视觉语言，不引入大型企业 UI 框架重做视觉。
- **长期 SMB 默认实现为 builtin `naos-smb`。**
- **短中期保留 system SMB，直到 builtin 通过明确 production gate。**
- **`naos-smb` 当前保留在 monorepo，不提前拆仓。**
- **先保证 SMB2.1 + signing + NTLMv2 的正确互操作，再扩 SMB3.1.1；不一次性追求完整 SMB3 feature set。**
- **系统账号映射与文件系统 ACL 暂不删除：builtin SMB 使用其作为 ownership 与防御纵深，fallback 仍依赖它们。**
- **Kerberos 是 SMB 长期首选认证方向，但不阻塞 P0 NTLMv2 本地用户场景。**

---

## 23. Definition of Done

v0.4 设计落地完成的最低标准：

- `cargo build` 能构建后端，生产构建包含 Web SPA；
- OpenAPI 可稳定生成，前端类型全部由契约生成；
- 首次初始化、登录、Session、CSRF 完整；
- 用户/组/共享/ACL/NFS binding 的 CRUD 可用；
- 共享和 ACL 写操作返回 Operation 并通过 SSE 展示进度；
- Apply 失败可回滚，失败后状态可诊断；
- Dashboard/文件/共享/用户/模拟器/审计/设置/个人页均脱离 mock；
- system SMB fallback 在 Linux/macOS/Windows 可用；
- `naos-smbd` 可独立启动并通过 Windows/macOS/Linux 基础互操作；
- builtin SMB 至少完成 SMB2.1、SPNEGO/NTLMv2、signing、核心文件命令；
- builtin SMB 的请求直接经过统一 `acl-engine`、FileBackend 与 AuditSink；
- SMB credential material 加密存储且无 API/log 泄露路径；
- builtin/system 切换有 preflight、verify、rollback；
- 三协议 ACL 一致性用例通过；
- Linux/macOS/Windows 至少完成安装、服务启动与核心 smoke test；
- SMB/NFS 网络 parser 的关键 fuzz target 通过；
- 关键安全测试通过；
- 管理 API、协议操作、拒绝访问均有审计记录。

### 23.1 builtin SMB 成为默认实现的额外 gate

以下条件未全部满足前，正式 release 不把 builtin SMB 设为默认：

- §9.2.11 客户端互操作矩阵通过；
- signing-required Windows 客户端无需降低安全策略即可连接；
- SMB3.1.1 若被 advertise，则 pre-auth/signing/encryption 对应测试全部通过；
- 24h soak 无持续增长的 connection/session/tree/open handle；
- 并发/断连场景未发现已确认写入的数据损坏；
- fuzz/sanitizer/资源耗尽测试不存在 blocker；
- system → builtin → system rollback 演练通过；
- 有至少一个 release cycle 的 opt-in experimental 使用反馈。