# naos 设计文档

> 跨平台 NAS 管理面板：把任意文件夹通过 SMB / WebDAV / NFS 共享，带多用户与目录级权限。 版本 v0.2 · Draft · 技术栈 Rust

## 0. v0.2 变更

| # | 决策 | 影响 |
| --- | --- | --- |
| 1 | **自研 NFS 服务端**（用户态） | Windows 也能提供 NFS；认证/权限/审计完全可控 |
| 2 | macOS SMB 依赖 Homebrew Samba | 行为与 Linux 一致 |
| 3 | NFS 认证自研：客户端绑定 + uid 映射 + 可选 Kerberos | 见 §5 |
| 4 | **一次交付全部能力**：每用户系统账号映射 + 子目录 ACL + 按用户审计 | 取消 `force user` 方案 |
| 5 | 后端改 **Rust** | 见 §2 |

## 1. 目标与范围

| 项 | 内容 |
| --- | --- |
| 平台 | Linux / macOS / Windows |
| 协议 | SMB、WebDAV、NFS（仅此三种） |
| 能力 | 任意目录共享、多用户、用户组、**子目录级权限**、按用户审计 |
| 形态 | 单二进制守护进程 `naosd` + 内嵌 Web UI |
| 非目标 | RAID/磁盘管理、快照、备份、LDAP/AD、FTP/AFP/iSCSI、文件预览 |

原则：① SMB 委托系统原生服务，WebDAV/NFS 自研 ② 声明式（DB → 渲染 → diff → 应用 → 回滚）③ 只管理 naos 自己的配置块 ④ 默认安全（UI 仅监听 127.0.0.1）。

## 2. 架构与技术选型

```
Browser SPA ──HTTPS REST/SSE──┐
┌─────────────────────────────▼──────────────────────────┐
│ naosd (Rust, tokio, root/SYSTEM)                       │
│  api(axum) · auth · rbac · audit                       │
│  acl-engine   ← 唯一的权限计算实现                      │
│  reconciler   desired → render → diff → apply → rollback│
│  webdav-server (自研/封装)    nfs-server (自研 NFSv3)   │
│  smb-adapter ─ Samba(Linux/macOS) / SMB cmdlets(Win)   │
│  platform: 账号/ACL/服务管理                            │
│  store (SQLite)                                        │
└────────────────────────────────────────────────────────┘
```

| 模块 | 选型 |
| --- | --- |
| 运行时/Web | `tokio` + `axum` + `tower` |
| 存储 | `sqlx` (SQLite) + migrations |
| 密码 | `argon2` |
| WebDAV | `dav-server` crate（自定义 `DavFileSystem` 注入 ACL 检查） |
| NFS | 自研 ONC-RPC/XDR + NFSv3/MOUNT/NLM（可参考 `nfsserve`），v1 仅 NFSv3 |
| 前端 | SPA，`rust-embed` 打入二进制 |
| Windows 服务 | `windows-service` + `windows` crate |
| 外部命令 | `tokio::process::Command` 参数数组，禁止 shell 拼接 |

## 3. 协议后端矩阵

| 协议 | Linux | macOS | Windows |
| --- | --- | --- | --- |
| SMB | Samba，`/etc/samba/naos.conf` include | Homebrew Samba，同上 | `New-SmbShare` / `Grant-SmbShareAccess` |
| WebDAV | 内置 | 内置 | 内置 |
| NFS | **内置 naos-nfs** | 内置 | 内置 |

`naosd doctor` 探测依赖（Samba、brew、权限），UI 对缺失项给出安装指引。

```rust
trait ProtocolAdapter {
    fn detect(&self) -> Capability;
    fn render(&self, desired: &DesiredState) -> Result<Plan>;  // 不落地
    fn apply(&self, plan: Plan) -> Result<()>;                 // 失败自动回滚
    fn status(&self) -> Vec<ShareStatus>;
}
```

SMB 为外部服务适配器；WebDAV/NFS 为进程内服务，`apply` = 热更新内存路由表。

## 4. 身份与权限

### 4.1 每用户系统账号映射

naos 用户创建时同步创建系统账号，**文件归属真实用户**，SMB 不再使用 `force user`。

| 平台 | 创建账号 | SMB 凭据 |
| --- | --- | --- |
| Linux | `useradd -M -s /usr/sbin/nologin -G naos-users naos_<name>` | `smbpasswd -a` |
| macOS | `sysadminctl -addUser` / `dscl`（隐藏账号，无登录） | `smbpasswd -a`（Homebrew Samba） |
| Windows | `New-LocalUser`（拒绝交互登录） | 本地账号自带 |

约束：账号统一前缀 `naos_`，只管理带前缀账号；改密/禁用/删除同步；失败回滚。

### 4.2 子目录级 ACL

规则：`(share, rel_path, subject, perm, inherit)`，`perm ∈ none | ro | rw`。

**求值算法（acl-engine）**

1. 取目标路径从共享根到自身的所有规则，**越深越优先**（最近祖先覆盖上层）。
2. 同一层级：用户直授 + 所属组授权取 `max`，**显式 `none` 优先**。
3. 无任何匹配规则 → 拒绝。
4. 用户为 `admin` 不自动获得文件权限（只管理权限）。

**强制落地（两条路径，同一份规则）**

| 协议 | 执行方式 |
| --- | --- |
| SMB | ACL 同步到文件系统：Linux `setfacl`、macOS `chmod +a`、Windows `icacls`；Samba/SMB 以真实用户身份访问 |
| WebDAV / NFS | 进程内 `acl-engine` 每次操作检查；创建文件后 `chown`/设置所有者为实际用户 |

> 风险：两条路径可能漂移。对策：规则变更后重放同步 + 一致性测试（同一用例矩阵跑三协议，结果必须一致）+ 定时 `naosd verify` 巡检。

## 5. 自研 NFS 服务端

NFS 协议本身**不带口令认证**（AUTH_SYS 仅声明 uid/gid，可伪造）。naos 提供三级机制：

| 等级 | 机制 | 说明 | 平台 |
| --- | --- | --- | --- |
| L1 默认 | **客户端绑定**：`CIDR/IP → naos 用户` | 来自该地址的所有请求视为该用户 | 全平台 |
| L2 | **uid 映射**：`(CIDR, uid) → naos 用户` | 同一机器多用户；必须限定 CIDR | 全平台 |
| L3 可选 | **RPCSEC_GSS (krb5/krb5p)** | 真正的用户认证+加密，需 KDC | Linux/macOS（feature `nfs-krb5`，经 GSSAPI） |

- 未命中任何绑定 → 拒绝挂载（MOUNT 阶段）并记审计。
- 固定 `export` 路径 = 共享名，文件句柄 = 加密签名的 `(share_id, inode, gen)`，防句柄猜测。
- 范围：NFSv3（READ/WRITE/CREATE/MKDIR/RENAME/READDIRPLUS/…）+ MOUNT + NLM 简化锁；NFSv4 不在本期。
- **安全提示（UI 显式告知）**：L1/L2 仅适用于可信局域网/VPN，不适用于公网。

## 6. 数据模型

```sql
users(id, username UNIQUE, pw_hash, role, enabled, sys_account, sys_uid, created_at)
groups(id, name UNIQUE)
group_members(group_id, user_id)
shares(id, name UNIQUE, path, comment, enabled, smb_on, webdav_on, nfs_on, created_at)
share_acl(id, share_id, rel_path, subject_type, subject_id, perm, inherit)
nfs_bindings(id, share_id, cidr, uid NULL, user_id, perm)   -- uid 为空=L1，非空=L2
nfs_krb_principals(id, principal, user_id)                  -- L3
audit_log(id, ts, actor, protocol, action, share, path, client_ip, result, detail_json)
apply_history(id, ts, target, plan_json, status, rollback_blob)
settings(key, value)
```

## 7. 核心流程

**创建共享**：选目录 → 路径校验 → 入库 → 勾选协议与 ACL → Reconciler（渲染 → diff → 备份 → 应用 → 状态校验）→ 失败整体回滚。

| 路径校验 | 规则 |
| --- | --- |
| 存在且为目录 | `canonicalize` 后判断 |
| 黑名单 | `/` `/etc` `/proc` `/sys` `/dev` `/boot` `/System` `C:\Windows`、naos 数据目录 |
| 嵌套 | 同协议下共享路径不得互相包含（可配置放行） |
| ACL 落地可行 | 文件系统需支持 ACL（ext4/xfs/APFS/NTFS），否则提示或拒绝 |

**WebDAV**：`/dav/<share>/…`；Basic over TLS → 用户 → `acl-engine` 检查 → 路径 canonicalize 并限定在共享根内。

## 8. 审计

| 来源 | 实现 |
| --- | --- |
| WebDAV / NFS | 进程内记录，字段完整（用户、IP、路径、动作） |
| SMB (Linux/macOS) | Samba `vfs_full_audit` → 本地日志，naosd 解析入库 |
| SMB (Windows) | 对象访问审核 → 安全事件日志（4663），naosd 订阅；默认关闭，需启用审核策略 |

保留策略可配置（默认 90 天），支持 CSV 导出。

## 9. REST API（`/api/v1`）

| 资源 | 路径 |
| --- | --- |
| 认证 | `POST /auth/login` `/auth/logout` |
| 用户 | `/users` `/users/{id}` `POST /users/{id}/password` |
| 用户组 | `/groups` `/groups/{id}` `PUT /groups/{id}/members` |
| 共享 | `/shares` `/shares/{id}` |
| ACL | `GET/PUT /shares/{id}/acl`（含 rel_path）；`POST /shares/{id}/acl/simulate`（模拟有效权限） |
| NFS | `/shares/{id}/nfs-bindings` `/nfs/principals` |
| 目录浏览 | `GET /fs/browse?path=` |
| 协议 | `GET /protocols`；`POST /protocols/{p}/{start\|stop\|reload}` |
| 审计/系统 | `/audit` `/system/info` `/system/doctor` `POST /system/verify` |

约定：统一错误 `{code,message,detail}`；变更写审计；Apply 走 SSE 推送进度。

## 10. Web UI

| 页面 | 要点 |
| --- | --- |
| Dashboard | 协议状态、连接数、最近审计、doctor 告警 |
| 共享 | 新建向导；**目录树 + 权限矩阵**编辑子目录 ACL；访问地址一键复制 |
| 用户 / 用户组 | CRUD、重置密码、启停 |
| NFS | 客户端绑定、uid 映射、Kerberos 主体；安全等级提示 |
| 权限模拟器 | 选用户+路径 → 展示有效权限及命中规则 |
| 审计 / 设置 | 过滤导出；监听地址、TLS、会话、黑名单 |

## 11. 安全

| 威胁 | 对策 |
| --- | --- |
| 管理面暴露 | 默认 `127.0.0.1`；对外需显式配置 + 强制 TLS |
| 暴力破解 | argon2id、登录限速与锁定、首次强制设置管理员 |
| 会话/CSRF | HttpOnly + SameSite cookie + CSRF token |
| 路径穿越/符号链接 | `canonicalize` + 前缀校验；NFS 禁止跨出共享根；Samba `wide links = no` |
| 命令注入 | 参数数组调用；用户名/共享名白名单字符 |
| NFS 伪造身份 | 绑定 CIDR、句柄签名、审计；高要求场景启用 Kerberos |
| 提权面 | naosd 需 root/SYSTEM，最小依赖，不加载插件；特权操作集中在 `platform` 模块 |
| SMB 传输 | `server min protocol = SMB2`，可选签名/加密 |

## 12. 部署

| 平台 | 服务 | 包 |
| --- | --- | --- |
| Linux | systemd | deb / rpm / 静态二进制（musl） |
| macOS | launchd | pkg / Homebrew |
| Windows | Windows Service | MSI |

数据目录：Linux `/var/lib/naos`，macOS `/Library/Application Support/naos`，Windows `%ProgramData%\naos`。

## 13. 工程结构（Cargo workspace）

```
naos/
├─ crates/
│  ├─ naosd/          # 入口、服务装配
│  ├─ naos-api/       # axum 路由、认证、RBAC
│  ├─ naos-core/      # 模型、acl-engine、路径校验、reconciler
│  ├─ naos-store/     # sqlx + migrations
│  ├─ naos-platform/  # 账号/ACL/服务管理（cfg(target_os)）
│  ├─ naos-smb/       # Samba / Windows SMB adapter
│  ├─ naos-webdav/
│  ├─ naos-nfs/       # RPC/XDR、NFSv3、MOUNT、NLM、GSS(可选)
│  └─ naos-audit/
├─ web/               # 前端 SPA
└─ packaging/         # systemd / launchd / wix
```

## 14. 交付计划（一次发布，内部按序推进）

| 序 | 工作流 | 出口标准 |
| --- | --- | --- |
| 1 | core + store + api 骨架、acl-engine、路径校验 | ACL 求值单测全绿 |
| 2 | platform：三平台账号与 ACL 同步 | 账号/ACL 增删改幂等、可回滚 |
| 3 | SMB adapter（Linux → macOS → Windows） | 三平台真机读写/拒绝通过 |
| 4 | WebDAV | 一致性矩阵通过 |
| 5 | naos-nfs（L1/L2）→ krb5（L3，可选 feature） | Linux/macOS/Windows 客户端挂载读写 |
| 6 | 审计、UI、权限模拟器 | 三协议审计可检索 |
| 7 | 打包、E2E、安全测试 | CI 三平台矩阵全绿 |

## 15. 测试

| 类型 | 做法 |
| --- | --- |
| 单元 | acl-engine、路径校验、配置渲染（golden） |
| 一致性 | 同一 ACL 用例矩阵跑 SMB/WebDAV/NFS，结果必须一致 |
| 协议 | NFS：对照 Linux `nfs-utils` 客户端、macOS/Windows 客户端；`pynfs` 子集 |
| 集成 | Docker 起 Samba，`smbclient`/`curl`/`mount.nfs` 验证 |
| 安全 | 穿越、符号链接逃逸、句柄伪造、越权、模糊测试 RPC/XDR 解析 |

## 16. 风险与开放问题

| 风险 | 影响 | 对策 |
| --- | --- | --- |
| **自研 NFS 工作量与兼容性**（各系统客户端差异） | 最大工期风险 | 仅 NFSv3；先对 Linux 客户端，再 macOS/Windows；RPC/XDR 解析做 fuzz |
| NFS L1/L2 可被同网段伪造 | 越权 | 明确限定可信网络；L3 Kerberos 作为安全方案 |
| Windows 无 GSSAPI 路径 | L3 不可用 | L3 仅 Linux/macOS |
| 两条权限执行路径漂移 | 越权/误拒 | 一致性矩阵 + `verify` 巡检 |
| 文件系统不支持 ACL（FAT/exFAT） | 子目录 ACL 失效 | 校验阶段拒绝或降级为仅共享根 ACL |
| Windows SMB 审计依赖系统审核策略 | 审计缺失 | 默认关闭，UI 提示启用 |
| 以 root/SYSTEM 运行 | 攻击面大 | 特权集中、最小依赖、代码审计 |