# naos

> 跨平台 NAS 管理面板：把任意文件夹通过 SMB / WebDAV / NFS 共享，带多用户与目录级权限。

## 🎯 目标与特性

- **跨平台支持**：Linux / macOS / Windows 统一管理
- **三协议聚合**：SMB、WebDAV、NFS（NFSv3 自研用户态服务，Windows 亦可提供 NFS）
- **多用户与系统账号映射**：创建 naos 用户时同步创建底层 `naos_*` 本地账号，文件归属真实用户，杜绝 `force user` 方案
- **子目录级 ACL 权限**：继承与显式拒绝结合，越深越优先，就近生效
- **统一安全审计**：三协议数据访问日志集中采集与检索
- **单二进制管理面**：单二进制守护进程 `naosd` + 内嵌 Web 控制台；SMB 数据面复用平台系统 SMB 服务，避免抢占 TCP/445

## 📚 文档与原型

- **系统设计文档**：[docs/naos 设计文档.md](docs/naos%20设计文档.md)
- **自研 SMB P0 候选方案（Deferred）**：[docs/naos SMB P0 实现设计.md](docs/naos%20SMB%20P0%20%E5%AE%9E%E7%8E%B0%E8%AE%BE%E8%AE%A1.md)
- **管理页面原型**：[docs/naos 管理页面原型.html](docs/naos%20管理页面原型.html)（可直接在浏览器中双击打开预览体验）

## 🏗️ 架构与技术选型

- **运行时 / Web API**：Rust (`tokio` + `axum` + `tower`)
- **存储**：`sqlx` (SQLite)
- **密码哈希**：`argon2`
- **WebDAV 服务**：基于 `dav-server` crate 注入 `acl-engine`
- **NFS 服务**：自研 ONC-RPC/XDR + NFSv3/MOUNT/NLM（带 L1 客户端 CIDR 绑定 / L2 UID 映射 / L3 Kerberos）
- **SMB 适配**：现阶段不自研 SMB Server；Linux 复用 Samba，Windows 复用系统 SMB Server，macOS 优先复用可管理的系统 SMB provider；启动/Apply 前检测 TCP/445 归属并拒绝未知冲突


## 🔐 NFS Kerberos（可选）

Linux / macOS 使用 `system-gss` feature 将 NFS RPCSEC_GSS 接到系统 Kerberos/GSS：

```bash
cargo build -p naosd --features system-gss
NAOS_NFS_ENABLED=true \
NAOS_NFS_KERBEROS_SERVICE_PRINCIPAL='nfs/server.example.com@EXAMPLE.COM' \
./target/debug/naosd
```

Windows 使用 `windows-sspi` feature，直接调用原生 Kerberos SSPI package，不经过 `Negotiate`，因此不会回退到 NTLM：

```powershell
cargo build -p naosd --features windows-sspi
$env:NAOS_NFS_ENABLED = "true"
$env:NAOS_NFS_KERBEROS_SERVICE_PRINCIPAL = "nfs/server.example.com@EXAMPLE.COM"
.\target\debug\naosd.exe
```

Unix 的 service principal 必须能从系统 GSS acceptor 的凭据来源取得对应密钥；MIT/Heimdal 环境可在启动 `naosd` 前通过 `KRB5_KTNAME` 指定 keytab。Windows SSPI 使用 naosd 进程当前安全上下文可用的入站 Kerberos credentials，并在 context 完成后校验 SSPI 返回的 server principal 与配置值一致。任一平台无法取得 Kerberos acceptor credential 时，NFS 数据面拒绝启动，不降级到弱认证。

Unix system GSS provider 已支持 `krb5` / `krb5i` / `krb5p`；privacy 只有在协商 `GSS_C_CONF_FLAG` 且 RFC 4121 Wrap token 设置 `Sealed` 时才接受。Windows SSPI 第一阶段支持 Kerberos context establishment、principal 与 MIC（`krb5` / `krb5i`），`krb5p` 暂时 fail-closed，待域环境下完成 EncryptMessage/DecryptMessage wire 互操作验证后启用。Linux CI 使用临时 MIT Kerberos realm/keytab 跑真实 MOUNT → NFS `krb5i` / `krb5p` TCP smoke；Windows hosted CI 目前覆盖 SSPI feature 的编译、lint 与单测，真实 AD/Kerberos 客户端互操作留给 domain-joined self-hosted gate。
