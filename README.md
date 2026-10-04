# naos

> 跨平台 NAS 管理面板：把任意文件夹通过 SMB / WebDAV / NFS 共享，带多用户与目录级权限。

## 🎯 目标与特性

- **跨平台支持**：Linux / macOS / Windows 统一管理
- **三协议聚合**：SMB、WebDAV、NFS（NFSv3 自研用户态服务，Windows 亦可提供 NFS）
- **多用户与系统账号映射**：创建 naos 用户时同步创建底层 `naos_*` 本地账号，文件归属真实用户，杜绝 `force user` 方案
- **子目录级 ACL 权限**：继承与显式拒绝结合，越深越优先，就近生效
- **统一安全审计**：三协议数据访问日志集中采集与检索
- **单二进制部署**：单二进制守护进程 `naosd` + 内嵌 Web 控制台，极简运维

## 📚 文档与原型

- **系统设计文档**：[docs/naos 设计文档.md](docs/naos%20设计文档.md)
- **管理页面原型**：[docs/naos 管理页面原型.html](docs/naos%20管理页面原型.html)（可直接在浏览器中双击打开预览体验）

## 🏗️ 架构与技术选型

- **运行时 / Web API**：Rust (`tokio` + `axum` + `tower`)
- **存储**：`sqlx` (SQLite)
- **密码哈希**：`argon2`
- **WebDAV 服务**：基于 `dav-server` crate 注入 `acl-engine`
- **NFS 服务**：自研 ONC-RPC/XDR + NFSv3/MOUNT/NLM（带 L1 客户端 CIDR 绑定 / L2 UID 映射 / L3 Kerberos）
- **SMB 适配**：Linux/macOS 委托 Samba，Windows 委托 PowerShell SMB cmdlets
