# NAOS 部署、升级与交付验收

本文档适用于当前 v0.1.0 **交付候选版本**，不代表所有宿主机互操作验收已通过。必须以对应 commit 的 `ci`、`delivery` 和本机验收记录为准。

## 1. 获取产物

进入 GitHub Actions → **delivery** → 对应 main commit 的 workflow run，下载以下平台工件之一：

- `naos-Linux-X64`：Linux tar.gz 包 + SHA-256；
- `naos-macOS-ARM64` / `naos-macOS-X64`：Apple Silicon / Intel macOS tar.gz 包 + SHA-256；
- `naos-Windows-X64`：Windows zip 包 + SHA-256。

工件名由 GitHub runner 的 OS/arch 决定，文件包内包含 `naosd`（Windows 为 `naosd.exe`）和本部署说明。下载后验证同名 `.sha256` 文件提供的 checksum；包由 CI 构建，并不等于代码签名或公证，生产发行仍应增加签名与发布流程。CI 产物有保留期，不能作为长期下载渠道。

`delivery` 同时执行Linux、Windows 与双架构 macOS release 编译、OpenAPI CLI smoke；Linux/macOS/Windows 均执行内嵌 SPA 启动、深链路、静态资源和 API 404 保护测试。真实 SMB 客户端行为、系统服务安装及生产部署仍需在目标主机运行。

## 2. 运行环境与安全前提

- 仅支持**单实例管理同一宿主机**；DB 使用本机 SQLite，勿放到非可靠网络文件系统。
- 当前 `naosd` 监听管理 HTTP，不直接提供 HTTPS；默认绑定 `127.0.0.1:8443`。生产使用 TLS 终止代理，限制对管理端口的直连，并配置强认证及适当访问控制。
- **首次管理员初始化须在可信的本机环境完成，再开放远程代理入口。** 服务端按 TCP peer loopback 校验初始化；同机反向代理会使外网请求看起来来自 loopback，因此初始化之前不能把 `/api/v1/setup/admin` 暴露给不可信客户端。
- Session Cookie 使用 `Secure; HttpOnly; SameSite=Strict`。远程浏览器必须通过 HTTPS 代理访问；生产不要把明文管理 HTTP 直接暴露到局域网或公网。
- 创建系统账号、修改宿主机文件 ACL 和操作 SMB provider 可能需要提升权限。根据平台最小化权限，在具备管理权限的受控主机上运行；本项目不会擅自接管未知 TCP/445 listener。
- SMB 使用本机系统 provider（Linux Samba、Windows 原生 SMB、macOS 当前可用 provider），**不运行自研 SMB listener**。先检查现有 shares 与 TCP/445 ownership，并备份现有 SMB 配置。
- NFS 默认关闭；如启用，请确认 `2049/20048/20049/20050` 与 rpcbind 相关端口可用，并通过防火墙限制可信客户端。低级 CIDR/UID 模式不等价于 Kerberos 安全性。

## 3. 首次启动

解压后进入准备好的专用数据目录，确保运行账户对 SQLite 数据目录有读写权限。Unix 示例：

```bash
mkdir -p ./naos-data
export NAOS_DATABASE_URL="sqlite://$(pwd)/naos-data/naos.db?mode=rwc"
export NAOS_LISTEN=127.0.0.1
export NAOS_PORT=8443
./naosd doctor-smb
./naosd
```

Windows PowerShell 示例（从解压目录运行）：

```powershell
New-Item -ItemType Directory -Force .\naos-data | Out-Null
$env:NAOS_DATABASE_URL = "sqlite://naos-data/naos.db?mode=rwc"
$env:NAOS_LISTEN = "127.0.0.1"
$env:NAOS_PORT = "8443"
.\naosd.exe doctor-smb
.\naosd.exe
```

在可信本机通过浏览器打开 `http://localhost:8443/` 完成首次管理员创建。浏览器对 Secure Cookie 的本地 HTTP 例外可能不同；如会话无法持久化，请使用可信本地 HTTPS 代理完成初始化，不要移除 Cookie 安全属性。完成首次初始化后，配置 HTTPS 代理再授权远程访问。

可用的基础检查：

```bash
curl -f http://127.0.0.1:8443/health/live
curl -f http://127.0.0.1:8443/health/ready
```

`/health/ready` 可能在依赖未准备好时返回 503；不能以 SPA 首页响应 200 替代 readiness 验证。可使用 `./naosd export-openapi` 验证 API 契约，也可在管理页面「设置与诊断」运行 Verify。

## 4. 升级和回滚

1. 记录当前程序版本、运行参数、Git commit 与 SMB Doctor 结果；确认无正在运行的配置 Apply 操作。
2. 停止 naosd，在停止状态下备份整个 SQLite 数据文件（以及使用到的配置、服务身份与证书/密钥），并保证备份可恢复。
3. 校验新产物的 SHA-256、对应 commit 的 CI 状态和平台架构；替换二进制，保留原二进制与备份。
4. 以原参数启动，检查 `health/ready`、管理员登录、共享状态、Doctor/Verify、ACL 与协议读写。
5. 数据库迁移可能不可逆。若升级失败，先停止服务并恢复升级前的 SQLite 快照及相匹配的旧二进制；不要在已迁移的生产 DB 上盲目直接启动旧程序。
6. 卸载前备份数据并核查所有 naos-owned SMB share/system account；禁止盲目清理 unmanaged share、已有 Samba include 或其它服务。

当前版本**未提供自动安装器、系统服务安装/卸载器、数据库在线备份工具或一键回滚**。生产运维需要另外配置 OS 服务管理、权限、日志采集、TLS 代理和备份计划。

## 5. 交付验收门禁（必须留存证据）

| 门禁 | 自动化检查 | 仍需实机确认 |
| --- | --- | --- |
| Web/API | SPA 生成、OpenAPI 类型、CI 构建、登录/ACL 等 Rust API 集成测试 | 浏览器初始化→登录→增删用户/共享→权限设置→审计，跨浏览器/权限角色 |
| Linux SMB | CI Samba real smoke、Samba adapter 测试 | 已有 Samba / 未管理 share coexistence、真实客户端权限拒绝、升级后 Verify |
| Windows SMB | CI Windows SMB real smoke、platform Rust matrix | 目标 Windows 版本的 Explorer/权限继承/共享重启 |
| macOS SMB | CI Doctor + adapter 测试 | File Sharing provider 可管理性、Finder 读写及未知 445 owner 不接管 |
| WebDAV | Rust 测试 | 真实客户端经 HTTPS 代理读写/拒绝访问 |
| NFSv3 | RPC/NLM/NSM 单测与选定 CI smoke | 分离 client/server 的 NLM restart/reclaim、真实客户端 ACL 与网络边界 |
| Kerberos | Linux MIT KDC 集成、Windows SSPI build/test | 企业 AD/真实 realm + Windows/macOS/Linux 内核客户端互操作 |
| 交付包 | Linux/Windows/macOS（ARM64 与 X64）`delivery` release 构建、三平台 SPA smoke、checksum | 目标机器启动、系统服务、恢复演练、程序包签名/公证 |

只有**目标部署环境所需门禁全部通过**并保存运行记录，才能把对应平台/功能标记为「可交付」。某平台 provider 返回 unsupported/degraded 时不应对外宣称该功能可用。含 `system-gss` 的 Kerberos 构建不是默认发布包，需要在正确配置 GSS/SSPI 凭据后单独构建和验收：

```bash
cargo build --release -p naosd --features embedded-web,system-gss
```

## 6. 当前已知限制

- 默认发行包不提供安装器、数字签名、公证或自动更新。
- 不承诺 macOS native SMB provider 能管理所有用户共享配置；不可管理场景必须 fail-closed。
- 真实 Windows/macOS/Linux 内核 NFS 锁恢复与企业 Kerberos 全链路仍依赖独立测试环境。
- 单机单实例，未实现 HA；审计与配置备份由部署方负责。
- 生产环境必须先完成 TLS、最小权限、防火墙、故障恢复与实际客户端验收。
