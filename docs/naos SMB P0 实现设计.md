# naos 自研 SMB P0 候选设计（Deferred）

> **状态：Deferred / 非当前实现计划。** v0.5 决策为：现阶段不自研 SMB Server，`naosd` 不监听 TCP/445，Linux/macOS/Windows 优先复用 system SMB provider。本文仅保留未来研究资料，不属于当前 workspace、roadmap、CI 或 Definition of Done。  
>
> 若未来恢复自研 SMB，必须先新增 ADR，重新评估 445 端口共存、系统 SMB 迁移、安装升级兼容和安全维护成本。  
>
> 以下内容保留 v0.4 时的 P0 候选技术方案，**当前不得据此直接进入实现**。  
>
> 原目标：把“自研 SMB”收敛成可直接编码、联调和验收的 P0 方案。  
> P0 目标：**Direct TCP + SMB 2.1 + SPNEGO/NTLMv2 + signing + 常用文件操作 + 基础 lock/share-mode 语义**。  
> P0 不追求完整 Windows File Server 功能，也不宣称 SMB3 能力。

---

## 1. 目标与边界

P0 要解决的是：

1. Windows 11、macOS、Linux kernel cifs 能稳定连接；
2. 本地 naos 用户可以通过 NTLMv2 登录；
3. 客户端要求 SMB signing 时可以正常工作；
4. 能完成目录浏览、创建、读写、flush、rename、delete、查询元数据；
5. 基础 share-access 和 byte-range lock 语义正确；
6. 所有文件访问都经过 naos 的统一 ACL、FileBackend 和 AuditSink；
7. malformed packet、资源耗尽和状态机异常不能造成 panic、越界或无上限内存分配。

P0 明确不做：SMB1、SMB 3.x dialect negotiation、encryption、multichannel、RDMA、QUIC、DFS、durable/persistent handle、lease、oplock caching、printer、通用 named pipe server、AD Domain Controller、Kerberos。

未实现能力不能在 NEGOTIATE response 中 advertise。

---

## 2. 规范基线

实现以 Microsoft Open Specifications 为协议权威来源：

- [MS-SMB2] SMB Protocol Versions 2 and 3  
  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/
- [MS-SPNG] SPNEGO Extensions  
  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-spng/
- [MS-NLMP] NT LAN Manager Authentication Protocol  
  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/
- [MS-ERREF] Windows Error Codes / NTSTATUS
- [MS-FSCC] File System Control Codes / file information structures

v0.4 设计阶段记录的 [MS-SMB2] published revision 为 **88.0（2026-09-28）**。

真正开始协议实现时增加 `docs/protocol/smb-spec-baseline.md`，记录规范版本、实现日期、已实现 dialect/command/context/info class 和已知偏差。规范版本升级不能只改链接，必须跑完整 interoperability regression。

---

## 3. crate 边界

```text
crates/
├─ naos-smb-protocol/
│  ├─ transport/
│  ├─ header/
│  ├─ command/
│  ├─ codec/
│  ├─ status/
│  ├─ signing/
│  └─ types/
├─ naos-smb-server/
│  ├─ connection/
│  ├─ session/
│  ├─ tree/
│  ├─ open/
│  ├─ credit/
│  ├─ compound/
│  ├─ dispatcher/
│  └─ auth/
└─ naos-smb-adapter/
   ├─ auth/
   ├─ filesystem/
   ├─ acl/
   ├─ audit/
   └─ fallback/
```

依赖固定为：

```text
naos-smb-protocol
       ▲
       │
naos-smb-server
       ▲
       │
naos-smb-adapter
```

硬约束：protocol/server 不知道 SQLite、host absolute path、naos ACL；adapter 才做 identity/share/path/ACL/FileBackend 映射。wire parser 默认不使用 `unsafe`；所有 attacker-controlled length/count 在 allocation 前必须先过硬上限与 checked arithmetic。

---

## 4. Direct TCP 传输层

P0 只支持 Direct TCP。生产监听 TCP/445；standalone 默认用 `127.0.0.1:1445`。

每条 SMB message 前有 4-byte framing：

```text
byte 0      = 0x00
bytes 1..3  = 24-bit big-endian payload length
payload     = SMB2 message
```

reader：

```text
read_exact(4)
→ first byte == 0
→ decode u24 length
→ length <= max_frame_size
→ bounded allocation
→ read_exact(length)
→ SMB2 frame decoder
```

建议初始：`max_frame_size=16MiB`、`read_timeout=30s`、`idle_timeout=15min`。长度超上限直接断连接并记录 security audit。

每连接必须限制：inflight request、pending bytes、session、tree、open 数量。禁止“每 packet 无限制 spawn task”。推荐 bounded request queue + dispatcher + bounded response queue + single socket writer。

---

## 5. SMB2 parser / encoder

解析分两阶段：

```text
RawFrame
→ SMB2 header view
→ compound boundary validation
→ command fixed header validation
→ offset/length slice validation
→ typed request
```

所有 `offset + length`、`count * element_size`、`NextCommand` 都必须 checked arithmetic。

P0 header 校验至少包含：

- ProtocolId = FE 'S' 'M' 'B'；
- StructureSize = 64；
- client request 不允许 SERVER_TO_REDIR；
- Command 在已知范围；
- NextCommand 为 0 或 8-byte aligned；
- NextCommand 不越 frame；
- signed request 在 handler 前验签；
- SessionId/TreeId/FileId 在 state/dispatcher 层校验。

### 5.1 compound

P0 支持常见 related compound：

```text
CREATE + QUERY_INFO + CLOSE
CREATE + READ + CLOSE
CREATE + WRITE + CLOSE
```

后续 related request 可继承 Session/Tree，CREATE 后的特殊 FileId 映射为前序 CREATE 返回的 FileId。related/unrelated 不能混用；前一步失败后不能读取未初始化 inherited context。P0 不实现需要长期 STATUS_PENDING 的 compound。

---

## 6. Connection 状态机

```text
Accepted
  ↓
Unnegotiated
  ↓ NEGOTIATE
Negotiated
  ↓ SESSION_SETUP (1..n)
Authenticated Session
  ↓ TREE_CONNECT
Tree
  ↓ CREATE
Open
```

Connection 至少保存 dialect、signing policy、multi-credit、max sizes、credit window、session table、outstanding request table、peer、created/last activity。

P0 禁止：未 NEGOTIATE 就 SESSION_SETUP、未认证就 TREE_CONNECT、跨 Session 使用 TreeId、跨 Tree/Session 使用 FileId、close 后复用 FileId。

---

## 7. NEGOTIATE

P0 产品策略：

```toml
[smb]
min_dialect = "2.1"
max_dialect = "2.1"
```

只有客户端列表包含 `0x0210` 才建立 P0 connection。P1 再开放 `3.1.1`。

P0 response：

```text
DialectRevision = 0x0210
SIGNING_ENABLED  = 1
SIGNING_REQUIRED = server policy
DFS              = 0
LEASING          = 0
MULTI_CHANNEL    = 0
PERSISTENT       = 0
ENCRYPTION       = 0
LARGE_MTU        = only after multi-credit verified
```

ServerGuid 必须跨重启稳定，首次初始化生成后持久化。

P0 MaxTransact/Read/Write 先设 1 MiB；multi-credit 未通过大 IO 测试前不提高也不宣称更强 capability。

---

## 8. SESSION_SETUP / SPNEGO / NTLMv2

典型流程：

```text
NEGOTIATE
→ SESSION_SETUP(NTLM NEGOTIATE)
← STATUS_MORE_PROCESSING_REQUIRED + CHALLENGE + SessionId
→ SESSION_SETUP(NTLM AUTHENTICATE, same SessionId)
← STATUS_SUCCESS
```

第一次需要继续认证时就分配 SessionId。

P0 只允许：NTLMv2 + Extended Session Security + SPNEGO。拒绝 LM、NTLMv1、guest、anonymous。

认证必须：CSPRNG challenge、constant-time MAC compare、统一 username canonicalization、明确 workgroup/domain policy、不记录 NT response/session key/NT hash、失败不暴露用户名存在性、接入 IP+username 双维度 rate limit。

P0 只认证本地 naos 用户，接受 `alice`、`WORKGROUP\alice`、`server-name\alice`；其它 domain 不映射本地身份。

认证成功产生 SessionKey，用于 SMB 2.1 HMAC-SHA256 signing。SessionKey 使用 secret wrapper，Debug 不输出，session 释放后 zeroize。

---

## 9. Signing

P0 支持 SMB 2.1 HMAC-SHA256 signing；生产默认 `required`。

接收：parse → locate session → determine requirement → require SIGNED → verify → dispatch。发送：encode → zero signature → calculate → set SIGNED → write。

invalid signature 在任何文件 IO 前终止。必须测试 valid、missing、single-bit corrupt、payload tamper、signed compound。

---

## 10. TREE_CONNECT

UNC `\\server\media` 解析成 server/share，再通过 ShareRegistry 找 ShareId；禁止 raw share name 直接 join filesystem root。

Tree connect 不能简单检查根 ACL，因为 naos 可以根无权限但深层有授权。规则：authenticated + share enabled + SMB enabled + user 在该 share 有任意潜在 grant。实际路径在 CREATE/后续操作重新 ACL。

不存在 share → `STATUS_BAD_NETWORK_NAME`；存在但完全无授权 → `STATUS_ACCESS_DENIED`。

P0 可提供最小 `IPC$` compatibility tree，但不提供通用 named pipe。

---

## 11. CREATE

解析 DesiredAccess、FileAttributes、ShareAccess、CreateDisposition、CreateOptions、Name、CreateContexts。Name 先 UTF-16 decode → separator normalization → reject NUL/traversal → RelativePath；protocol/server 永远不拿 host absolute path。

P0 支持全部常见 disposition：SUPERSEDE、OPEN、CREATE、OPEN_IF、OVERWRITE、OVERWRITE_IF。

最低 access mapping：

```text
READ_DATA / LIST_DIRECTORY → read/list
READ_ATTRIBUTES            → stat
WRITE_DATA / APPEND_DATA    → write
WRITE_ATTRIBUTES            → metadata write
DELETE                      → delete intent
```

请求多项权限时必须全部满足，不能 silent downgrade。

P0 明确处理 DIRECTORY_FILE、NON_DIRECTORY_FILE、DELETE_ON_CLOSE、WRITE_THROUGH、SEQUENTIAL_ONLY、RANDOM_ACCESS。

### 11.1 share mode

P0 必须实现 FILE_SHARE_READ/WRITE/DELETE。检查是双向的：new DesiredAccess 必须被所有 existing ShareAccess 允许，同时 existing DesiredAccess 必须被 new ShareAccess 允许。冲突返回 `STATUS_SHARING_VIOLATION`。

share-mode table 用 stable file identity，不用纯 pathname。

### 11.2 create contexts

parser 必须安全遍历 context chain，但 P0 不 advertise lease/durable/persistent handle。未知 context 仅在规范允许时忽略。

---

## 12. FileId / Open

Open 至少保存 FileId、BackendHandle、SessionId、TreeId、GrantedAccess、ShareAccess、delete-on-close、directory flag、enumeration state。

FileId 由 server 分配，不编码裸指针/fd/HANDLE/绝对路径；lookup 同时验证 Session/Tree ownership；close 后失效。P0 重启后所有 open handle 失效。

---

## 13. FileBackend

```rust
#[async_trait]
pub trait FileBackend: Send + Sync {
    async fn open(&self, ctx: &FileContext, share: ShareId, path: &RelativePath, request: OpenRequest)
        -> Result<OpenedFile, FileError>;
    async fn read_at(&self, handle: &BackendHandle, offset: u64, len: usize)
        -> Result<Bytes, FileError>;
    async fn write_at(&self, handle: &BackendHandle, offset: u64, data: Bytes)
        -> Result<usize, FileError>;
    async fn flush(&self, handle: &BackendHandle) -> Result<(), FileError>;
    async fn query_info(&self, handle: &BackendHandle, class: FileInfoClass)
        -> Result<FileInfo, FileError>;
    async fn set_info(&self, handle: &BackendHandle, change: FileInfoChange)
        -> Result<(), FileError>;
    async fn read_dir(&self, handle: &BackendHandle, query: DirQuery)
        -> Result<DirBatch, FileError>;
    async fn lock(&self, handle: &BackendHandle, request: LockRequest)
        -> Result<(), FileError>;
    async fn close(&self, handle: BackendHandle) -> Result<(), FileError>;
}
```

open 后尽量按 handle 操作；rename/delete 优先 handle-relative；FileBackend 才知道 canonical host path；backend 返回平台无关错误，adapter 映射 NTSTATUS。

---

## 14. 文件名与大小写

默认 `portable_names=true`。新建/rename 至少拒绝 NUL、separator、`.`、`..`；portable 模式还拒绝 Windows 设备保留名和 trailing dot/space。

Linux 既存 non-UTF8 filename 无法无损映射 SMB Unicode：v1 由 Doctor 报告，不发明私有转义。

SMB case-insensitive lookup 必须集中在 `SmbNameComparator`，不能各处随手 `to_lowercase()`。Linux 若已有 `Foo.txt` 与 `foo.txt`：exact match 优先；否则唯一 case-insensitive match 使用；多 match 返回冲突并产生 Doctor warning；CREATE/RENAME 不允许制造新 collision。

---

## 15. READ / WRITE / FLUSH

READ 校验 Session/Tree/File、granted access、range、CreditCharge；使用 bounded buffer；EOF 可 short read。

WRITE 校验 write/append access、ACL、range、disk/read-only 错误；禁止 attacker length 直接驱动无上限 allocation。

ACL：CREATE/Open 必查；Open 保存 ACL generation；generation 不变时连续 READ/WRITE 可用缓存授权，变化后重新求值；rename/delete/set-info 每次走最新 ACL。

FLUSH 必须落真实 backend flush，不能直接 success。

---

## 16. QUERY_DIRECTORY

每个 directory Open 保留 enumeration state。P0 优先支持：FileDirectoryInformation、FileFullDirectoryInformation、FileBothDirectoryInformation、FileNamesInformation、FileIdBothDirectoryInformation。

要求 restart scan、pattern filter、bounded response、大目录分页；不能一次 materialize 全目录。额外 info class 根据三端抓包补。

---

## 17. QUERY_INFO / SET_INFO

P0 优先：FileBasicInformation、FileStandardInformation、FileInternalInformation、FileNetworkOpenInformation、FileNameInformation、FileDispositionInformation、FileRenameInformation、FileEndOfFileInformation、FileAllocationInformation；NormalizedName 是否加入由 interop 决定。

security descriptor / EA / stream / quota 未实现时返回明确 unsupported/invalid-info-class，不伪造成功。

rename：source parent rw + destination parent rw + collision check + share-delete check + handle-relative rename + audit；禁止跨 share rename。

---

## 18. LOCK

LOCK 纳入 P0：basic shared/exclusive byte range、unlock、immediate conflict、fail-immediately。暂不做无限等待。lock table 使用 stable file identity，不能因 rename 丢锁。

---

## 19. Credit accounting

SMB 2.1 起不能忽略 CreditCharge。Connection 维护有界 CreditWindow：validate CreditCharge → validate MessageId/window → consume → process → bounded grant。

初始建议 `initial=32`、`max=512`，以后可调但必须有硬上限。

---

## 20. NTSTATUS 映射

FileBackend 不直接返回 NTSTATUS。典型映射：NotFound→OBJECT_NAME_NOT_FOUND，ParentNotFound→OBJECT_PATH_NOT_FOUND，AlreadyExists/NameCollision→OBJECT_NAME_COLLISION，PermissionDenied→ACCESS_DENIED，NotDirectory→NOT_A_DIRECTORY，IsDirectory→FILE_IS_A_DIRECTORY，SharingViolation→SHARING_VIOLATION，InvalidHandle→FILE_CLOSED，ReadOnly→MEDIA_WRITE_PROTECTED，NoSpace→DISK_FULL，NameInvalid→OBJECT_NAME_INVALID，NotSupported→NOT_SUPPORTED。

最终 status 按 command/context 细化。OS error 只进受限日志，不返回 host path。

---

## 21. CANCEL / async

P0 解析 SMB2 CANCEL，并允许取消尚未产生不可逆副作用的 backend operation。P0 不依赖 STATUS_PENDING + AsyncId 实现 CHANGE_NOTIFY；P1 引入 notify 后再完整建设 AsyncCommandList。

---

## 22. 生命周期

Connection close：停止新请求 → cancel pending → release auth → close session/tree/open → release lock/share-mode → zeroize keys → audit summary。

LOGOFF 使 SessionId、tree、open、lock 全失效；TREE_DISCONNECT 只清理当前 tree。cleanup 必须 idempotent。

---

## 23. 审计与指标

SMB data audit 至少关联 connection/session/user/client/dialect/signed/share/action/path/result/duration/bytes。高频 read/write 可聚合，但 deny/security 必须记录。禁止记录 NT hash、NTLM response、session key、完整 security blob。

建议内部 metrics：connections、sessions、trees、opens、auth success/failure、signature failure、requests by command/status、duration、read/write bytes、credit、parser reject、resource limit。

---

## 24. naos-smbd

standalone：`--listen 127.0.0.1:1445 --root ... --user alice --password-stdin --signing required|enabled`。密码不能普通 argv 传递；test credential 只放内存，退出丢失。

---

## 25. 测试与 fuzz

测试目录覆盖 codec、vectors、state、backend、interop/windows|macos|linux、fuzz、soak。

状态用例至少：SESSION_SETUP before NEGOTIATE、TREE_CONNECT before auth、wrong TreeId/FileId、cross-session FileId、LOGOFF invalidation、TREE_DISCONNECT 隔离。

share-mode 建 read/write/delete DesiredAccess × ShareAccess 完整矩阵。

interop：Windows Explorer/PowerShell、macOS Finder/mount_smbfs、Linux mount.cifs/smbclient，覆盖 browse/copy/rename/delete/overwrite/concurrent-open/signing-required，并用 MessageId 对齐 pcap 与 server trace。

fuzz 至少覆盖 Direct TCP framing、SMB2 header、compound、NEGOTIATE、SESSION_SETUP envelope、TREE_CONNECT、CREATE/context、QUERY_DIRECTORY、QUERY_INFO、SET_INFO、LOCK。Invariant：no panic、no UB、no unchecked overflow、no unbounded allocation、no infinite loop。

---

## 26. P0 编码顺序

| 序 | 工作 | 出口 |
| --- | --- | --- |
| 1 | Direct TCP + SMB2 header | golden + fuzz |
| 2 | NEGOTIATE | Windows 收有效 SMB2 response |
| 3 | SPNEGO/NTLMv2 SESSION_SETUP | Active Session |
| 4 | signing | signing-required 正常 |
| 5 | TREE_CONNECT | share 可连接 |
| 6 | CREATE + CLOSE | root/file 可 open |
| 7 | QUERY_DIRECTORY | 三端列目录 |
| 8 | QUERY_INFO | metadata |
| 9 | READ | 文件读取 |
| 10 | WRITE + FLUSH | 创建/覆盖 |
| 11 | SET_INFO | rename/delete/EOF |
| 12 | share-access | 并发 open 冲突 |
| 13 | LOCK | range lock |
| 14 | compound | related chain |
| 15 | resource limits | hardening |
| 16 | interop + fuzz + soak | experimental gate |

---

## 27. P0 出口标准

- Direct TCP framing 稳定；
- SMB2 parser/compound 有 fuzz；
- SMB 2.1 negotiation；
- SPNEGO + NTLMv2；
- signing-required；
- TREE_CONNECT；
- CREATE/CLOSE/READ/WRITE/FLUSH；
- QUERY_DIRECTORY/QUERY_INFO/SET_INFO；
- share-access；
- byte-range LOCK；
- Windows/macOS/Linux smoke；
- malformed request 不 panic；
- host absolute path 不进入 protocol/server crate；
- ACL deny 在实际 IO 前；
- credential/session key 无日志泄露；
- 1 GiB+ 传输；
- standalone soak 至少 2 小时无 connection/session/open 持续泄漏。

P0 完成后才进入 SMB3.1.1 P1，不并行提前做 encryption/lease/durable handle。