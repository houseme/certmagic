<div align="center">

# certmagic

**为 Rust 服务端提供 TLS 证书的自动获取、续期与维护。**

[![CI](https://github.com/houseme/certmagic/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/houseme/certmagic/actions/workflows/ci.yml)
[![Audit](https://github.com/houseme/certmagic/actions/workflows/audit.yml/badge.svg?branch=main)](https://github.com/houseme/certmagic/actions/workflows/audit.yml)
[![Crates](https://img.shields.io/crates/v/certmagic.svg)](https://crates.io/crates/certmagic)
[![Documentation](https://docs.rs/certmagic/badge.svg)](https://docs.rs/certmagic)
[![Dependency status](https://deps.rs/repo/github/houseme/certmagic/status.svg)](https://deps.rs/repo/github/houseme/certmagic)
[![Crates.io Total Downloads](https://img.shields.io/crates/d/certmagic)](https://crates.io/crates/certmagic)
[![Crates.io License](https://img.shields.io/crates/l/certmagic)](https://crates.io/crates/certmagic)

[English](README.md) | [简体中文](README.zh-CN.md)

</div>

---

## 概述

CertMagic 为你托管 TLS 证书：从 ACME CA（Let's Encrypt、ZeroSSL 等）自动获取证书、到期前自动续期、装订 OCSP
响应、通过共享存储实现多实例协作，甚至支持 **TLS 握手期间的按需签发**。

本 crate 提供证书全生命周期的自动化能力，并附带地道的 Rust API（async trait、强类型事件、`thiserror`、全链路 `Send + Sync`）。

## 核心特性

- **自研 ACME v2 客户端**：目录发现、防重放 nonce 池、账户管理（含外部账户绑定 EAB）、订单状态机、吊销、ARI 续期信息（含建议窗口抖动）
- **四种挑战求解器**：HTTP-01（引用计数共享监听器 + 框架无关处理器）、TLS-ALPN-01（RFC 8737 挑战证书）、DNS-01（可插拔
  `DnsProvider` + 传播检查），以及基于共享存储的 **分布式求解**——集群签发无需粘滞会话
- **HTTP-01 请求辅助函数**：校验无填充 base64url token，兼容查询参数和路由器添加的一层尾斜杠；无法保留挑战状态时可显式选择 blind-solving 回退（默认仍使用更安全的主机绑定注册表路径）
- **握手期签发与按需 TLS**：域名首次出现时即签发证书，由 `DecisionFunc` 或显式主机 allowlist 把关；未配置任何门禁时默认拒绝
- **证书缓存与维护循环**：按 SAN 索引的内存缓存、续期窗口（固定比例或 ARI 驱动 + 抖动）、OCSP 装订（手写 RFC 6960
  编解码：请求构建、委派响应者授权、ECDSA/RSA/Ed25519 签名验证）
- **存储抽象与分布式锁**：默认文件存储（原子写入 + 心跳锁文件），可自选后端（Redis、etcd、S3 等）实现多实例集群
- **证书存储可解耦**：证书和私钥可使用独立的 `CertStore` 后端，而 ACME 账户、锁和 OCSP 数据继续使用地面真实 `Storage`
- **生产级细节**：手调退避表（30 天总预算）的重试、按名去重的后台任务、滑动窗口限流器、强类型事件钩子、防 panic 的维护循环
- **运维扩展点**：缓存生命周期回调、可配置 HTTPS 重定向主机策略、自定义 DNS 传播解析器，以及可选关闭 OCSP 吊销后的自动替换

## 安装

```toml
[dependencies]
certmagic = "0.1"
tokio = { version = "1", features = ["full"] }
```

默认构建使用 AWS-LC-RS 加密后端，并启用 ZeroSSL 签发方。RSA 密钥生成为显式 opt-in。
如果需要更轻量、可移植的 Ring 构建，可关闭默认 feature 并显式选择所需能力：

```toml
[dependencies]
certmagic = { version = "0.1", default-features = false, features = [
  "ring", "file-storage", "http-01", "dns-01", "ocsp",
] }
```

`ring` 和 `aws-lc-rs` provider feature 会同时选择匹配的 `x509-parser` 签名验证后端（分别为 `verify` 和 `verify-aws`），因此证书验证后端与 rustls、rcgen、reqwest 保持一致。使用 `--no-default-features` 时应明确选择一个 provider，并按需打开 runtime feature。

`rsa` feature 现在是显式 opt-in，因为它会引入 RustCrypto `rsa` crate。
只签发 ECDSA 或 Ed25519 证书的部署应保持关闭，以缩小依赖树并避免 RSA
路径的 timing side-channel 风险。RustSec `RUSTSEC-2023-0071` 仍被显式跟踪，
因为上游尚未发布修复版本。

## 快速开始

```rust,no_run
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let domain = "example.com"; // 必须解析到本机

    let cache = certmagic::Cache::new(Default::default())?;
    let options = certmagic::ConfigOptions {
        issuers: vec![Arc::new(certmagic::AcmeIssuer::lets_encrypt())],
        ..Default::default()
    };
    let config = certmagic::Config::new(cache, options)?;
    let ct = CancellationToken::new();

    // 立即签发，后台自动续期
    config.manage_sync(&ct, &[domain.to_owned()]).await?;

    // 用 rustls 提供 HTTPS 服务
    let acceptor = Arc::new(config.certmagic_acceptor()?);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:443").await?;
    loop {
        let (tcp, _) = listener.accept().await?;
        let acceptor = Arc::clone(&acceptor);
        tokio::spawn(async move {
            if let Ok(tls) = acceptor.accept(tcp).await
                && let Ok(mut tls) = tls.await
            {
                // `tls` 是就绪的 TLS 流，交给你的 HTTP 栈即可
            }
        });
    }
}
```

更多示例见 [`examples/`](examples/)：[`basic_https`](examples/basic_https.rs)、
[`on_demand`](examples/on_demand.rs)（握手期按需签发）、
[`custom_dns01`](examples/custom_dns01.rs)（自定义 DNS 提供商签发泛域名）。

如需不绑定具体 Web 框架的 HTTP/1.1 包装、HTTP-01 应答和 HTTPS 重定向，
可使用 `certmagic::https` 或 `certmagic::https_on`。

更喜欢高层管理器？`CertManager` 用无取消参数的封装提供了同样的能力：

```rust,no_run
let manager = certmagic::CertManager::builder()
    .issuers(vec![std::sync::Arc::new(certmagic::AcmeIssuer::lets_encrypt())])
    .build()?;                    // try_build() 是显式的可错别名
manager.manage(&["example.com".to_owned()]).await?;   // 前台签发 + 自动续期
let acceptor = std::sync::Arc::new(manager.config().certmagic_acceptor()?);
```

如需一次性入口，`certmagic::manage(&domains).await` 会返回可直接使用的
`rustls::ServerConfig`。需要复用策略和后端配置时，可使用
`ConfigBuilder::new().policy(Policy::default()).storage(storage).build()`。

`Cache::new` 会自动启动续期/OCSP 维护。需要显式生命周期时，可使用
`Cache::new_without_maintenance`，再调用 `start_maintenance`；`stop_and_wait`
会取消并加入任务而不消费 cache。停止后的 cache 不能重新启动。

## 与 rustls 集成

三种路径，按部署形态选择：

| 路径              | API                                      | 行为                                                                                |
|-------------------|------------------------------------------|-------------------------------------------------------------------------------------|
| 同步缓存 resolver | `Config::tls_config()`                   | 仅从内存缓存服务，无 IO                                                              |
| 异步 acceptor     | `Config::certmagic_acceptor()`           | 在握手完成**之前**执行完整异步解析（存储加载 / 按需签发 / 维护）                     |
| 后台补救          | on-demand 开启时 `tls_config()` 自动附带 | 缓存未命中时后台签发，本次握手失败、下次成功                                        |

## Feature 开关

| Feature             | 默认 | 说明                                      |
|---------------------|------|-------------------------------------------|
| `file-storage`      | ✔   | 文件存储后端（原子写、心跳锁文件）        |
| `http-01`           | ✔   | HTTP-01 挑战监听器（Tokio TCP）           |
| `dns-01`            | ✔   | DNS 传播检查（hickory-resolver）          |
| `ocsp`              | ✔   | OCSP 装订生命周期（手写 RFC 6960 编解码） |
| `zerossl`           | ✔   | ZeroSSL ACME/EAB 与 REST API 签发方        |
| `local-cache`       |      | 节点本地读穿存储缓存                      |
| `rsa`               |     | 显式启用的 RSA 2048/4096/8192 密钥生成     |
| `ring`              |     | Ring 加密后端与 `x509-parser/verify`       |
| `aws-lc-rs`         | ✔   | AWS-LC 加密后端与 `x509-parser/verify-aws`（含 P-521 CSR 签名） |
| `redis-storage`     |     | 可选 Redis 存储与所有者校验租约锁         |
| `etcd-storage`      |     | etcd 租约、快照读取和受保护的证书发布     |
| `integration-tests` |      | Pebble 端到端测试                         |

`https` / `https_on` 包装器仅协商 HTTP/1.1，接收不超过 1 MiB 的 Content-Length
请求体，拒绝 chunked 等传输编码，并对请求读取设置 30 秒总超时。

## 存储后端选择

当前内置持久化后端为 FileStorage；LocalCache 是节点本地读缓存，不是分布式权威存储。
提供可选的 `redis-storage` 与 `etcd-storage`；SQL 和对象存储适配器尚未内置。

自定义后端实现 `Storage` 和 `Locker`，通过 `ConfigBuilder::storage` 注入。
`LockGuard::new` 已开放，未启用 `file-storage` 时也能创建后端自有的锁句柄。
释放回调必须保留本次获取的所有者 token，并避免阻塞异步执行器；网络后端可排队执行
校验 token 后的释放，并通过带过期时间的租约处理运行时退出后的恢复。
新增 `LockRelease::release_async` 与 `LockGuard::release_and_wait().await` 用于等待释放确认；
`is_valid()` 仅反映本地租约健康，不是 fencing。自动清理按获取实例追踪，同名或不同后端的
锁不会因旧句柄释放而被取消追踪。

手动调用 `track_lock(storage, name)` 后，所有权结束时必须配对调用 `untrack_lock(name)`。
句柄只移除自己的自动登记，不再按名称移除手动登记；新适配器优先使用自动追踪的获取函数。

LocalCache 命中不等待后端操作，缺失读取与写入按规范化后的键串行，同键并发缺失共享一次填充。
前缀删除会等待在途填充和写入结束。缓存项复用对应的键锁；淘汰或最后一个在途操作结束后，
无用键锁自动回收。存在键别名的自定义后端应覆盖 `Storage::canonical_key`；默认保留原始键，
FileStorage 和 Redis 使用统一的路径规范化，嵌套装饰器透传此身份。
单键缓存需淘汰后才能看到外部修改；整组资源读取直接交给后端。取消不能撤回已发给后端的写入；结果不确定时应读取
权威后端，不能假定本地缓存已与其同步。

精确移动通过 `Storage::move_key` 交给后端实现，不再借用递归 `delete`。移动到自身规范化
路径是无操作，源键的子项保持不变，目标已有值时返回 `StorageError::Conflict`。使用
KeyValueCertStore 的自定义 Storage 若需要私钥归档，应实现此可选方法；默认实现在修改
任何数据前报错。FileStorage 先将普通文件复制到目标目录的私有临时文件并 fsync，
再以硬链接发布完整值，最后删除源文件；目录和符号链接源会被拒绝，导入源权限较宽时
归档仍保持 Unix owner-only 权限。目标文件系统不支持硬链接时保留源数据并报错。
中断可能留下两份数据，不承诺跨文件崩溃原子性。Redis 使用单次原子重命名脚本，etcd 使用
revision 比较；受保护的 etcd 移动在同一事务内区分数据冲突和失锁，归档冲突不再废弃有效租约。

证书与私钥还可通过 `ConfigBuilder::cert_store` 单独接入 `CertStore`；账号、挑战记录、
锁和 OCSP 仍走 `Storage`。数据库事务或带版本的完整证书资源对象，可以提供比通用三键
适配器更强的原子性。通用适配器现已并发读取三项内容及存在性，但这不是后端事务快照。

**建议保留默认文件后端，将 Redis 作为可选适配器。** 单机握手缓存命中不需要 Redis；
多实例且已有 Redis 基础设施时，可以显式启用 `redis-storage`，并配置持久化、容量和故障恢复策略。
Redis 异步复制后的故障切换不能自动保证锁互斥，持久化策略也需要明确，参见
[Redis 锁文档](https://redis.io/docs/latest/develop/clients/patterns/distributed-locks/)
与[持久化文档](https://redis.io/docs/latest/operate/oss_and_stack/management/persistence/)。
对事务或一致性有更高要求时，可评估
[PostgreSQL 锁/事务](https://www.postgresql.org/docs/current/explicit-locking.html)
或 [etcd 事务/租约](https://etcd.io/docs/v3.6/learning/api/)；仍需后端适配和写入侧的
所有权检查，不能仅更换服务就宣称具备 fencing。

性能基准、原始样本及适用范围见 [benches/README.md](benches/README.md)。

## Etcd 适配器与写入侧保护

此功能属于 **Unreleased**，不包含在已发布的 0.1.0 中。启用 `etcd-storage`；
构建此功能（包括 `--all-features`）需安装 `protoc`。默认构建不引入 etcd/gRPC 依赖；
TLS 使用所选择的 Ring 或 AWS-LC provider。

通过 `EtcdStorage::connect(&endpoints, EtcdStorageOptions { namespace, ..Default::default() })`
连接同一集群的多个端点，再传给 `Config::builder().storage(storage)`。
端点必须使用相同协议。支持 HTTPS、WebPKI/自定义 CA、双向 TLS 和用户名密码；
认证信息放在 options 中，不允许嵌入 URL，日志与 Debug 不输出凭据或 PEM。

签发和续期通过 `CertStore::save_with_lock` 发布完整证书资源，默认键值适配器将三项写入
交给 `Storage::store_tx_with_lock`。etcd 在同一事务中校验锁的 revision、lease ID 和 token，
并写入证书、私钥和元数据。泄露私钥归档通过 `move_private_key_with_lock` / `move_with_lock`
原子完成，同时比较源 revision 和目标不存在条件，避免旧持有者覆盖、归档或移除新私钥。

`LockRelease::write_fence` 携带后端专用上下文；不支持该上下文的默认实现会直接报错，
Config 在联系 CA 前就检查兼容性。etcd 上下文支持原存储句柄的克隆及装饰器，
不同连接实例或不同后端会被拒绝。etcd 锁搭配任意 S3/秘密存储并不自动具备跨系统原子性，
这些 `CertStore` 适配器仍属后续工作。

完整资源的 `load_many` / `exists_exact_many` 在 etcd 中使用事务快照；仅有子键的前缀
不再算作证书组件值，原有 `exists/exists_many` 的前缀语义保持不变。LocalCache 整组透传，
避免缓存的旧版本和后端新版本混合。普通后端保留并发读取行为。前缀列表按固定 revision
分页，若历史已压缩则返回错误。数据使用版本化二进制封装，修改时间来自写入节点时钟；
所有权由 revision 判断。数据不绑定锁 TTL；记录和写入批次限制为 1 MiB，每批最多 64 个键。

默认租约 30 秒，每 10 秒保活。etcd 获取锁时确定 TTL；显式续租可以刷新，但不支持临时
扩展到超过配置的时长。取消在途续租后立即放弃本地所有权，防止错用迟到响应。
`Drop` 尽力撤销租约，`release_and_wait` 等待确认，进程或运行时退出由 TTL 恢复。
leader 切换期间可能返回暂时不可用或超时；不盲目重试结果不确定的写入，失去多数节点时
拒绝写入。普通 `store/delete`、旧 `save/move_private_key`、账号/挑战写入和存储清理
不自动具备 fencing；FileStorage/Redis 保留此前的本地健康检查语义。

显式运行隔离测试（需要 Docker 和 `protoc`）：

```sh
docker pull quay.io/coreos/etcd:v3.6.5
cargo test --locked --no-default-features --features ring,etcd-storage,local-cache \
  --test etcd_storage --test custom_locker -- --include-ignored
```

测试创建并清理专属容器与网络，客户端端口仅绑定回环地址；覆盖三节点故障恢复、旧所有者
拒绝、快照一致性、Config 签发/续期、私钥归档、取消与运行时退出、认证及真实双向 TLS。
不访问生产集群或 CA。使用示例见 `examples/etcd_storage.rs`。

## Redis 适配器

该能力目前属于 **Unreleased**，已发布的 0.1.0 不包含此 feature；请在当前仓库源码
或 path 依赖中使用，等待后续版本发布。

启用 `features = ["redis-storage"]`，通过
`RedisStorage::connect(url, RedisStorageOptions { namespace: "my-service".into(), ..Default::default() }).await?`
创建后端，再传给 `Config::builder().storage(storage).build()`。示例见
[examples/redis_storage.rs](examples/redis_storage.rs)。

- 单端点连接，支持密码/ACL URL、验证证书的 `rediss://` 与 redis-rs Unix socket URL。
- 默认租约 30 秒、心跳 10 秒、命令超时 5 秒、获取锁轮询 100 毫秒；心跳与命令预算之和必须小于租约。
- 值与服务端修改时间原子保存在同一 Redis hash 中，不设置过期时间；锁采用独立键空间和 `SET NX PX`。
- Lua 续租/释放先校验本次获取的 token；旧持有者不能操作新锁，心跳不缩短显式延长的租约。
- 前缀遍历使用转义后的 SCAN，删除分批执行；并发前缀修改不提供原子快照。
- `Drop` 是 best-effort 清理；需要确认释放时使用 `release_and_wait().await`，进程/运行时退出由 TTL 恢复。

**边界：** 当前不是 Redlock，不实现 Cluster/Sentinel 自动发现，也不提供写入侧 fencing。
签发/续期会在检测到租约丢失后停止重试和发布，但这些检查点不能替代原子写入 fencing。
证书通用三键适配器仍不是跨键崩溃事务。账号和私钥的持久化、非淘汰容量策略以及 ACL/TLS
需要由部署配置保证，库不会修改 Redis 服务端配置或输出连接 URL。

真实实例测试会启动独立临时目录、回环端口的 Redis，不使用生产 URL：

```sh
cargo test --locked --features redis-storage --test redis_storage -- --include-ignored
cargo test --locked --no-default-features --features ring,redis-storage --test redis_storage -- --include-ignored
```

可通过 `CERTMAGIC_REDIS_SERVER` 指定本地服务端二进制。网络测试默认忽略，纯配置测试正常运行。
本机验证使用 Redis 8.10.2，覆盖 AOF 重启恢复、认证、续租、连接失效、取消和旧持有者保护；
未据此宣称验证了 TLS 握手、Cluster/Sentinel、Valkey 或 Dragonfly。

| 其他后端 | 适配方向 | 当前状态与关键边界 |
| --- | --- | --- |
| Valkey | 复用 Redis 协议适配器 | 候选，需先运行同一兼容测试套件 |
| etcd | `Storage` + `Locker` + 受保护事务和快照读取 | 已实现 `etcd-storage`；所有权上下文绑定原始后端 |
| Consul KV | `Storage` + session 锁 | 需处理 session 失效、续期和 lock-delay |
| DynamoDB | 条件写、租约记录 | TTL 异步删除，不能直接当成锁过期判定 |
| redb / RocksDB | 单机嵌入式 KV | 阻塞工作移出 Tokio；不等同于分布式共享存储 |
| S3 兼容存储/密钥服务 | 优先适配完整资源 `CertStore` | 仍需合适的账号、挑战和锁后端 |

参考 [Valkey 兼容说明](https://valkey.io/topics/migration/)、
[Consul session](https://developer.hashicorp.com/consul/docs/automate/session)、
[DynamoDB TTL](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ttl-expired-items.html)。
以上其他后端是候选方案，目前没有对应的内置适配器。

## 文件存储协调

FileStorage 使用永久保留的 `locks/*.guard` 文件和唯一持有者标识，串行化锁创建、
心跳、释放及过期接管。共享文件系统必须支持操作系统文件锁；实例运行时不要删除
这些辅助文件。从旧的仅心跳协议升级时，应先停止所有实例，再以同一版本重新启动。

该机制属于租约协议，不提供 fencing：进程暂停超过租约后恢复，仍可能继续执行原有
业务写入。需要 fencing 的部署必须使用能强制隔离失效持有者的后端。
证书、私钥和元数据仍分别写入；`store_tx` 能回滚返回的写入错误，但不具备跨文件的
崩溃原子性。

## 测试

```sh
cargo test                          # 单元测试（离线）
cargo test --lib --all-features     # 全 feature 组合
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
shellcheck tests/*.sh

# RustSec 审计：RUSTSEC-2023-0071 是显式 opt-in RSA 例外
cargo audit --file Cargo.lock --deny warnings --ignore RUSTSEC-2023-0071

# 对 Pebble（Let's Encrypt 参考服务器）的真实 ACME 端到端测试：
./tests/run-pebble.sh               # 默认 DNS-01
PEBBLE_CHALLENGE=http-01 ./tests/run-pebble.sh
PEBBLE_CHALLENGE=tls-alpn-01 ./tests/run-pebble.sh

# 确定性边界检查（强制 Cargo 离线模式）：
./tests/external-validation.sh --offline
# 显式本地 Pebble lane（不访问生产 CA）：
./tests/external-validation.sh --pebble
# 临时 loopback 端口上的监听器检查（不需要 CA 或公网 DNS）：
./tests/external-validation.sh --loopback-challenges
```

Pebble 测试覆盖完整生命周期——账户注册、选定的 HTTP-01/TLS-ALPN-01/DNS-01
校验、签发、存储持久化和强制续期；HTTP-01 与 TLS-ALPN-01 模式会关闭
challtestsrv 的预置 challenge responder，让 certmagic 自己在配置的高端口上提供验证响应。

## 项目结构

```
src/
├── acme/           # ACME 协议层：传输、JWS、目录、订单、签发方
├── solvers/        # http-01 / tls-alpn-01 / dns-01 / 分布式挑战求解器
├── storage/        # Storage/Locker trait + FileStorage（原子写、锁）
├── ocsp/           # RFC 6960 编解码 + 装订生命周期
├── certificate.rs  # 解析、名称匹配、主体资格、续期窗口
├── cache.rs        # 内存证书缓存
├── config.rs       # 编排：签发 / 续期 / 管理 / 吊销
├── handshake.rs    # 握手期签发 + 按需门禁
├── tls_integration # rustls 胶水（三种集成路径）
└── runtime.rs      # 重试预算、任务管理器、单飞
```

## 许可证

Apache-2.0 —— 见 [LICENSE](LICENSE)。

## 鸣谢

- 感谢 [caddyserver/certmagic](https://github.com/caddyserver/certmagic) —— 本项目参考其设计思想。
- 感谢 [salvo-rs/certon](https://github.com/salvo-rs/certon) —— 其 API 命名启发了本项目的兼容别名与高层管理器设计。
