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
| `integration-tests` |      | Pebble 端到端测试                         |

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
