//! DNS-01 with a custom provider (the only challenge type that can issue
//! wildcard certificates).
use async_trait::async_trait;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

/// Your DNS provider integration (production: libdns-style API calls).
#[derive(Debug, Default)]
struct MyDns;

#[async_trait]
impl certmagic::solvers::dns::DnsProvider for MyDns {
    async fn append_txt(
        &self,
        _ct: &CancellationToken,
        zone: &str,
        name: &str,
        value: &str,
        _ttl: u32,
    ) -> certmagic::Result<()> {
        println!("DNS: create TXT {name} = {value} in zone {zone}");
        Ok(())
    }

    async fn delete_txt(
        &self,
        _ct: &CancellationToken,
        zone: &str,
        name: &str,
        value: &str,
    ) -> certmagic::Result<()> {
        println!("DNS: delete TXT {name} = {value} in zone {zone}");
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let domain = std::env::var("DOMAIN").expect("set DOMAIN");
    let wildcard = format!("*.{domain}");

    let mut issuer = certmagic::AcmeIssuer::lets_encrypt();
    issuer.dns_provider = Some(Arc::new(MyDns));

    let cache = certmagic::Cache::new(Default::default())?;
    let options = certmagic::ConfigOptions {
        issuers: vec![Arc::new(issuer)],
        ..Default::default()
    };
    let config = certmagic::Config::new(cache, options)?;

    let ct = tokio_util::sync::CancellationToken::new();
    config.manage_sync(&ct, &[domain.clone(), wildcard]).await?;
    println!("obtained {domain} and *.{domain}");
    Ok(())
}
