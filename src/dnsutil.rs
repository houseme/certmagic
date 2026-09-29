//! DNS utilities for DNS-01 propagation checks.

use crate::error::{DnsError, Error, Result};

#[cfg(feature = "dns-01")]
type AuthoritativeNsEntry = (std::time::Instant, Vec<std::net::IpAddr>);
#[cfg(feature = "dns-01")]
type AuthoritativeNsCache =
    std::sync::Mutex<std::collections::HashMap<String, AuthoritativeNsEntry>>;
#[cfg(feature = "dns-01")]
static AUTHORITATIVE_NS_CACHE: std::sync::OnceLock<AuthoritativeNsCache> =
    std::sync::OnceLock::new();

/// Return the recursive resolvers to use for propagation checks. Explicit
/// resolvers are normalized and preserved; when none are supplied, read the
/// platform resolver list. This keeps resolver discovery independent of the
/// optional hickory feature and a system-resolver fallback.
#[must_use]
pub fn recursive_nameservers(resolvers: &[String]) -> Vec<String> {
    if !resolvers.is_empty() {
        return resolvers
            .iter()
            .map(|r| r.trim().trim_end_matches('.').to_owned())
            .filter(|r| !r.is_empty())
            .collect();
    }

    #[cfg(unix)]
    {
        std::fs::read_to_string("/etc/resolv.conf")
            .map(|contents| {
                contents
                    .lines()
                    .filter_map(|line| {
                        let body = line.split_once('#').map_or(line, |(body, _)| body);
                        let mut fields = body.split_whitespace();
                        (fields.next() == Some("nameserver")).then(|| fields.next())
                    })
                    .flatten()
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    }
    #[cfg(not(unix))]
    {
        Vec::new()
    }
}

/// Find the closest enclosing zone (SOA apex) for `fqdn` by walking up
/// label by label.
///
/// # Errors
/// [`Error::Dns`] when no SOA is found or DNS support is disabled.
pub async fn find_zone_by_fqdn(fqdn: &str) -> Result<String> {
    #[cfg(feature = "dns-01")]
    {
        let resolver = system_resolver()?;
        let mut labels: Vec<&str> = fqdn.trim().trim_end_matches('.').split('.').collect();
        while labels.len() >= 2 {
            let candidate = labels.join(".");
            if soa_exists(&resolver, &candidate).await {
                return Ok(candidate);
            }
            labels.remove(0);
        }
        Err(Error::Dns(DnsError::ZoneNotFound(fqdn.to_owned())))
    }
    #[cfg(not(feature = "dns-01"))]
    {
        let _ = fqdn;
        Err(Error::Dns(DnsError::Disabled))
    }
}

/// Whether a TXT lookup for `name` contains `value` exactly
///.
///
/// Lookup errors (NXDOMAIN, servfail, …) resolve to `Ok(false)` — during
/// propagation polling a missing record is the expected intermediate state.
///
/// # Errors
/// `DnsError::Disabled` when the `dns-01` cargo feature is off.
pub async fn txt_contains(name: &str, value: &str) -> Result<bool> {
    #[cfg(feature = "dns-01")]
    {
        use hickory_resolver::proto::rr::{RData, RecordType};
        let resolver = system_resolver()?;
        let present = match resolver
            .lookup(name.trim_end_matches('.').to_string(), RecordType::TXT)
            .await
        {
            Ok(response) => {
                for record in response.answers() {
                    if let RData::TXT(txt) = &record.data {
                        let joined: String = txt
                            .txt_data
                            .iter()
                            .map(|b| String::from_utf8_lossy(b).into_owned())
                            .collect();
                        if joined == value {
                            return Ok(true);
                        }
                    }
                }
                false
            }
            // NXDOMAIN / NoRecordsFound are expected while propagating.
            Err(_) => false,
        };
        Ok(present)
    }
    #[cfg(not(feature = "dns-01"))]
    {
        let _ = (name, value);
        Err(Error::Dns(DnsError::Disabled))
    }
}

/// Query TXT records directly from the zone's authoritative name servers.
/// The recursive system resolver is used only to discover the zone's NS set
/// and resolve nameserver hostnames; TXT answers are then fetched from each
/// authoritative address independently.
pub async fn txt_contains_authoritative(name: &str, value: &str) -> Result<bool> {
    #[cfg(feature = "dns-01")]
    {
        use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
        use hickory_resolver::net::runtime::TokioRuntimeProvider;
        use hickory_resolver::proto::rr::{RData, RecordType};

        let recursive = system_resolver()?;
        let zone = find_zone_by_fqdn(name).await?;
        let cache = AUTHORITATIVE_NS_CACHE.get_or_init(Default::default);
        let cached = cache.lock().ok().and_then(|entries| {
            entries.get(&zone).and_then(|(stored, ips)| {
                (stored.elapsed() < std::time::Duration::from_secs(60)).then(|| ips.clone())
            })
        });
        let authoritative_ips = if let Some(cached) = cached {
            cached
        } else {
            let ns_lookup = recursive
                .lookup(zone.clone(), RecordType::NS)
                .await
                .map_err(|e| Error::Dns(DnsError::Query(format!("NS lookup: {e}"))))?;
            let mut authoritative_ips = Vec::new();
            for record in ns_lookup.answers() {
                let RData::NS(ns) = &record.data else {
                    continue;
                };
                let host = ns.0.to_utf8();
                if let Ok(ips) = recursive.lookup_ip(host).await {
                    authoritative_ips.extend(ips.iter());
                }
            }
            authoritative_ips.sort_unstable();
            authoritative_ips.dedup();
            if let Ok(mut entries) = cache.lock() {
                entries.insert(zone, (std::time::Instant::now(), authoritative_ips.clone()));
            }
            authoritative_ips
        };
        for ip in authoritative_ips {
            let config =
                ResolverConfig::from_parts(None, vec![], vec![NameServerConfig::udp_and_tcp(ip)]);
            let Ok(resolver) = hickory_resolver::Resolver::builder_with_config(
                config,
                TokioRuntimeProvider::default(),
            )
            .with_options(ResolverOpts::default())
            .build() else {
                continue;
            };
            let Ok(response) = resolver
                .lookup(name.trim_end_matches('.'), RecordType::TXT)
                .await
            else {
                continue;
            };
            for record in response.answers() {
                if let RData::TXT(txt) = &record.data {
                    let joined: String = txt
                        .txt_data
                        .iter()
                        .map(|part| String::from_utf8_lossy(part).into_owned())
                        .collect();
                    if joined == value {
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }
    #[cfg(not(feature = "dns-01"))]
    {
        let _ = (name, value);
        Err(Error::Dns(DnsError::Disabled))
    }
}

/// Check a TXT value using caller-supplied recursive resolvers.
///
/// Resolver entries are `host:port` socket addresses. An empty list keeps the
/// authoritative/system resolver behavior of [`txt_contains_authoritative`].
pub async fn txt_contains_with_resolvers(
    name: &str,
    value: &str,
    resolvers: &[String],
) -> Result<bool> {
    if resolvers.is_empty() {
        return txt_contains_authoritative(name, value).await;
    }
    #[cfg(feature = "dns-01")]
    {
        use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
        use hickory_resolver::net::runtime::TokioRuntimeProvider;
        use hickory_resolver::proto::rr::{RData, RecordType};

        let servers: Vec<_> = resolvers
            .iter()
            .filter_map(|resolver| resolver.parse().ok())
            .map(NameServerConfig::udp_and_tcp)
            .collect();
        if servers.is_empty() {
            return Ok(false);
        }
        let config = ResolverConfig::from_parts(None, vec![], servers);
        let resolver = hickory_resolver::Resolver::builder_with_config(
            config,
            TokioRuntimeProvider::default(),
        )
        .with_options(ResolverOpts::default())
        .build()
        .map_err(|error| Error::Dns(DnsError::Query(format!("resolver build: {error}"))))?;
        let response = resolver
            .lookup(name.trim_end_matches('.'), RecordType::TXT)
            .await
            .map_err(|error| Error::Dns(DnsError::Query(format!("TXT lookup: {error}"))))?;
        Ok(response.answers().iter().any(|record| {
            let RData::TXT(txt) = &record.data else {
                return false;
            };
            let joined: String = txt
                .txt_data
                .iter()
                .map(|part| String::from_utf8_lossy(part))
                .collect();
            joined == value
        }))
    }
    #[cfg(not(feature = "dns-01"))]
    {
        let _ = (name, value, resolvers);
        Err(Error::Dns(DnsError::Disabled))
    }
}

#[cfg(feature = "dns-01")]
fn system_resolver() -> Result<hickory_resolver::TokioResolver> {
    use hickory_resolver::Resolver;
    use hickory_resolver::net::runtime::TokioRuntimeProvider;

    let (config, mut options) = hickory_resolver::system_conf::read_system_conf()
        .map_err(|e| Error::Dns(DnsError::Query(format!("system resolver config: {e}"))))?;
    options.timeout = std::time::Duration::from_secs(5);
    Resolver::builder_with_config(config, TokioRuntimeProvider::default())
        .with_options(options)
        .build()
        .map_err(|e| Error::Dns(DnsError::Query(format!("resolver build: {e}"))))
}

#[cfg(feature = "dns-01")]
async fn soa_exists(resolver: &hickory_resolver::TokioResolver, name: &str) -> bool {
    matches!(
        resolver
            .lookup(
                name.to_string(),
                hickory_resolver::proto::rr::RecordType::SOA,
            )
            .await,
        Ok(response) if !response.answers().is_empty()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_recursive_nameservers_are_normalized() {
        let input = vec!["8.8.8.8.".to_owned(), " 1.1.1.1 ".to_owned()];
        assert_eq!(recursive_nameservers(&input), vec!["8.8.8.8", "1.1.1.1"]);
    }

    #[tokio::test]
    async fn disabled_feature_returns_disabled_error() {
        // The result is correct in both build modes: with the feature enabled
        // this performs a real SOA walk (needs network); without, it reports
        // the disabled error.
        let result = find_zone_by_fqdn("example.com").await;
        #[cfg(feature = "dns-01")]
        let _ = result; // network-dependent; integration test territory
        #[cfg(not(feature = "dns-01"))]
        assert!(matches!(result, Err(Error::Dns(DnsError::Disabled))));
    }
}
