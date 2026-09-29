//! ACME directory discovery (RFC 8555 §7.1.1).

use serde::Deserialize;

use crate::error::{AcmeError, Error, Result};

/// The CA's directory: endpoint URLs plus useful metadata.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct Directory {
    /// New nonce endpoint (may also be `HEAD`/`GET`-able elsewhere).
    #[serde(rename = "newNonce")]
    pub new_nonce: Option<String>,
    /// New account endpoint.
    #[serde(rename = "newAccount")]
    pub new_account: Option<String>,
    /// New order endpoint.
    #[serde(rename = "newOrder")]
    pub new_order: Option<String>,
    /// New pre-authorization endpoint (rarely used).
    #[serde(rename = "newAuthz")]
    pub new_authz: Option<String>,
    /// Revocation endpoint.
    #[serde(rename = "revokeCert")]
    pub revoke_cert: Option<String>,
    /// Key rollover endpoint.
    #[serde(rename = "keyChange")]
    pub key_change: Option<String>,
    /// ARI renewal info endpoint (draft-ietf-acme-ari).
    #[serde(rename = "renewalInfo")]
    pub renewal_info: Option<String>,
    /// Directory metadata.
    #[serde(default)]
    pub meta: Option<DirectoryMeta>,
}

/// Directory metadata (RFC 8555 §7.1.1 `meta`).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct DirectoryMeta {
    /// Terms of service URL.
    #[serde(rename = "termsOfService")]
    pub terms_of_service: Option<String>,
    /// Website of the CA.
    #[serde(default)]
    pub website: Option<String>,
    /// CA name.
    #[serde(default)]
    pub caa_identities: Vec<String>,
    /// Whether EAB is required for new accounts.
    #[serde(rename = "externalAccountRequired", default)]
    pub external_account_required: bool,
    /// Available certificate profiles (draft-aaron-acme-profiles): the
    /// newer spec serializes these as a map of name → descriptor, while the
    /// earlier draft used a plain array of names — accept both.
    #[serde(default, deserialize_with = "deserialize_profiles")]
    pub profiles: ProfileList,
}

/// Profile list: tolerant of both the object form (name → descriptor) and
/// the legacy array-of-names form.
#[derive(Debug, Clone, Default)]
pub struct ProfileList(pub Vec<String>);

fn deserialize_profiles<'de, D>(deserializer: D) -> Result<ProfileList, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    let Some(value) = value else {
        return Ok(ProfileList::default());
    };
    match value {
        serde_json::Value::Array(items) => Ok(ProfileList(
            items
                .into_iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect(),
        )),
        serde_json::Value::Object(map) => Ok(ProfileList(map.keys().cloned().collect())),
        _ => Ok(ProfileList::default()),
    }
}

impl Directory {
    /// Fetch the directory from `directory_url`.
    ///
    /// # Errors
    /// [`Error::Acme`] on transport failure or non-JSON body.
    pub async fn fetch(
        transport: &dyn super::transport::Transport,
        directory_url: &str,
    ) -> Result<Self> {
        let resp = transport
            .execute(super::transport::HttpRequest {
                method: super::transport::Method::Get,
                url: directory_url.to_owned(),
                body: None,
                content_type: None,
                accept: Some("application/json".into()),
            })
            .await?;
        if !resp.is_success() {
            return Err(Error::Acme(AcmeError::Directory(format!(
                "directory fetch returned HTTP {}",
                resp.status
            ))));
        }
        serde_json::from_slice(&resp.body)
            .map_err(|e| Error::Acme(AcmeError::Directory(format!("invalid JSON: {e}"))))
    }

    /// The newAccount endpoint.
    ///
    /// # Errors
    /// `AcmeError::MissingEndpoint` when absent.
    pub fn new_account(&self) -> Result<&str> {
        self.new_account
            .as_deref()
            .ok_or_else(missing("newAccount"))
    }

    /// The newOrder endpoint.
    ///
    /// # Errors
    /// `AcmeError::MissingEndpoint` when absent.
    pub fn new_order(&self) -> Result<&str> {
        self.new_order.as_deref().ok_or_else(missing("newOrder"))
    }

    /// The newNonce endpoint.
    ///
    /// # Errors
    /// `AcmeError::MissingEndpoint` when absent.
    pub fn new_nonce(&self) -> Result<&str> {
        self.new_nonce.as_deref().ok_or_else(missing("newNonce"))
    }

    /// The revokeCert endpoint.
    ///
    /// # Errors
    /// `AcmeError::MissingEndpoint` when absent.
    pub fn revoke_cert(&self) -> Result<&str> {
        self.revoke_cert
            .as_deref()
            .ok_or_else(missing("revokeCert"))
    }

    /// The renewalInfo endpoint (ARI).
    ///
    /// # Errors
    /// `AcmeError::MissingEndpoint` when absent.
    pub fn renewal_info(&self) -> Result<&str> {
        self.renewal_info
            .as_deref()
            .ok_or_else(missing("renewalInfo"))
    }
}

fn missing(name: &str) -> impl Fn() -> Error + '_ {
    move || Error::Acme(AcmeError::MissingEndpoint(name.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acme::transport::{HttpRequest, HttpResponse};
    use async_trait::async_trait;
    use std::sync::Arc;

    #[derive(Debug)]
    struct StaticTransport(HttpResponse);

    #[async_trait]
    impl crate::acme::transport::Transport for StaticTransport {
        async fn execute(&self, _req: HttpRequest) -> Result<HttpResponse> {
            Ok(self.0.clone())
        }
    }

    #[tokio::test]
    async fn parses_directory_json() {
        let body = br#"{
            "newNonce": "https://ca/nnonce",
            "newAccount": "https://ca/nacct",
            "newOrder": "https://ca/norder",
            "revokeCert": "https://ca/revoke",
            "keyChange": "https://ca/kc",
            "renewalInfo": "https://ca/ri",
            "meta": {"termsOfService": "https://ca/tos", "externalAccountRequired": true}
        }"#;
        let transport = StaticTransport(HttpResponse {
            status: 200,
            headers: Default::default(),
            body: body.to_vec(),
        });
        let dir = Directory::fetch(&transport, "https://ca/directory")
            .await
            .unwrap();
        assert_eq!(dir.new_order().unwrap(), "https://ca/norder");
        assert_eq!(dir.renewal_info().unwrap(), "https://ca/ri");
        assert!(dir.meta.as_ref().unwrap().external_account_required);
        assert_eq!(
            dir.meta.as_ref().unwrap().terms_of_service.as_deref(),
            Some("https://ca/tos")
        );
        let _ = Arc::new(());
    }

    #[tokio::test]
    async fn missing_endpoint_is_reported() {
        let dir = Directory::default();
        assert!(matches!(
            dir.new_order(),
            Err(Error::Acme(AcmeError::MissingEndpoint(_)))
        ));
    }
}
