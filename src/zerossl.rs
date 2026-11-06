//! ZeroSSL issuer.
//!
//! ZeroSSL's ACME endpoint requires External Account Binding; the EAB
//! credentials are derived from a ZeroSSL API key via their REST API. This
//! module wires that exchange into a preconfigured [`AcmeIssuer`].

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::acme::AcmeIssuer;
use crate::acme::account::EabCredentials;
use crate::error::{AcmeError, Error, Result};
use crate::issuer::{CertificateResource, Csr, IssuedCertificate, Issuer, RevocationReason};

/// ZeroSSL production ACME directory.
pub const ZEROSSL_PRODUCTION_CA: &str = "https://acme.zerossl.com/v2/DV90";

/// EAB credentials endpoint.
pub const EAB_CREDENTIALS_URL: &str = "https://api.zerossl.com/acme/eab-credentials";
/// ZeroSSL REST API base URL.
pub const ZEROSSL_REST_API_BASE: &str = "https://api.zerossl.com";
/// ZeroSSL's non-standard HTTP validation path prefix.
pub const ZEROSSL_HTTP_VALIDATION_PREFIX: &str = "/.well-known/pki-validation/";

fn http_client() -> Result<reqwest::Client> {
    static CLIENT: std::sync::OnceLock<std::result::Result<reqwest::Client, String>> =
        std::sync::OnceLock::new();
    CLIENT
        .get_or_init(|| {
            crate::tls_integration::install_default_provider();
            reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .user_agent(crate::user_agent())
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|error| error.to_string())
        })
        .clone()
        .map_err(|error| Error::Acme(AcmeError::Http(error)))
}

/// Whether an HTTP request is a ZeroSSL/Sectigo file-validation request.
#[must_use]
pub fn looks_like_zerossl_http_validation(method: &str, path: &str) -> bool {
    method.eq_ignore_ascii_case("GET") && path.starts_with(ZEROSSL_HTTP_VALIDATION_PREFIX)
}

/// Answer a ZeroSSL file-validation request when the caller supplies the
/// validation URL and token obtained from its provider API. This keeps the
/// core path framework-neutral and avoids a global mutable validation map.
#[must_use]
pub fn handle_zerossl_http_validation(
    method: &str,
    request_path: &str,
    validation_url: &str,
    token: &str,
) -> Option<String> {
    if !looks_like_zerossl_http_validation(method, request_path) {
        return None;
    }
    let validation_url = reqwest::Url::parse(validation_url).ok()?;
    let expected = validation_url.path();
    (request_path == expected).then(|| token.to_owned())
}

/// A ZeroSSL-backed issuer: an [`AcmeIssuer`] bound to the ZeroSSL ACME
/// endpoint with API-key-derived EAB.
#[derive(Debug, Clone)]
pub struct ZeroSslIssuer {
    /// The underlying ACME issuer (exposed for configuration).
    pub inner: AcmeIssuer,
}

impl ZeroSslIssuer {
    /// Create the issuer from a ZeroSSL API key: fetches EAB credentials
    /// from the REST API and pre-agrees to the terms (the API key exchange
    /// itself establishes the account relationship).
    ///
    /// # Errors
    /// [`Error::Acme`] when the REST call fails or returns an error body.
    pub async fn new(api_key: &str) -> Result<Self> {
        let eab = fetch_eab(api_key).await?;
        Ok(Self {
            inner: zerossl_issuer_with_eab(eab.key_id, eab.hmac_key),
        })
    }

    /// The underlying issuer, ready to be placed into `ConfigOptions.issuers`.
    #[must_use]
    pub fn into_inner(self) -> AcmeIssuer {
        self.inner
    }
}

/// Builder for the ACME/EAB-based [`ZeroSslIssuer`].
#[derive(Clone, Default)]
pub struct ZeroSslIssuerBuilder {
    api_key: Option<String>,
    email: Option<String>,
    storage: Option<Arc<dyn crate::storage::Storage>>,
}

impl std::fmt::Debug for ZeroSslIssuerBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZeroSslIssuerBuilder")
            .field("email", &self.email)
            .field("api_key_configured", &self.api_key.is_some())
            .finish_non_exhaustive()
    }
}

impl ZeroSslIssuerBuilder {
    /// Create an empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the ZeroSSL API key used to obtain EAB credentials.
    #[must_use]
    pub fn api_key(mut self, api_key: impl Into<String>) -> Self {
        self.api_key = Some(api_key.into());
        self
    }

    /// Set the ACME account contact email.
    #[must_use]
    pub fn email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }

    /// Set the ground-truth storage backend.
    #[must_use]
    pub fn storage(mut self, storage: Arc<dyn crate::storage::Storage>) -> Self {
        self.storage = Some(storage);
        self
    }

    /// Fetch EAB credentials and build the issuer.
    pub async fn build(self) -> Result<ZeroSslIssuer> {
        let api_key = self.api_key.ok_or_else(|| {
            Error::Config(crate::error::ConfigError::Missing(
                "ZeroSSL API key is required".into(),
            ))
        })?;
        let mut issuer = ZeroSslIssuer::new(&api_key).await?;
        issuer.inner.email = self.email;
        issuer.inner.storage = self.storage;
        Ok(issuer)
    }
}

/// ZeroSSL is an issuer in its own right, not merely a builder for an
/// `AcmeIssuer`. Delegate the protocol work while preserving a distinct type
/// for callers that want to select it explicitly.
#[async_trait]
impl Issuer for ZeroSslIssuer {
    async fn issue(
        &self,
        ct: &CancellationToken,
        csr: &Csr,
        attempt: u32,
    ) -> Result<IssuedCertificate> {
        self.inner.issue(ct, csr, attempt).await
    }

    async fn issue_with_replaces(
        &self,
        ct: &CancellationToken,
        csr: &Csr,
        attempt: u32,
        replaces: Option<&str>,
    ) -> Result<IssuedCertificate> {
        self.inner
            .issue_with_replaces(ct, csr, attempt, replaces)
            .await
    }

    fn issuer_key(&self) -> String {
        self.inner.issuer_key()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn pre_check(
        &self,
        ct: &CancellationToken,
        names: &[String],
        interactive: bool,
    ) -> Result<()> {
        self.inner.pre_check(ct, names, interactive).await
    }

    async fn revoke(
        &self,
        ct: &CancellationToken,
        resource: &CertificateResource,
        reason: RevocationReason,
    ) -> Result<()> {
        self.inner.revoke(ct, resource, reason).await
    }

    async fn get_renewal_info(
        &self,
        ct: &CancellationToken,
        cert: &crate::certificate::Certificate,
    ) -> Result<crate::certificate::RenewalInfo> {
        self.inner.get_renewal_info(ct, cert).await
    }
}

#[derive(Debug, Deserialize)]
struct EabResponse {
    #[serde(default)]
    eab_kid: Option<String>,
    #[serde(default)]
    eab_hmac_key: Option<String>,
    #[serde(default)]
    success: Option<Value>,
    #[serde(default)]
    error: Option<serde_json::Value>,
}

async fn fetch_eab(api_key: &str) -> Result<EabCredentials> {
    let mut url = Url::parse(EAB_CREDENTIALS_URL).expect("built-in EAB URL");
    url.query_pairs_mut().append_pair("access_key", api_key);
    let client = http_client()?;
    let resp = client
        .post(url)
        .timeout(std::time::Duration::from_secs(30))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send()
        .await
        .map_err(|e| Error::Acme(AcmeError::Http(e.without_url().to_string())))?;

    let status = resp.status();
    let bytes = crate::http::read_body_limited(resp, crate::http::MAX_JSON_BODY_BYTES).await?;
    let body: EabResponse = serde_json::from_slice(&bytes)
        .map_err(|e| Error::Acme(AcmeError::Http(format!("decode: {e}"))))?;

    if !status.is_success() || !body.valid() {
        let detail = body
            .error
            .as_ref()
            .and_then(|e| e.get("code").and_then(|c| c.as_u64()))
            .map(|code| format!("error code {code} (0 = invalid key, 011 = rate limited)"))
            .unwrap_or_else(|| "unknown ZeroSSL API error".into());
        return Err(Error::Acme(AcmeError::Account(detail)));
    }

    Ok(EabCredentials {
        key_id: body.eab_kid.expect("checked above"),
        hmac_key: body.eab_hmac_key.expect("checked above"),
    })
}

impl EabResponse {
    fn valid(&self) -> bool {
        self.success
            .as_ref()
            .is_some_and(|value| value.as_bool() == Some(true) || value.as_u64() == Some(1))
            && self.error.as_ref().is_none_or(Value::is_null)
            && self
                .eab_kid
                .as_ref()
                .is_some_and(|value| !value.trim().is_empty())
            && self
                .eab_hmac_key
                .as_ref()
                .is_some_and(|value| !value.trim().is_empty())
    }
}

#[cfg(test)]
#[test]
fn certon_eab_success_accepts_documented_integer_and_boolean() {
    for value in [json!(true), json!(1)] {
        let response: EabResponse =
            serde_json::from_value(json!({"success":value,"eab_kid":"kid","eab_hmac_key":"key"}))
                .unwrap();
        assert!(response.valid());
    }
    for value in [json!(false), json!(0), json!(2), json!("1"), Value::Null] {
        let response: EabResponse =
            serde_json::from_value(json!({"success":value,"eab_kid":"kid","eab_hmac_key":"key"}))
                .unwrap();
        assert!(!response.valid());
    }
    for body in [
        json!({"success":1,"eab_kid":"","eab_hmac_key":"key"}),
        json!({"success":1,"eab_kid":"kid","eab_hmac_key":"key","error":{"code":1}}),
    ] {
        assert!(!serde_json::from_value::<EabResponse>(body).unwrap().valid());
    }
}

/// Convenience: build a ZeroSSL issuer synchronously when the EAB
/// credentials are already known (e.g. cached in storage).
#[must_use]
pub fn zerossl_issuer_with_eab(key_id: String, hmac_key: String) -> AcmeIssuer {
    AcmeIssuer {
        ca: ZEROSSL_PRODUCTION_CA.to_owned(),
        eab: Some(EabCredentials { key_id, hmac_key }),
        tos_agreed: true,
        issuer_key_override: Some("zerossl".into()),
        ..AcmeIssuer::default()
    }
}

/// ZeroSSL's REST API issuer.
///
/// This is separate from [`ZeroSslIssuer`]: the latter uses ZeroSSL's ACME
/// directory, while this type follows the REST API's email-validation flow.
/// The certificate private key remains owned by `certmagic`; the issuer only
/// receives the CSR and returns the issued chain plus an API certificate ID.
#[derive(Clone)]
pub struct ZeroSslApiIssuer {
    api_key: String,
    api_base_url: Url,
    validity_days: u32,
    poll_interval: Duration,
    validation_emails: std::collections::BTreeMap<String, String>,
}

impl std::fmt::Debug for ZeroSslApiIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZeroSslApiIssuer")
            .field("api_key", &"[REDACTED]")
            .field(
                "api_base_url",
                &crate::http::diagnostic_endpoint(self.api_base_url.as_str()),
            )
            .field("validity_days", &self.validity_days)
            .field("poll_interval", &self.poll_interval)
            .finish()
    }
}

impl ZeroSslApiIssuer {
    /// Create a REST API issuer with 90-day certificates and a five-second
    /// polling interval.
    #[must_use]
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            api_base_url: Url::parse(ZEROSSL_REST_API_BASE)
                .expect("the built-in ZeroSSL REST API URL must be valid"),
            validity_days: 90,
            poll_interval: Duration::from_secs(5),
            validation_emails: Default::default(),
        }
    }

    /// Use an alternate REST API base URL.
    ///
    /// This is primarily useful for a local contract server in tests. The
    /// API key is still sent as the `access_key` query parameter, so callers
    /// must only use an endpoint they explicitly trust. The production
    /// default remains [`ZEROSSL_REST_API_BASE`].
    pub fn with_api_base_url(mut self, base_url: impl AsRef<str>) -> Result<Self> {
        let base_url = Url::parse(base_url.as_ref()).map_err(|error| {
            Error::Config(crate::error::ConfigError::Invalid(format!(
                "invalid ZeroSSL REST API base URL: {error}"
            )))
        })?;
        let insecure_loopback = base_url.scheme() == "http"
            && matches!(base_url.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
        let valid_scheme = base_url.scheme() == "https" || insecure_loopback;
        if !valid_scheme
            || base_url.host_str().is_none()
            || base_url.username() != ""
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
        {
            return Err(Error::Config(crate::error::ConfigError::Invalid(
                "ZeroSSL REST API base URL must use HTTPS (or loopback HTTP), have a host, no userinfo, query, or fragment".into(),
            )));
        }
        self.api_base_url = base_url;
        Ok(self)
    }

    /// Set the requested certificate validity in days.
    #[must_use]
    pub fn with_validity_days(mut self, days: u32) -> Self {
        self.validity_days = days;
        self
    }

    /// Set the interval between REST API status polls.
    #[must_use]
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// Select an eligible email recipient for a domain. Once configured,
    /// every requested domain must have a selection advertised by the CA.
    /// An empty configuration retains the existing provider-default flow.
    pub fn with_validation_email(
        mut self,
        domain: impl AsRef<str>,
        email: impl AsRef<str>,
    ) -> Result<Self> {
        let domain = crate::certificate::normalized_name(domain.as_ref().trim_end_matches('.'));
        let email = email.as_ref();
        if !crate::certificate::subject_qualifies_for_cert(&domain)
            || !domain.contains('.')
            || email.len() > 254
            || email
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control() || byte == b',')
            || !email.split_once('@').is_some_and(|(local, host)| {
                !local.is_empty() && !host.is_empty() && !host.contains('@')
            })
            || self.validation_emails.contains_key(&domain)
        {
            return Err(Error::Config(crate::error::ConfigError::Invalid(
                "invalid or duplicate ZeroSSL validation recipient".into(),
            )));
        }
        self.validation_emails.insert(domain, email.to_owned());
        Ok(self)
    }

    fn selected_emails(&self, domains: &[String]) -> Result<Option<Vec<String>>> {
        if self.validation_emails.is_empty() {
            return Ok(None);
        }
        domains
            .iter()
            .map(|domain| {
                self.validation_emails
                    .get(&crate::certificate::normalized_name(
                        domain.trim_end_matches('.'),
                    ))
                    .cloned()
                    .ok_or_else(|| {
                        Error::Config(crate::error::ConfigError::Missing(
                            "configure a validation recipient for every requested domain".into(),
                        ))
                    })
            })
            .collect::<Result<Vec<_>>>()
            .map(Some)
    }

    fn endpoint(&self, path: &str) -> String {
        let mut url = self.api_base_url.clone();
        let mut joined = url.path().trim_end_matches('/').to_owned();
        joined.push('/');
        joined.push_str(path.trim_start_matches('/'));
        url.set_path(&joined);
        url.query_pairs_mut()
            .append_pair("access_key", &self.api_key);
        url.into()
    }

    async fn send(
        &self,
        ct: &CancellationToken,
        request: reqwest::RequestBuilder,
    ) -> Result<reqwest::Response> {
        tokio::select! {
            () = ct.cancelled() => Err(Error::Internal("context canceled".into())),
            response = request.timeout(Duration::from_secs(30)).send() => response
                .map_err(|e| Error::Acme(AcmeError::Http(e.without_url().to_string()))),
        }
    }

    async fn response_json(&self, response: reqwest::Response) -> Result<Value> {
        let status = response.status();
        let limit = if status.is_success() {
            crate::http::MAX_JSON_BODY_BYTES
        } else {
            crate::http::MAX_ERROR_BODY_BYTES
        };
        let bytes = crate::http::read_body_limited(response, limit).await?;
        let body: Value = serde_json::from_slice(&bytes)
            .map_err(|e| Error::Acme(AcmeError::Http(format!("ZeroSSL response: {e}"))))?;
        if !status.is_success() {
            return Err(Error::Acme(AcmeError::Http(format!(
                "ZeroSSL REST API returned {status}: {body}"
            ))));
        }
        if let Some(error) = body.get("error").filter(|error| !error.is_null()) {
            return Err(Error::Acme(AcmeError::Account(format!(
                "ZeroSSL REST API error: {error}"
            ))));
        }
        if body
            .get("success")
            .is_some_and(|value| value.as_bool() != Some(true) && value.as_u64() != Some(1))
        {
            return Err(Error::Acme(AcmeError::Account(
                "ZeroSSL API did not confirm success".into(),
            )));
        }
        Ok(body)
    }

    async fn create_certificate(
        &self,
        ct: &CancellationToken,
        csr_pem: &str,
        domains: &[String],
        emails: Option<&[String]>,
    ) -> Result<String> {
        let response = self
            .send(
                ct,
                http_client()?.post(self.endpoint("certificates")).form(&[
                    ("certificate_domains", domains.join(",")),
                    ("certificate_csr", csr_pem.to_owned()),
                    ("certificate_validity_days", self.validity_days.to_string()),
                ]),
            )
            .await?;
        let body = self.response_json(response).await?;
        if let Some(emails) = emails {
            let candidates = body
                .pointer("/validation/email_validation")
                .and_then(Value::as_object)
                .ok_or_else(|| {
                    Error::Acme(AcmeError::Account(
                        "ZeroSSL response omitted eligible validation recipients".into(),
                    ))
                })?;
            for (domain, email) in domains.iter().zip(emails) {
                let name = crate::certificate::normalized_name(domain.trim_end_matches('.'));
                let matches: Vec<_> = candidates
                    .iter()
                    .filter(|(key, _)| {
                        crate::certificate::normalized_name(key.trim_end_matches('.')) == name
                    })
                    .collect();
                if matches.len() != 1
                    || !matches[0].1.as_array().is_some_and(|values| {
                        values.iter().any(|value| value.as_str() == Some(email))
                    })
                {
                    return Err(Error::Acme(AcmeError::Account(
                        "selected ZeroSSL recipient is not uniquely eligible".into(),
                    )));
                }
            }
        }
        body.get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| Error::Acme(AcmeError::Account("ZeroSSL response missing id".into())))
    }

    async fn start_email_validation(
        &self,
        ct: &CancellationToken,
        id: &str,
        emails: Option<&[String]>,
    ) -> Result<()> {
        let mut form = vec![("validation_method", "EMAIL".to_owned())];
        if let Some(emails) = emails {
            form.push(("validation_email", emails.join(",")));
        }
        let response = self
            .send(
                ct,
                http_client()?
                    .post(self.endpoint(&format!("certificates/{id}/challenges")))
                    .form(&form),
            )
            .await?;
        let body = self.response_json(response).await?;
        let has_identity = body.get("id").is_some() || body.get("status").is_some();
        let confirmed = if has_identity {
            body["id"].as_str() == Some(id)
                && matches!(
                    body["status"].as_str(),
                    Some("pending_validation" | "issued")
                )
        } else {
            body["success"].as_bool() == Some(true) || body["success"].as_u64() == Some(1)
        };
        if !confirmed {
            return Err(Error::Acme(AcmeError::Account(
                "ZeroSSL email validation was not confirmed".into(),
            )));
        }
        if let Some(method) = body.get("validation_type").filter(|value| !value.is_null())
            && !method
                .as_str()
                .is_some_and(|method| method.eq_ignore_ascii_case("EMAIL"))
        {
            return Err(Error::Acme(AcmeError::Account(
                "ZeroSSL confirmed a different validation method".into(),
            )));
        }
        if let (Some(emails), Some(confirmed)) = (
            emails,
            body.get("validation_emails")
                .filter(|value| !value.is_null()),
        ) {
            let actual = confirmed.as_str().map(|value| {
                value
                    .split(',')
                    .map(str::trim)
                    .collect::<std::collections::BTreeSet<_>>()
            });
            let expected = emails
                .iter()
                .map(String::as_str)
                .collect::<std::collections::BTreeSet<_>>();
            if actual != Some(expected) {
                return Err(Error::Acme(AcmeError::Account(
                    "ZeroSSL confirmed different validation recipients".into(),
                )));
            }
        }
        Ok(())
    }

    async fn wait_for_issued(&self, ct: &CancellationToken, id: &str) -> Result<()> {
        const MAX_POLLS: usize = 60;
        for _ in 0..MAX_POLLS {
            tokio::select! {
                () = ct.cancelled() => return Err(Error::Internal("context canceled".into())),
                () = tokio::time::sleep(self.poll_interval) => {}
            }
            let response = self
                .send(
                    ct,
                    http_client()?.get(self.endpoint(&format!("certificates/{id}"))),
                )
                .await?;
            let body = self.response_json(response).await?;
            match body
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or_default()
            {
                "issued" => return Ok(()),
                "draft" | "pending_validation" => continue,
                status => {
                    return Err(Error::Acme(AcmeError::Account(format!(
                        "ZeroSSL certificate {id} entered unexpected status {status:?}"
                    ))));
                }
            }
        }
        Err(Error::Acme(AcmeError::Account(
            "timed out waiting for ZeroSSL certificate issuance".into(),
        )))
    }

    async fn download_certificate(&self, ct: &CancellationToken, id: &str) -> Result<Vec<u8>> {
        let response = self
            .send(
                ct,
                http_client()?.get(self.endpoint(&format!("certificates/{id}/download/return"))),
            )
            .await?;
        let body = self.response_json(response).await?;
        let certificate = body
            .get("certificate.crt")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let ca_bundle = body
            .get("ca_bundle.crt")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if certificate.is_empty() {
            return Err(Error::Acme(AcmeError::Account(
                "ZeroSSL download response missing certificate.crt".into(),
            )));
        }
        Ok(format!("{certificate}{ca_bundle}").into_bytes())
    }
}

#[async_trait]
impl Issuer for ZeroSslApiIssuer {
    async fn issue(
        &self,
        ct: &CancellationToken,
        csr: &Csr,
        _attempt: u32,
    ) -> Result<IssuedCertificate> {
        if csr.dns_names.is_empty() {
            return Err(Error::Issuer(crate::error::IssuerError::Other(
                "ZeroSSL REST API requires at least one DNS name".into(),
            )));
        }
        let csr_pem = crate::pem::encode("CERTIFICATE REQUEST", &csr.der);
        let emails = self.selected_emails(&csr.dns_names)?;
        let certificate_id = self
            .create_certificate(
                ct,
                &String::from_utf8_lossy(&csr_pem),
                &csr.dns_names,
                emails.as_deref(),
            )
            .await?;
        self.start_email_validation(ct, &certificate_id, emails.as_deref())
            .await?;
        self.wait_for_issued(ct, &certificate_id).await?;
        let certificate = self.download_certificate(ct, &certificate_id).await?;
        Ok(IssuedCertificate {
            certificate,
            metadata: Some(json!({
                "issuer": "zerossl-api",
                "certificate_id": certificate_id,
            })),
        })
    }

    fn issuer_key(&self) -> String {
        "zerossl-api".into()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn revoke(
        &self,
        ct: &CancellationToken,
        resource: &CertificateResource,
        reason: RevocationReason,
    ) -> Result<()> {
        let certificate_id = resource
            .issuer_data
            .as_ref()
            .and_then(|data| data.get("certificate_id"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                Error::Issuer(crate::error::IssuerError::Other(
                    "ZeroSSL metadata has no certificate_id".into(),
                ))
            })?;
        let response = self
            .send(
                ct,
                http_client()?
                    .post(self.endpoint(&format!("certificates/{certificate_id}/revoke")))
                    .form(&[("reason", (reason as u8).to_string())]),
            )
            .await?;
        self.response_json(response).await.map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn review_zerossl_builder_debug_redacts_api_key() {
        let builder = ZeroSslIssuerBuilder::new().api_key("private-api-secret");
        assert!(!format!("{builder:?}").contains("private-api-secret"));
    }

    #[test]
    fn zero_ssl_validation_matches_provider_path() {
        assert_eq!(
            handle_zerossl_http_validation(
                "GET",
                "/.well-known/pki-validation/file.txt",
                "https://example.com/.well-known/pki-validation/file.txt",
                "credential"
            )
            .as_deref(),
            Some("credential")
        );
        assert!(
            handle_zerossl_http_validation(
                "POST",
                "/.well-known/pki-validation/file.txt",
                "https://example.com/.well-known/pki-validation/file.txt",
                "credential"
            )
            .is_none()
        );
    }

    #[test]
    fn api_issuer_redacts_credentials_and_has_stable_key() {
        let issuer = ZeroSslApiIssuer::new("secret-api-key");
        let debug = format!("{issuer:?}");
        assert!(!debug.contains("secret-api-key"));
        assert_eq!(issuer.issuer_key(), "zerossl-api");
    }
}
