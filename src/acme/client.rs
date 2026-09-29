//! The ACME protocol client: directory + nonce pool + account + order
//! operations over a [`Transport`].

use std::time::Duration;

use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

use crate::acme::account::{Account, EabCredentials, external_account_binding};
use crate::acme::directory::Directory;
use crate::acme::nonce::NoncePool;
use crate::acme::order::{
    Order, RenewalInfoResponse, ari_cert_id, new_order_body_with_options, poll_until,
};
use crate::acme::protocol::JWS_CONTENT_TYPE;
use crate::acme::transport::{HttpRequest, HttpResponse, Method, Transport};
use crate::error::{AcmeError, Error, Result};

/// A directory-bound ACME client bound to one account key.
pub struct AcmeClient {
    pub(crate) transport: std::sync::Arc<dyn Transport>,
    pub(crate) directory: Directory,
    pub(crate) nonces: NoncePool,
    /// Registered account, once available.
    pub account: Option<Account>,
    pub(crate) rate_limiter: Option<std::sync::Arc<crate::ratelimiter::RingBufferRateLimiter>>,
}

impl std::fmt::Debug for AcmeClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcmeClient")
            .field("directory", &"<endpoints>")
            .field(
                "registered",
                &self.account.as_ref().map(|a| a.is_registered()),
            )
            .finish()
    }
}

impl AcmeClient {
    /// Fetch the directory and construct a client.
    ///
    /// # Errors
    /// Propagates [`Directory::fetch`].
    pub async fn connect(
        transport: std::sync::Arc<dyn Transport>,
        directory_url: &str,
    ) -> Result<Self> {
        let directory = Directory::fetch(transport.as_ref(), directory_url).await?;
        Ok(Self {
            transport,
            directory,
            nonces: NoncePool::new(),
            account: None,
            rate_limiter: None,
        })
    }

    /// Adopt an already-registered account (e.g. loaded from storage).
    #[must_use]
    pub fn with_account(mut self, account: Account) -> Self {
        self.account = Some(account);
        self
    }

    /// Attach a shared sliding-window limiter to ACME POST requests.
    #[must_use]
    pub fn with_rate_limiter(
        mut self,
        limiter: std::sync::Arc<crate::ratelimiter::RingBufferRateLimiter>,
    ) -> Self {
        self.rate_limiter = Some(limiter);
        self
    }

    /// Register (or look up) an account at `newAccount` and bind it.
    ///
    /// - `tos_agreed` sets `termsOfServiceAgreed`; interactive callers can use
    ///   [`crate::acme::prompt_user_agreement`] before invoking this method.
    /// - `eab` attaches external account binding when the CA requires it.
    /// - `only_return_existing` performs the account-by-key lookup.
    ///
    /// On success the client holds the registered account.
    ///
    /// # Errors
    /// [`Error::Acme`] on transport/protocol problems.
    pub async fn register_account(
        &mut self,
        contacts: &[String],
        tos_agreed: bool,
        eab: Option<&EabCredentials>,
        only_return_existing: bool,
        ct: &CancellationToken,
    ) -> Result<Account> {
        let key = match self.account.as_ref() {
            Some(a) => a.key.clone(),
            None => crate::acme::protocol::AccountKey::generate_es256()?,
        };
        self.register_account_with_key(&key, contacts, tos_agreed, eab, only_return_existing, ct)
            .await
    }

    /// [`Self::register_account`] with an explicit account key (used when
    /// the key is loaded from storage).
    ///
    /// # Errors
    /// See [`Self::register_account`].
    pub async fn register_account_with_key(
        &mut self,
        key: &crate::acme::protocol::AccountKey,
        contacts: &[String],
        tos_agreed: bool,
        eab: Option<&EabCredentials>,
        only_return_existing: bool,
        ct: &CancellationToken,
    ) -> Result<Account> {
        let url = self.directory.new_account()?.to_owned();

        let mut body = json!({ "contact": contacts, "termsOfServiceAgreed": tos_agreed });
        if only_return_existing {
            body = json!({ "onlyReturnExisting": true });
        }
        if let Some(eab) = eab {
            body["externalAccountBinding"] = external_account_binding(eab, key, &url)?;
        }

        // New-account JWS uses `jwk` instead of `kid`.
        let resp = self
            .post_jws_retried(key, &url, None, Some(&body), ct)
            .await?;

        if let Some(problem) = crate::acme::problem::problem_from_response(&resp) {
            return Err(problem.into_error());
        }
        if !(resp.is_success() && (200..=201).contains(&resp.status)) {
            return Err(Error::Acme(AcmeError::Account(format!(
                "unexpected status {} registering account",
                resp.status
            ))));
        }
        let account_url = resp.location().ok_or_else(|| {
            Error::Acme(AcmeError::Account(
                "newAccount response missing Location header".into(),
            ))
        })?;

        let info: crate::acme::account::AccountInfo = if resp.body.is_empty() {
            Default::default()
        } else {
            serde_json::from_slice(&resp.body).unwrap_or_default()
        };

        let account = Account {
            key: key.clone(),
            url: account_url.to_owned(),
            contacts: info.contact,
            status: info.status,
            terms_of_service_agreed: info.terms_of_service_agreed || tos_agreed,
        };
        self.account = Some(account.clone());
        Ok(account)
    }

    /// Update an existing account's contact URIs and return the server view.
    pub async fn update_account(
        &mut self,
        contacts: &[String],
        ct: &CancellationToken,
    ) -> Result<Account> {
        let account = self.account()?.clone();
        let response = self
            .post_jws_retried(
                &account.key,
                &account.url,
                Some(&account.url),
                Some(&json!({ "contact": contacts })),
                ct,
            )
            .await?;
        if let Some(problem) = crate::acme::problem::problem_from_response(&response) {
            return Err(problem.into_error());
        }
        if !response.is_success() {
            return Err(Error::Acme(AcmeError::Account(format!(
                "unexpected status {} updating account",
                response.status
            ))));
        }
        let info: crate::acme::account::AccountInfo = if response.body.is_empty() {
            Default::default()
        } else {
            serde_json::from_slice(&response.body).unwrap_or_default()
        };
        let updated = Account {
            key: account.key,
            url: account.url,
            contacts: if info.contact.is_empty() {
                contacts.to_vec()
            } else {
                info.contact
            },
            status: info.status,
            terms_of_service_agreed: info.terms_of_service_agreed
                || account.terms_of_service_agreed,
        };
        self.account = Some(updated.clone());
        Ok(updated)
    }

    /// Revoke a certificate given as a PEM chain (leaf first)
    /// (RFC 8555 §7.6).
    ///
    /// # Errors
    /// Propagates protocol errors; non-2xx become problem errors.
    pub async fn revoke_pem(
        &self,
        cert_pem: &[u8],
        reason: Option<u8>,
        ct: &CancellationToken,
    ) -> Result<()> {
        use base64::Engine as _;
        let url = self.directory.revoke_cert()?.to_owned();
        let section =
            crate::pem::first_section_with_label(cert_pem, &["CERTIFICATE"]).ok_or_else(|| {
                Error::Certificate(crate::error::CertificateError::Parse(
                    "no certificate PEM".into(),
                ))
            })?;
        let mut body = json!({ "certificate": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&section.der) });
        if let Some(r) = reason {
            body["reason"] = json!(r);
        }
        let resp = self.jws_post(&url, Some(&body), ct).await?;
        if let Some(problem) = crate::acme::problem::problem_from_response(&resp) {
            return Err(problem.into_error());
        }
        Ok(())
    }

    /// The bound, registered account.
    ///
    /// # Errors
    /// [`Error::Acme`] when no registered account is bound.
    pub fn account(&self) -> Result<&Account> {
        self.account
            .as_ref()
            .filter(|a| a.is_registered())
            .ok_or_else(|| Error::Acme(AcmeError::Account("account not registered".into())))
    }

    /// POST-as-GET a resource URL (RFC 8555 §6.3): empty JWS payload.
    ///
    /// # Errors
    /// Propagates [`Self::jws_post`].
    pub async fn post_as_get(&self, url: &str, ct: &CancellationToken) -> Result<HttpResponse> {
        self.jws_post(url, None, ct).await
    }

    /// Signed JWS POST with transparent badNonce retry (RFC 8555 §6.5):
    /// on `urn:...:badNonce` the request is re-signed with a fresh nonce.
    ///
    /// # Errors
    /// Non-badNonce problems are returned as `AcmeError::Problem`;
    /// repeated badNonce failures give [`AcmeError::Nonce`].
    pub async fn jws_post(
        &self,
        url: &str,
        payload: Option<&Value>,
        ct: &CancellationToken,
    ) -> Result<HttpResponse> {
        let account = self.account()?;
        self.post_jws_retried(&account.key, url, Some(&account.url), payload, ct)
            .await
    }

    /// Sign + POST with transparent badNonce retry (RFC 8555 §6.5), shared by
    /// the `kid` (existing account) and `jwk` (new account) header paths.
    async fn post_jws_retried(
        &self,
        key: &crate::acme::protocol::AccountKey,
        url: &str,
        kid: Option<&str>,
        payload: Option<&Value>,
        ct: &CancellationToken,
    ) -> Result<HttpResponse> {
        const MAX_ATTEMPTS: usize = 3;
        let mut nonce = self
            .nonces
            .take_or_fetch(ct, self.transport.as_ref(), self.directory.new_nonce()?)
            .await?;

        for attempt in 0..MAX_ATTEMPTS {
            if let Some(limiter) = &self.rate_limiter {
                limiter.wait(ct).await?;
            }
            let jws = key.sign_jws(url, &nonce, kid, payload)?;
            let resp = self.post_raw(url, &jws).await?;

            // Harvest the next nonce from every response.
            if let Some(next) = resp.nonce() {
                self.nonces.supply(next);
            }

            if let Some(problem) = crate::acme::problem::problem_from_response(&resp) {
                if problem.is_bad_nonce() && attempt + 1 < MAX_ATTEMPTS {
                    tracing::debug!(url, "badNonce; retrying with a fresh one");
                    nonce = self
                        .nonces
                        .fetch_fresh(ct, self.transport.as_ref(), self.directory.new_nonce()?)
                        .await?;
                    continue;
                }
                return Err(problem.into_error());
            }
            return Ok(resp);
        }
        Err(Error::Acme(AcmeError::Nonce(
            "exhausted badNonce retries".into(),
        )))
    }

    async fn post_raw(&self, url: &str, jws: &Value) -> Result<HttpResponse> {
        let body = serde_json::to_vec(jws)
            .map_err(|e| Error::Acme(AcmeError::Jws(format!("serialize: {e}"))))?;
        self.transport
            .execute(HttpRequest {
                method: Method::Post,
                url: url.to_owned(),
                body: Some(body),
                content_type: Some(format!("application/{JWS_CONTENT_TYPE}")),
                accept: Some("application/json".into()),
            })
            .await
    }

    /// Create a new order; returns the order body and its URL.
    ///
    /// # Errors
    /// Propagates protocol errors.
    pub async fn new_order(
        &self,
        identifiers: &[crate::acme::order::Identifier],
        not_before: Option<time::OffsetDateTime>,
        not_after: Option<time::OffsetDateTime>,
        ct: &CancellationToken,
    ) -> Result<(Order, String)> {
        self.new_order_with_options(identifiers, not_before, not_after, None, None, ct)
            .await
    }

    /// Create a new order with profile and ARI replacement options.
    pub async fn new_order_with_options(
        &self,
        identifiers: &[crate::acme::order::Identifier],
        not_before: Option<time::OffsetDateTime>,
        not_after: Option<time::OffsetDateTime>,
        profile: Option<&str>,
        replaces: Option<&str>,
        ct: &CancellationToken,
    ) -> Result<(Order, String)> {
        let url = self.directory.new_order()?.to_owned();
        let resp = self
            .jws_post(
                &url,
                Some(&new_order_body_with_options(
                    identifiers,
                    not_before,
                    not_after,
                    profile,
                    replaces,
                )),
                ct,
            )
            .await?;
        let order: Order = serde_json::from_slice(&resp.body)
            .map_err(|e| Error::Acme(AcmeError::Order(format!("decode: {e}"))))?;
        let order_url = resp
            .location()
            .ok_or_else(|| Error::Acme(AcmeError::Order("newOrder missing Location".into())))?;
        Ok((order, order_url.to_owned()))
    }

    /// Fetch an authorization by URL.
    ///
    /// # Errors
    /// Propagates protocol errors.
    pub async fn authorization(
        &self,
        url: &str,
        ct: &CancellationToken,
    ) -> Result<crate::acme::order::Authorization> {
        let resp = self.post_as_get(url, ct).await?;
        #[cfg(test)]
        eprintln!("DBG authz body: {}", String::from_utf8_lossy(&resp.body));
        serde_json::from_slice(&resp.body).map_err(|e| {
            Error::Acme(AcmeError::Authorization(format!(
                "decode: {e}\nbody: {}",
                String::from_utf8_lossy(&resp.body)
            )))
        })
    }

    /// Trigger challenge validation by POSTing `{}` to the challenge URL.
    ///
    /// # Errors
    /// Propagates protocol errors.
    pub async fn trigger_challenge(
        &self,
        challenge_url: &str,
        ct: &CancellationToken,
    ) -> Result<crate::acme::order::Challenge> {
        let resp = self.jws_post(challenge_url, Some(&json!({})), ct).await?;
        serde_json::from_slice(&resp.body)
            .map_err(|e| Error::Acme(AcmeError::Challenge(format!("decode: {e}"))))
    }

    /// Poll an order until it reaches `ready` (all authorizations satisfied),
    /// `valid`, or `invalid`.
    ///
    /// # Errors
    /// [`AcmeError::Order`] on timeout; propagates protocol errors.
    pub async fn wait_for_order_ready(
        &self,
        order_url: &str,
        timeout: Duration,
        ct: &CancellationToken,
    ) -> Result<Order> {
        poll_until(
            || async {
                let order = self.order(order_url, ct).await?;
                let done = order.is_terminal() || order.status == "ready";
                Ok((order, done))
            },
            timeout,
            ct,
        )
        .await
    }

    /// Fetch the current order state.
    ///
    /// # Errors
    /// Propagates protocol errors.
    pub async fn order(&self, url: &str, ct: &CancellationToken) -> Result<Order> {
        let resp = self.post_as_get(url, ct).await?;
        serde_json::from_slice(&resp.body)
            .map_err(|e| Error::Acme(AcmeError::Order(format!("decode: {e}"))))
    }

    /// Submit the CSR and return the updated order (usually `processing`).
    ///
    /// # Errors
    /// Propagates protocol errors.
    pub async fn finalize(
        &self,
        finalize_url: &str,
        csr_der: &[u8],
        ct: &CancellationToken,
    ) -> Result<Order> {
        use base64::Engine as _;
        let body =
            json!({ "csr": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(csr_der) });
        let resp = self.jws_post(finalize_url, Some(&body), ct).await?;
        serde_json::from_slice(&resp.body)
            .map_err(|e| Error::Acme(AcmeError::Order(format!("decode: {e}"))))
    }

    /// Download the certificate chain (PEM, leaf first).
    ///
    /// # Errors
    /// [`Error::Acme`] when the body is not a PEM chain.
    pub async fn download_chain(&self, url: &str, ct: &CancellationToken) -> Result<Vec<u8>> {
        self.download_chain_candidates(url, ct)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| Error::Acme(AcmeError::Order("certificate chain missing".into())))
    }

    /// Download the primary certificate chain and any RFC 8555 alternate
    /// chains advertised through `Link: rel="alternate"`.
    pub async fn download_chain_candidates(
        &self,
        url: &str,
        ct: &CancellationToken,
    ) -> Result<Vec<Vec<u8>>> {
        let resp = self.post_as_get(url, ct).await?;
        if !resp.is_success() {
            if let Some(problem) = crate::acme::problem::problem_from_response(&resp) {
                return Err(problem.into_error());
            }
            return Err(Error::Acme(AcmeError::Order(format!(
                "certificate download returned HTTP {}",
                resp.status
            ))));
        }
        if crate::pem::sections(&resp.body).is_empty() {
            return Err(Error::Acme(AcmeError::Order(
                "certificate download returned no PEM".into(),
            )));
        }
        let alternate_links = resp.header("link").map(str::to_owned);
        let mut chains = vec![resp.body];
        if let Some(links) = alternate_links.as_deref() {
            for link in links.split(',') {
                let Some(start) = link.find('<') else {
                    continue;
                };
                let Some(end) = link[start + 1..].find('>') else {
                    continue;
                };
                let target = &link[start + 1..start + 1 + end];
                if !link[start + 1 + end..].contains("alternate") {
                    continue;
                }
                let alternate = self.post_as_get(target, ct).await?;
                if alternate.is_success() && !crate::pem::sections(&alternate.body).is_empty() {
                    chains.push(alternate.body);
                }
            }
        }
        Ok(chains)
    }

    /// Fetch ARI renewal info for a certificate
    /// (`issuer_spki`: issuing certificate's SubjectPublicKeyInfo DER;
    /// `serial_der`: leaf serial).
    ///
    /// # Errors
    /// [`AcmeError::MissingEndpoint`] when the CA does not advertise ARI.
    pub async fn renewal_info(
        &self,
        issuer_spki: &[u8],
        serial_der: &[u8],
        ct: &CancellationToken,
    ) -> Result<RenewalInfoResponse> {
        let base = self.directory.renewal_info()?.trim_end_matches('/');
        let url = format!("{base}/{}", ari_cert_id(issuer_spki, serial_der));
        let resp = self.post_as_get(&url, ct).await?;
        if let Some(problem) = crate::acme::problem::problem_from_response(&resp) {
            return Err(problem.into_error());
        }
        serde_json::from_slice(&resp.body)
            .map_err(|e| Error::Acme(AcmeError::Order(format!("ARI decode: {e}"))))
    }

    /// Poll an order until it is `valid` or `invalid`, with 500 ms → 5 s
    /// exponential pacing.
    ///
    /// # Errors
    /// [`AcmeError::Order`] on timeout/invalid; propagates protocol errors.
    pub async fn wait_for_order(
        &self,
        order_url: &str,
        timeout: Duration,
        ct: &CancellationToken,
    ) -> Result<Order> {
        poll_until(
            || async {
                let order = self.order(order_url, ct).await?;
                let done = order.is_terminal();
                Ok((order, done))
            },
            timeout,
            ct,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acme::transport::{HttpRequest, HttpResponse};
    use async_trait::async_trait;
    use base64::Engine as _;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A scripted CA for protocol tests.
    #[derive(Debug, Default)]
    struct MockCa {
        requests: AtomicUsize,
    }

    #[async_trait]
    impl Transport for MockCa {
        async fn execute(&self, req: HttpRequest) -> Result<HttpResponse> {
            let n = self.requests.fetch_add(1, Ordering::SeqCst);
            let mut headers = HashMap::new();
            headers.insert("replay-nonce".to_string(), format!("n{n}"));

            match (req.method, req.url.as_str()) {
                (Method::Get, "https://ca/directory") => Ok(HttpResponse {
                    status: 200,
                    headers,
                    body: br#"{"newNonce":"https://ca/new-nonce","newAccount":"https://ca/new-account","newOrder":"https://ca/new-order","renewalInfo":"https://ca/renewal-info/"}"#.to_vec(),
                }),
                (Method::Get, "https://ca/new-nonce") => Ok(HttpResponse {
                    status: 200,
                    headers,
                    body: Vec::new(),
                }),
                (Method::Post, "https://ca/new-account") => {
                    // Decode the JWS to verify structure.
                    let jws: Value = serde_json::from_slice(req.body.as_deref().unwrap()).unwrap();
                    let protected: Value = serde_json::from_slice(
                        &base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .decode(jws["protected"].as_str().unwrap())
                            .unwrap(),
                    )
                    .unwrap();
                    assert!(protected["jwk"].is_object(), "newAccount uses jwk header");
                    headers.insert("location".into(), "https://ca/acct/1".into());
                    Ok(HttpResponse {
                        status: 201,
                        headers,
                        body: br#"{"status":"valid","contact":["mailto:a@b.c"]}"#.to_vec(),
                    })
                }
                (Method::Post, "https://ca/new-order") => {
                    assert_eq!(
                        req.content_type.as_deref(),
                        Some("application/jose+json"),
                        "ACME POSTs must use the JWS content type"
                    );
                    assert_eq!(req.accept.as_deref(), Some("application/json"));
                    let jws: Value = serde_json::from_slice(req.body.as_deref().unwrap()).unwrap();
                    let body: Value = serde_json::from_slice(
                        &base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .decode(jws["payload"].as_str().unwrap())
                            .unwrap(),
                    )
                    .unwrap();
                    assert_eq!(body["identifiers"][0]["type"], "dns");
                    assert_eq!(body["identifiers"][0]["value"], "example.com");
                    assert_eq!(body["profile"], "tlsserver");
                    assert_eq!(body["replaces"], "https://ca/cert/previous");
                    headers.insert("location".into(), "https://ca/order/1".into());
                    Ok(HttpResponse {
                        status: 201,
                        headers,
                        body: br#"{"status":"pending","authorizations":["https://ca/authz1"],"finalize":"https://ca/finalize"}"#.to_vec(),
                    })
                }
                (Method::Post, "https://ca/authz1") => Ok(HttpResponse {
                    status: 200,
                    headers,
                    body: br#"{"identifier":{"type":"dns","value":"example.com"},"status":"pending","challenges":[{"type":"dns-01","token":"tok","url":"https://ca/chal1","status":"pending"}]}"#.to_vec(),
                }),
                (Method::Post, "https://ca/chal1") => Ok(HttpResponse {
                    status: 200,
                    headers,
                    body: br#"{"type":"dns-01","token":"tok","url":"https://ca/chal1","status":"valid"}"#.to_vec(),
                }),
                (Method::Post, "https://ca/finalize") => Ok(HttpResponse {
                    status: 200,
                    headers,
                    body: br#"{"status":"valid","certificate":"https://ca/cert"}"#.to_vec(),
                }),
                (Method::Post, "https://ca/order/1") => Ok(HttpResponse {
                    status: 200,
                    headers,
                    body: br#"{"status":"valid","certificate":"https://ca/cert"}"#.to_vec(),
                }),
                (Method::Post, "https://ca/cert") => Ok(HttpResponse {
                    status: 200,
                    headers,
                    body: b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n".to_vec(),
                }),
                (Method::Post, u) if u.starts_with("https://ca/renewal-info/") => {
                    assert_eq!(
                        u,
                        "https://ca/renewal-info/aXNzdWVyLXNwa2k.AQID",
                        "ARI certID must be encoded in the request path"
                    );
                    Ok(HttpResponse {
                        status: 200,
                        headers,
                        body: br#"{"suggestedWindow":{"start":"2026-09-28T00:00:00Z","end":"2026-09-30T00:00:00Z"},"explanationURL":"https://ca/ari","retryAfter":60}"#.to_vec(),
                    })
                }
                _ => Ok(HttpResponse {
                    status: 404,
                    headers,
                    body: br#"{"type":"urn:ietf:params:acme:error:malformed"}"#.to_vec(),
                }),
            }
        }
    }

    #[tokio::test]
    async fn full_order_flow_with_mock_ca() {
        let ca = Arc::new(MockCa::default());
        let mut client = AcmeClient::connect(ca, "https://ca/directory")
            .await
            .unwrap();

        // Register an account (jwk-protected JWS).
        let account = client
            .register_account(
                &["mailto:a@b.c".into()],
                true,
                None,
                false,
                &CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(account.url, "https://ca/acct/1");
        assert!(client.account().is_ok());

        // New order.
        let (order, order_url) = client
            .new_order_with_options(
                &["example.com".into()],
                None,
                None,
                Some("tlsserver"),
                Some("https://ca/cert/previous"),
                &CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(order.status, "pending");

        // Authorization + challenge.
        let authz = client
            .authorization(&order.authorizations[0], &CancellationToken::new())
            .await
            .unwrap();
        let chal = authz.challenge("dns-01").unwrap();
        assert_eq!(chal.token, "tok");
        let key_auth = chal
            .key_authorization(&client.account().unwrap().key)
            .unwrap();
        assert!(key_auth.starts_with("tok."));
        let triggered = client
            .trigger_challenge(&chal.url, &CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(triggered.status, "valid");

        // Finalize + wait + download.
        let finalized = client
            .finalize("https://ca/finalize", b"CSR-DER", &CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(finalized.status, "valid");
        let done = client
            .wait_for_order(
                &order_url,
                Duration::from_secs(5),
                &CancellationToken::new(),
            )
            .await
            .unwrap();
        let chain = client
            .download_chain(
                done.certificate.as_deref().unwrap(),
                &CancellationToken::new(),
            )
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&chain).contains("BEGIN CERTIFICATE"));
    }

    #[tokio::test]
    async fn ari_roundtrip_with_cert_id_in_url() {
        let ca = Arc::new(MockCa::default());
        let mut client = AcmeClient::connect(ca, "https://ca/directory")
            .await
            .unwrap();
        client
            .register_account(&[], true, None, false, &CancellationToken::new())
            .await
            .unwrap();
        let info = client
            .renewal_info(b"issuer-spki", &[1, 2, 3], &CancellationToken::new())
            .await
            .unwrap();
        let (start, end) = info.window().unwrap();
        assert!(end > start);
    }

    #[tokio::test]
    async fn bad_nonce_is_retried() {
        // A CA that rejects the first POST with badNonce then accepts.
        #[derive(Debug, Default)]
        struct BadOnceCa(AtomicUsize);
        #[async_trait]
        impl Transport for BadOnceCa {
            async fn execute(&self, req: HttpRequest) -> Result<HttpResponse> {
                let n = self.0.fetch_add(1, Ordering::SeqCst);
                let mut headers = HashMap::new();
                headers.insert("replay-nonce".into(), format!("n{n}"));
                if req.url == "https://ca/new-account" && n == 1 {
                    headers.remove("replay-nonce");
                    return Ok(HttpResponse {
                        status: 400,
                        headers,
                        body: br#"{"type":"urn:ietf:params:acme:error:badNonce"}"#.to_vec(),
                    });
                }
                if req.url == "https://ca/new-account" {
                    headers.insert("location".into(), "https://ca/acct/9".into());
                    return Ok(HttpResponse {
                        status: 201,
                        headers,
                        body: br#"{"status":"valid"}"#.to_vec(),
                    });
                }
                if req.url == "https://ca/new-nonce" {
                    return Ok(HttpResponse {
                        status: 200,
                        headers,
                        body: Vec::new(),
                    });
                }
                Ok(HttpResponse {
                    status: 200,
                    headers,
                    body: br#"{"newNonce":"https://ca/new-nonce","newAccount":"https://ca/new-account"}"#.to_vec(),
                })
            }
        }

        let mut client = AcmeClient::connect(
            Arc::new(BadOnceCa(AtomicUsize::new(0))),
            "https://ca/directory",
        )
        .await
        .unwrap();
        let account = client
            .register_account(&[], true, None, false, &CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(account.url, "https://ca/acct/9");
    }
}
