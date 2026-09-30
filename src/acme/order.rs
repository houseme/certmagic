//! ACME orders, authorizations, challenges (RFC 8555 §7.4) and ARI
//! (draft-ietf-acme-ari).

use std::net::IpAddr;
use std::time::Duration;

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::OffsetDateTime;

use crate::error::{AcmeError, Error, Result};

/// Delay before the first order-status poll; grows to [`MAX_POLL_INTERVAL`].
const FIRST_POLL_INTERVAL: Duration = Duration::from_millis(500);
/// Upper bound on order-status polling intervals.
const MAX_POLL_INTERVAL: Duration = Duration::from_secs(5);
/// Default total budget for reaching a terminal order state.
pub const DEFAULT_ORDER_TIMEOUT: Duration = Duration::from_secs(30);

/// An order identifier (RFC 8555 §9.7.1 + RFC 8738).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "lowercase")]
pub enum Identifier {
    /// A DNS name.
    Dns(String),
    /// An IP address (RFC 8738).
    Ip(IpAddr),
}

impl Identifier {
    /// The value as a string (for matching against challenge targets).
    #[must_use]
    pub fn value(&self) -> String {
        match self {
            Self::Dns(d) => d.clone(),
            Self::Ip(ip) => ip.to_string(),
        }
    }
}

impl From<&str> for Identifier {
    fn from(s: &str) -> Self {
        Identifier::Dns(s.to_owned())
    }
}

impl From<IpAddr> for Identifier {
    fn from(ip: IpAddr) -> Self {
        Identifier::Ip(ip)
    }
}

/// A single challenge (RFC 8555 §8).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct Challenge {
    /// `http-01`, `dns-01`, `tls-alpn-01`.
    #[serde(rename = "type")]
    pub kind: String,
    /// The challenge token. Absent on newer challenge types such as
    /// `dns-persist-01` (RFC 8555 §8.1 tokens are required for the types we
    /// solve).
    #[serde(default)]
    pub token: String,
    /// The challenge URL (to POST to for validation).
    pub url: String,
    /// Server-reported status.
    #[serde(default)]
    pub status: String,
    /// Validation errors, when failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
}

impl Challenge {
    /// Build the key authorization `token.thumbprintB64` for this challenge.
    ///
    /// # Errors
    /// Propagates thumbprint computation.
    pub fn key_authorization(&self, account: &crate::acme::protocol::AccountKey) -> Result<String> {
        let thumb = account.thumbprint_b64()?;
        crate::acme::protocol::key_authorization(&self.token, &thumb)
    }
}

/// An authorization for one identifier.
#[derive(Debug, Clone, Deserialize)]
pub struct Authorization {
    /// The identifier being validated.
    pub identifier: Identifier,
    /// Server-reported status.
    #[serde(default)]
    pub status: String,
    /// Available challenges.
    #[serde(default)]
    pub challenges: Vec<Challenge>,
    /// True for the wildcard authorization (identifier `*.`-prefixed semantically).
    #[serde(default)]
    pub wildcard: bool,
    /// Authorization expiry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
}

impl Authorization {
    /// Find a challenge by type.
    #[must_use]
    pub fn challenge(&self, kind: &str) -> Option<&Challenge> {
        self.challenges.iter().find(|c| c.kind == kind)
    }
}

/// An ACME order.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct Order {
    /// `pending | ready | processing | valid | invalid`.
    #[serde(default)]
    pub status: String,
    /// Authorizations to satisfy (URLs).
    #[serde(default)]
    pub authorizations: Vec<String>,
    /// The finalize URL (CSR submission).
    #[serde(default)]
    pub finalize: String,
    /// The certificate download URL, once `valid`.
    #[serde(default)]
    pub certificate: Option<String>,
    /// Server-reported error, when invalid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
    /// Requested window start (`notBefore` echo).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    /// Requested window end (`notAfter` echo).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
}

impl Order {
    /// Whether the order reached a terminal state.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self.status.as_str(), "valid" | "invalid")
    }
}

/// Build the `newOrder` request body.
#[must_use]
pub fn new_order_body(
    identifiers: &[Identifier],
    not_before: Option<OffsetDateTime>,
    not_after: Option<OffsetDateTime>,
) -> Value {
    new_order_body_with_options(identifiers, not_before, not_after, None, None)
}

/// Build a `newOrder` body with ACME profile and ARI replacement metadata.
#[must_use]
pub fn new_order_body_with_options(
    identifiers: &[Identifier],
    not_before: Option<OffsetDateTime>,
    not_after: Option<OffsetDateTime>,
    profile: Option<&str>,
    replaces: Option<&str>,
) -> Value {
    let mut body = json!({
        "identifiers": identifiers
            .iter()
            .map(|id| match id {
                Identifier::Dns(d) => json!({"type": "dns", "value": d}),
                Identifier::Ip(ip) => json!({"type": "ip", "value": ip.to_string()}),
            })
            .collect::<Vec<_>>(),
    });
    if let Some(nb) = not_before {
        body["notBefore"] = Value::String(rfc3339(nb));
    }
    if let Some(na) = not_after {
        body["notAfter"] = Value::String(rfc3339(na));
    }
    if let Some(profile) = profile {
        body["profile"] = Value::String(profile.to_owned());
    }
    if let Some(replaces) = replaces {
        body["replaces"] = Value::String(replaces.to_owned());
    }
    body
}

/// The ARI `certID` (draft-ietf-acme-ari-03 §4.1):
/// `base64url(AKI keyIdentifier) . "." . base64url(serialNumber)` — the
/// dot-separated two-part path segment, where the first part is the
/// **Authority Key Identifier extension's keyIdentifier** of the target
/// certificate (the issuer's SKID as embedded by the CA, which may use any
/// RFC 7093 derivation — do not recompute it).
#[must_use]
pub fn ari_cert_id(aki_key_identifier: &[u8], serial_der: &[u8]) -> String {
    format!(
        "{}.{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(aki_key_identifier),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serial_der)
    )
}

/// A wire-level renewal-info response (RFC 9773 wire shape).
///
/// This is deliberately kept separate from [`crate::certificate::RenewalInfo`].
/// The latter is mutable runtime state: it contains a locally selected renewal
/// instant and bookkeeping used by the maintenance loop.  The ACME response,
/// in contrast, carries server metadata that must survive a round trip even
/// when no usable renewal window was supplied.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct RenewalInfoResponse {
    /// The optional CA-suggested renewal window.
    #[serde(rename = "suggestedWindow", default)]
    pub suggested_window: Option<SuggestedWindow>,
    /// Optional URL explaining why the CA suggested renewal.
    #[serde(rename = "explanationURL", default)]
    pub explanation_url: Option<String>,
    /// Optional retry delay in seconds supplied by the CA.
    #[serde(rename = "retryAfter", default)]
    pub retry_after: Option<u64>,
    /// A locally selected renewal instant.
    ///
    /// This is intentionally not part of the wire representation.  It is
    /// populated only by callers that choose to attach local scheduling state
    /// to this response DTO; [`Self::to_runtime`] always derives fresh native
    /// state from the server window instead.
    #[serde(skip)]
    pub selected_time: Option<OffsetDateTime>,
}

/// Start/end of the suggested renewal window (RFC 3339).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SuggestedWindow {
    /// Window start.
    pub start: String,
    /// Window end.
    pub end: String,
}

impl RenewalInfoResponse {
    /// Parse the optional window into concrete instants.
    ///
    /// `Ok(None)` means the CA returned a valid response without a suggested
    /// window.  This is distinct from malformed timestamps, which are
    /// rejected.  The distinction lets callers preserve `retry_after` and
    /// `explanation_url` without accidentally scheduling a renewal at an
    /// untrusted instant.
    pub fn window_opt(&self) -> Result<Option<(OffsetDateTime, OffsetDateTime)>> {
        let Some(window) = &self.suggested_window else {
            return Ok(None);
        };
        let parse = |s: &str| -> Result<OffsetDateTime> {
            OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
                .map_err(|e| Error::Acme(AcmeError::Order(format!("ARI timestamp: {e}"))))
        };
        let start = parse(&window.start)?;
        let end = parse(&window.end)?;
        if end <= start {
            return Err(Error::Acme(AcmeError::Order(
                "ARI renewal window end must be after start".into(),
            )));
        }
        Ok(Some((start, end)))
    }

    /// Parse the required window, preserving the historical fallible API.
    ///
    /// # Errors
    /// Returns an ACME order error if no window was supplied or if its
    /// timestamps are malformed/reversed.
    pub fn window(&self) -> Result<(OffsetDateTime, OffsetDateTime)> {
        self.window_opt()?.ok_or_else(|| {
            Error::Acme(AcmeError::Order(
                "ARI response omitted suggestedWindow".into(),
            ))
        })
    }

    /// Convert the server response into local renewal state when a window is
    /// present.
    ///
    /// The conversion intentionally discards response metadata from the
    /// runtime value and re-generates `selected_time` inside the validated
    /// window.  Callers that need `retry_after` or `explanation_url` should
    /// retain this response DTO alongside the native state.
    pub fn to_runtime(&self) -> Result<Option<crate::certificate::RenewalInfo>> {
        self.window_opt()?
            .map(|(start, end)| {
                Ok(crate::certificate::RenewalInfo::from_suggested_window(
                    start, end,
                ))
            })
            .transpose()
    }

    /// Build a response DTO from local renewal state.
    ///
    /// Server metadata is unavailable in native state and is therefore left
    /// unset.  The selected instant is retained only as non-serialized local
    /// metadata; it does not alter the window conversion semantics.
    pub fn from_runtime(info: &crate::certificate::RenewalInfo) -> Result<Self> {
        let window = info.renewal_window()?;
        Ok(Self {
            suggested_window: Some(SuggestedWindow {
                start: window.start,
                end: window.end,
            }),
            explanation_url: None,
            retry_after: None,
            selected_time: Some(info.selected_time),
        })
    }
}

impl From<crate::certificate::RenewalWindow> for SuggestedWindow {
    fn from(window: crate::certificate::RenewalWindow) -> Self {
        Self {
            start: window.start,
            end: window.end,
        }
    }
}

impl From<SuggestedWindow> for crate::certificate::RenewalWindow {
    fn from(window: SuggestedWindow) -> Self {
        Self {
            start: window.start,
            end: window.end,
        }
    }
}

/// Poll `check` until it reports `Some(value)` or the budget expires,
/// starting at 500 ms and doubling to a 5 s cap, honouring an optional
/// server-provided interval.
///
/// # Errors
/// Returns a timeout error when the total budget expires, including time
/// spent inside `check`. Check errors are returned immediately.
pub async fn poll_until<T, F, Fut>(
    mut check: F,
    timeout: Duration,
    ct: &tokio_util::sync::CancellationToken,
) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<(T, bool)>>,
{
    let polling = async {
        let mut interval = FIRST_POLL_INTERVAL;
        loop {
            let (value, done) = check().await?;
            if done {
                return Ok(value);
            }
            tokio::time::sleep(interval).await;
            interval = (interval * 2).min(MAX_POLL_INTERVAL);
        }
    };
    tokio::select! {
        biased;
        () = ct.cancelled() => Err(Error::Acme(AcmeError::Order("canceled".into()))),
        result = tokio::time::timeout(timeout, polling) => result.unwrap_or_else(|_| {
            Err(Error::Acme(AcmeError::Order(format!("not ready within {}s", timeout.as_secs()))))
        }),
    }
}

fn rfc3339(t: OffsetDateTime) -> String {
    t.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| t.unix_timestamp().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn review_poll_timeout_includes_inflight_check() {
        let result: Result<()> = poll_until(
            std::future::pending,
            Duration::from_secs(2),
            &tokio_util::sync::CancellationToken::new(),
        )
        .await;
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("not ready within 2s")
        );
    }

    #[tokio::test]
    async fn review_cancelled_poll_does_not_start_check() {
        let ct = tokio_util::sync::CancellationToken::new();
        ct.cancel();
        let result: Result<()> = poll_until(
            || async { panic!("cancelled poll must not execute") },
            Duration::from_secs(1),
            &ct,
        )
        .await;
        assert!(result.is_err());
    }

    #[test]
    fn ari_cert_id_is_dot_separated() {
        // Known-answer via Python: b64url(0x11*20) + "." + b64url(0x010203).
        let id = ari_cert_id(&[0x11; 20], &[0x01, 0x02, 0x03]);
        assert_eq!(id, "ERERERERERERERERERERERERERE.AQID");
        assert!(!id.contains('='));
        assert_eq!(id.matches('.').count(), 1, "AKID.serial shape");
        assert_ne!(id, ari_cert_id(&[0x11; 20], &[0x01, 0x02, 0x04]));
    }

    #[test]
    fn identifiers_roundtrip() {
        let dns = Identifier::Dns("example.com".into());
        let ip: Identifier = "127.0.0.1".parse::<IpAddr>().unwrap().into();
        assert_eq!(dns.value(), "example.com");
        assert_eq!(ip.value(), "127.0.0.1");

        let body = new_order_body(&[dns, ip], None, None);
        assert_eq!(body["identifiers"][0]["type"], "dns");
        assert_eq!(body["identifiers"][1]["type"], "ip");
    }

    #[tokio::test(start_paused = true)]
    async fn poll_until_completes_on_done() {
        let ct = tokio_util::sync::CancellationToken::new();
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let c2 = counter.clone();
        let value = poll_until(
            move || {
                let c = c2.clone();
                async move {
                    let n = c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok((n, n >= 2))
                }
            },
            Duration::from_secs(10),
            &ct,
        )
        .await
        .unwrap();
        assert_eq!(value, 2);
    }

    #[test]
    fn order_deserializes_minimally() {
        let order: Order =
            serde_json::from_str(r#"{"status":"pending","finalize":"https://ca/fx"}"#).unwrap();
        assert_eq!(order.status, "pending");
        assert!(!order.is_terminal());
        let invalid: Order = serde_json::from_str(r#"{"status":"invalid"}"#).unwrap();
        assert!(invalid.is_terminal());
    }

    #[test]
    fn renewal_info_response_preserves_wire_metadata_without_runtime_state() {
        let response: RenewalInfoResponse = serde_json::from_str(
            r#"{
                "suggestedWindow": {
                    "start": "2030-01-01T00:00:00Z",
                    "end": "2030-01-02T00:00:00Z"
                },
                "explanationURL": "https://ca.example/ari/explanation",
                "retryAfter": 3600
            }"#,
        )
        .unwrap();

        assert_eq!(
            response.explanation_url.as_deref(),
            Some("https://ca.example/ari/explanation")
        );
        assert_eq!(response.retry_after, Some(3600));
        assert_eq!(response.selected_time, None);
        let runtime = response.to_runtime().unwrap().unwrap();
        let (start, end) = response.window().unwrap();
        assert!(runtime.selected_time >= start);
        assert!(runtime.selected_time <= end);

        let encoded = serde_json::to_value(&response).unwrap();
        assert_eq!(
            encoded["explanationURL"],
            "https://ca.example/ari/explanation"
        );
        assert_eq!(encoded["retryAfter"], 3600);
        assert!(encoded.get("selected_time").is_none());
    }

    #[test]
    fn renewal_info_response_allows_metadata_without_window() {
        let response: RenewalInfoResponse =
            serde_json::from_str(r#"{"explanationURL":"https://ca.example/ari","retryAfter":120}"#)
                .unwrap();

        assert_eq!(response.window_opt().unwrap(), None);
        assert!(response.to_runtime().unwrap().is_none());
        assert!(response.window().is_err());
        assert_eq!(response.retry_after, Some(120));
    }

    #[test]
    fn renewal_info_response_rejects_reversed_window() {
        let response = RenewalInfoResponse {
            suggested_window: Some(SuggestedWindow {
                start: "2030-01-02T00:00:00Z".into(),
                end: "2030-01-01T00:00:00Z".into(),
            }),
            ..RenewalInfoResponse::default()
        };
        assert!(response.to_runtime().is_err());
    }

    #[test]
    fn new_order_options_include_profile_and_replaces() {
        let body = new_order_body_with_options(
            &[Identifier::Dns("example.com".into())],
            None,
            None,
            Some("tlsserver"),
            Some("https://ca/cert/1"),
        );
        assert_eq!(body["profile"], "tlsserver");
        assert_eq!(body["replaces"], "https://ca/cert/1");
    }
}
