//! ACME problem documents (RFC 7807 / RFC 8555 §8) and their mapping to
//! [`crate::error::AcmeError`].

use serde_json::Value;

use crate::error::{AcmeError, Error, ProblemType};

/// A parsed problem document.
#[derive(Debug, Clone)]
pub struct Problem {
    /// The problem type (URN suffix).
    pub problem_type: ProblemType,
    /// Human-readable detail.
    pub detail: Option<String>,
    /// HTTP status the CA attached.
    pub status: u16,
    /// Retry-After hint carried alongside, when the CA sent one.
    pub retry_after: Option<std::time::Duration>,
}

impl Problem {
    /// Parse a problem document from a response body (JSON or plain text
    /// fallback for non-conformant errors).
    #[must_use]
    pub fn parse(status: u16, body: &[u8]) -> Self {
        if let Ok(doc) = serde_json::from_slice::<Value>(body) {
            let type_urn = doc
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("urn:ietf:params:acme:error:serverInternal");
            return Self {
                problem_type: ProblemType::from_urn(type_urn),
                detail: doc.get("detail").and_then(Value::as_str).map(str::to_owned),
                status,
                retry_after: None,
            };
        }
        // Non-JSON error body: keep the text as detail.
        let text = String::from_utf8_lossy(body);
        Self {
            problem_type: if status == 429 {
                ProblemType::RateLimited
            } else {
                ProblemType::ServerInternal
            },
            detail: Some(text.trim().to_owned()),
            status,
            retry_after: None,
        }
    }

    /// Attach a Retry-After duration.
    #[must_use]
    pub fn with_retry_after(mut self, d: std::time::Duration) -> Self {
        self.retry_after = Some(d);
        self
    }

    /// Convert into the crate error type.
    #[must_use]
    pub fn into_error(self) -> Error {
        Error::Acme(AcmeError::Problem(
            self.problem_type,
            self.detail.unwrap_or_default(),
        ))
    }

    /// badNonce problems are retried transparently by the client (RFC 8555
    /// §6.5); everything else is returned.
    #[must_use]
    pub fn is_bad_nonce(&self) -> bool {
        self.problem_type == ProblemType::BadNonce
    }

    /// Whether this problem reports a missing account
    ///.
    #[must_use]
    pub fn is_account_does_not_exist(&self) -> bool {
        self.problem_type == ProblemType::AccountDoesNotExist
    }
}

/// Parse a problem document if the response is an error; `None` on success.
#[must_use]
pub fn problem_from_response(resp: &crate::acme::transport::HttpResponse) -> Option<Problem> {
    if resp.is_success() {
        return None;
    }
    let mut problem = Problem::parse(resp.status, &resp.body);
    if let Some(ra) = resp.retry_after() {
        problem = problem.with_retry_after(ra);
    }
    Some(problem)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rfc7807_document() {
        let body = br#"{"type":"urn:ietf:params:acme:error:rateLimited","detail":"too many","status":429}"#;
        let p = Problem::parse(429, body);
        assert_eq!(p.problem_type, ProblemType::RateLimited);
        assert_eq!(p.detail.as_deref(), Some("too many"));
        assert_eq!(p.status, 429);
    }

    #[test]
    fn non_json_body_maps_to_rate_limit_on_429() {
        let p = Problem::parse(429, b"slow down");
        assert_eq!(p.problem_type, ProblemType::RateLimited);
        assert_eq!(p.detail.as_deref(), Some("slow down"));
    }

    #[test]
    fn account_does_not_exist_detection() {
        let body = br#"{"type":"urn:ietf:params:acme:error:accountDoesNotExist"}"#;
        let p = Problem::parse(400, body);
        assert!(p.is_account_does_not_exist());
    }

    #[test]
    fn success_responses_have_no_problem() {
        let resp = crate::acme::transport::HttpResponse {
            status: 200,
            headers: Default::default(),
            body: b"{}".to_vec(),
        };
        assert!(problem_from_response(&resp).is_none());
    }

    #[test]
    fn retry_after_is_preserved_on_http_problem_mapping() {
        let resp = crate::acme::transport::HttpResponse {
            status: 429,
            headers: [("retry-after".into(), "11".into())].into_iter().collect(),
            body: br#"{
                "type":"urn:ietf:params:acme:error:rateLimited",
                "detail":"account quota exceeded"
            }"#
            .to_vec(),
        };

        let problem = problem_from_response(&resp).expect("HTTP error problem");
        assert_eq!(problem.problem_type, ProblemType::RateLimited);
        assert_eq!(problem.status, 429);
        assert_eq!(problem.detail.as_deref(), Some("account quota exceeded"));
        assert_eq!(
            problem.retry_after,
            Some(std::time::Duration::from_secs(11))
        );
    }
}
