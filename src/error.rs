//! Error types for the certmagic crate.
//!
//! Error semantics contract:
//! - `StorageError::NotFound` models a missing-file error (callers branch on
//!   it).
//! - [`Error::NoRetry`] marks permanent failures: it short-circuits
//!   [`crate::runtime::do_with_retry`].

use thiserror::Error;

/// Convenience alias used throughout the crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// The top-level error type.
#[derive(Debug, Clone, Error)]
pub enum Error {
    /// Storage backend failures.
    #[error("storage: {0}")]
    Storage(#[from] StorageError),

    /// ACME protocol failures (RFC 8555 client layer).
    #[error("acme: {0}")]
    Acme(#[from] AcmeError),

    /// Issuer-level failures (account, order orchestration, challenge solving).
    #[error("issuer: {0}")]
    Issuer(#[from] IssuerError),

    /// OCSP stapling failures.
    #[error("ocsp: {0}")]
    Ocsp(#[from] OcspError),

    /// Certificate parsing / matching failures.
    #[error("certificate: {0}")]
    Certificate(#[from] CertificateError),

    /// Configuration errors (missing cache, invalid settings, …).
    #[error("config: {0}")]
    Config(#[from] ConfigError),

    /// DNS-01 propagation checks and zone discovery.
    #[error("dns: {0}")]
    Dns(#[from] DnsError),

    /// The operation must not be retried.
    #[error("no retry: {0}")]
    NoRetry(Box<Error>),

    /// An internal invariant was violated. This indicates a bug.
    #[error("internal: {0}")]
    Internal(String),
}

impl Error {
    /// Wrap `self` so that retry loops treat it as terminal.
    #[must_use]
    pub fn no_retry(self) -> Error {
        Error::NoRetry(Box::new(self))
    }

    /// Returns `true` if this error (or any error nested inside it) is a
    /// [`Error::NoRetry`].
    #[must_use]
    pub fn has_no_retry(&self) -> bool {
        matches!(self, Error::NoRetry(_))
    }

    /// Whether the CA reported a nonexistent account; callers delete the
    /// local account and re-register — rotating the key.
    #[must_use]
    pub fn is_account_does_not_exist(&self) -> bool {
        matches!(
            self,
            Error::Acme(AcmeError::Problem(ProblemType::AccountDoesNotExist, _))
        )
    }
}

impl From<std::io::Error> for StorageError {
    fn from(err: std::io::Error) -> Self {
        StorageError::Io(err.to_string())
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Storage(StorageError::from(err))
    }
}

/// Storage backend errors.
#[derive(Debug, Clone, Error)]
pub enum StorageError {
    /// The key does not exist.
    #[error("key not found: {0}")]
    NotFound(String),

    /// The key exists but is malformed for the requested operation.
    #[error("invalid key: {0}")]
    InvalidKey(String),

    /// A lock could not be acquired because it is held elsewhere.
    #[error("lock unavailable: {0}")]
    LockUnavailable(String),

    /// A lock is stale, its lease was lost, or stale-lock recovery failed.
    #[error("stale lock or lost lease: {0}")]
    StaleLock(String),

    /// The destination cannot atomically validate this acquisition's proof.
    #[error("destination does not support this lock's write fence")]
    UnsupportedFencing,

    /// Underlying I/O failure (message preserved; kind lost across clone).
    #[error("io: {0}")]
    Io(String),

    /// Backend-specific failure.
    #[error("{0}")]
    Other(String),
}

/// Failures of the hand-written RFC 8555 protocol layer.
#[derive(Debug, Clone, Error)]
pub enum AcmeError {
    /// The CA returned a problem document (RFC 7807).
    #[error("acme problem [{0}]: {1}")]
    Problem(ProblemType, String),

    /// Directory fetch or malformed directory.
    #[error("directory: {0}")]
    Directory(String),

    /// Nonce handling failed.
    #[error("nonce: {0}")]
    Nonce(String),

    /// Account creation or lookup failed.
    #[error("account: {0}")]
    Account(String),

    /// Order could not reach the `valid` state in time.
    #[error("order: {0}")]
    Order(String),

    /// Authorization was rejected or expired.
    #[error("authorization: {0}")]
    Authorization(String),

    /// Challenge validation failed.
    #[error("challenge: {0}")]
    Challenge(String),

    /// The HTTP transport failed.
    #[error("http: {0}")]
    Http(String),

    /// JWS signing / encoding failure.
    #[error("jws: {0}")]
    Jws(String),

    /// A required endpoint is missing from the directory.
    #[error("directory does not advertise endpoint: {0}")]
    MissingEndpoint(String),
}

/// Issuer orchestration failures (above the wire protocol).
#[derive(Debug, Clone, Error)]
pub enum IssuerError {
    /// The ACME account no longer exists at the CA (triggers a local
    /// account rebuild).
    #[error("account does not exist")]
    AccountDoesNotExist,

    /// The user must agree to the CA terms of service.
    #[error("user must agree to CA terms")]
    MustAgreeToTerms,

    /// Challenge solving failed.
    #[error("challenge: {0}")]
    Challenge(String),

    /// No issuer in the configured list could issue the certificate.
    #[error("all issuers failed")]
    AllIssuersFailed,

    /// Other issuer failure.
    #[error("{0}")]
    Other(String),
}

/// OCSP stapling errors.
#[derive(Debug, Clone, Error)]
pub enum OcspError {
    /// The certificate has no OCSP responder in its AIA extension.
    #[error("no OCSP server specified in certificate")]
    NoOcspServer,

    /// The staple is malformed.
    #[error("malformed ocsp response: {0}")]
    Malformed(String),

    /// The OCSP response does not cover the requested certificate.
    #[error("ocsp response is for a different certificate")]
    CertIdMismatch,

    /// The responder failed authorization checks (RFC 6960 §4.2.2.2).
    #[error("unauthorized ocsp responder")]
    UnauthorizedResponder,

    /// Fetching failed.
    #[error("fetch: {0}")]
    Fetch(String),
}

/// Certificate parsing / selection errors.
#[derive(Debug, Clone, Error)]
pub enum CertificateError {
    /// PEM/DER bundle could not be parsed.
    #[error("parse: {0}")]
    Parse(String),

    /// The certificate covers no usable names.
    #[error("certificate has no names")]
    NoNames,

    /// No private key is available for the certificate.
    #[error("no private key")]
    NoPrivateKey,

    /// The subject is not allowed.
    #[error("certificate is not allowed for subject {0:?}")]
    NotAllowed(String),
}

/// Configuration errors.
#[derive(Debug, Clone, Error)]
pub enum ConfigError {
    /// A required component was not provided.
    #[error("{0}")]
    Missing(String),

    /// A value is out of range or inconsistent.
    #[error("{0}")]
    Invalid(String),
}

/// DNS utility errors.
#[derive(Debug, Clone, Error)]
pub enum DnsError {
    /// Zone discovery failed.
    #[error("could not find zone for {0}")]
    ZoneNotFound(String),

    /// DNS query failure.
    #[error("query: {0}")]
    Query(String),

    /// The feature requires the `dns-01` cargo feature.
    #[error("dns support not enabled (build with feature \"dns-01\")")]
    Disabled,
}

/// ACME problem document types we branch on (RFC 8555 §8 / RFC 7807).
///
/// The URN suffix is carried without the `urn:ietf:params:acme:error:` prefix.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Error)]
pub enum ProblemType {
    /// The request specified an account that does not exist.
    #[error("accountDoesNotExist")]
    AccountDoesNotExist,
    /// The request is covered by an existing account already.
    #[error("alreadyRevoked")]
    AlreadyRevoked,
    /// The request message was malformed.
    #[error("badNonce")]
    BadNonce,
    /// The client sent insufficient information.
    #[error("badPublicKey")]
    BadPublicKey,
    /// The request specified a nonce that is no longer valid.
    #[error("badRevocationReason")]
    BadRevocationReason,
    /// The CSR requests names not allowed by the CA.
    #[error("badSignatureAlgorithm")]
    BadSignatureAlgorithm,
    /// Revocation reason is not allowed.
    #[error("caa")]
    Caa,
    /// The signing key did not match.
    #[error("conflict")]
    Conflict,
    /// DNS problem during validation.
    #[error("dns")]
    Dns,
    /// A required EAB was not provided / wrong.
    #[error("externalAccountRequired")]
    ExternalAccountRequired,
    /// A general error.
    #[error("incorrectResponse")]
    IncorrectResponse,
    /// Contact is invalid.
    #[error("invalidContact")]
    InvalidContact,
    /// The client lacks authorization.
    #[error("malformed")]
    Malformed,
    /// The order is not ready to be finalized.
    #[error("orderNotReady")]
    OrderNotReady,
    /// Rate limit exceeded (check `Retry-After`).
    #[error("rateLimited")]
    RateLimited,
    /// The certificate was already revoked.
    #[error("rejectedIdentifier")]
    RejectedIdentifier,
    /// The server rejects the identifier.
    #[error("serverInternal")]
    ServerInternal,
    /// The CA had an internal error.
    #[error("tls")]
    Tls,
    /// TLS problem during validation.
    #[error("unauthorized")]
    Unauthorized,
    /// The client is not authorized.
    #[error("unsupportedContact")]
    UnsupportedContact,
    /// Unsupported contact scheme.
    #[error("unknownIdentifier")]
    UnknownIdentifier,
    /// An unrecognized problem type.
    #[error("{0}")]
    Other(String),
}

impl ProblemType {
    /// Build from the raw URN (or bare suffix) of a problem document.
    #[must_use]
    pub fn from_urn(urn: &str) -> Self {
        const PREFIX: &str = "urn:ietf:params:acme:error:";
        let suffix = urn.strip_prefix(PREFIX).unwrap_or(urn);
        match suffix {
            "accountDoesNotExist" => Self::AccountDoesNotExist,
            "alreadyRevoked" => Self::AlreadyRevoked,
            "badNonce" => Self::BadNonce,
            "badPublicKey" => Self::BadPublicKey,
            "badRevocationReason" => Self::BadRevocationReason,
            "badSignatureAlgorithm" => Self::BadSignatureAlgorithm,
            "caa" => Self::Caa,
            "conflict" => Self::Conflict,
            "dns" => Self::Dns,
            "externalAccountRequired" => Self::ExternalAccountRequired,
            "incorrectResponse" => Self::IncorrectResponse,
            "invalidContact" => Self::InvalidContact,
            "malformed" => Self::Malformed,
            "orderNotReady" => Self::OrderNotReady,
            "rateLimited" => Self::RateLimited,
            "rejectedIdentifier" => Self::RejectedIdentifier,
            "serverInternal" => Self::ServerInternal,
            "tls" => Self::Tls,
            "unauthorized" => Self::Unauthorized,
            "unsupportedContact" => Self::UnsupportedContact,
            "unknownIdentifier" => Self::UnknownIdentifier,
            other => Self::Other(other.to_owned()),
        }
    }

    /// The bare suffix (without the URN prefix).
    #[must_use]
    pub fn suffix(&self) -> String {
        match self {
            Self::AccountDoesNotExist => "accountDoesNotExist".into(),
            Self::AlreadyRevoked => "alreadyRevoked".into(),
            Self::BadNonce => "badNonce".into(),
            Self::BadPublicKey => "badPublicKey".into(),
            Self::BadRevocationReason => "badRevocationReason".into(),
            Self::BadSignatureAlgorithm => "badSignatureAlgorithm".into(),
            Self::Caa => "caa".into(),
            Self::Conflict => "conflict".into(),
            Self::Dns => "dns".into(),
            Self::ExternalAccountRequired => "externalAccountRequired".into(),
            Self::IncorrectResponse => "incorrectResponse".into(),
            Self::InvalidContact => "invalidContact".into(),
            Self::Malformed => "malformed".into(),
            Self::OrderNotReady => "orderNotReady".into(),
            Self::RateLimited => "rateLimited".into(),
            Self::RejectedIdentifier => "rejectedIdentifier".into(),
            Self::ServerInternal => "serverInternal".into(),
            Self::Tls => "tls".into(),
            Self::Unauthorized => "unauthorized".into(),
            Self::UnsupportedContact => "unsupportedContact".into(),
            Self::UnknownIdentifier => "unknownIdentifier".into(),
            Self::Other(s) => s.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn problem_type_roundtrip() {
        for urn in [
            "urn:ietf:params:acme:error:accountDoesNotExist",
            "urn:ietf:params:acme:error:rateLimited",
            "urn:ietf:params:acme:error:customThing",
        ] {
            let pt = ProblemType::from_urn(urn);
            assert_eq!(pt.suffix(), urn.rsplit(':').next().unwrap());
        }
    }

    #[test]
    fn no_retry_detection() {
        let err = Error::Issuer(IssuerError::MustAgreeToTerms).no_retry();
        assert!(err.has_no_retry());
        let plain = Error::Issuer(IssuerError::Other("x".into()));
        assert!(!plain.has_no_retry());
    }
}
