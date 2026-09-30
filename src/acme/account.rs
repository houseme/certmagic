//! ACME accounts (RFC 8555 §7.3) including external account binding
//! (RFC 8555 §7.3.4).

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::acme::protocol::AccountKey;
use crate::error::{AcmeError, Error, Result};

/// External account binding credentials issued by the CA.
#[derive(Clone, Serialize, Deserialize)]
pub struct EabCredentials {
    /// The CA-issued key identifier (`kid`).
    pub key_id: String,
    /// The HMAC-SHA256 key, base64url-encoded.
    pub hmac_key: String,
}

impl std::fmt::Debug for EabCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EabCredentials")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

/// An ACME account: the key *is* the account; the URL is its server-side
/// identifier.
#[derive(Debug, Clone)]
pub struct Account {
    /// The account key pair.
    pub key: AccountKey,
    /// The account URL (`kid` for JWS). Empty until registered.
    pub url: String,
    /// Contact URIs, e.g. `mailto:admin@example.com`.
    pub contacts: Vec<String>,
    /// Server-reported account status (`valid`, `deactivated`, …).
    pub status: String,
    /// Whether the CA reports the TOS as agreed.
    pub terms_of_service_agreed: bool,
}

impl Account {
    /// Create an unregistered account with a fresh key and the given contacts.
    ///
    /// # Errors
    /// Propagates key generation.
    pub fn new_es256(contacts: &[String]) -> Result<Self> {
        Ok(Self {
            key: AccountKey::generate_es256()?,
            url: String::new(),
            contacts: contacts.to_vec(),
            status: String::new(),
            terms_of_service_agreed: false,
        })
    }

    /// Create an unregistered RSA-2048 account.
    #[cfg(feature = "rsa")]
    pub fn new_rsa2048(contacts: &[String]) -> Result<Self> {
        Ok(Self {
            key: AccountKey::generate_rsa2048()?,
            url: String::new(),
            contacts: contacts.to_vec(),
            status: String::new(),
            terms_of_service_agreed: false,
        })
    }

    /// Whether this account has been registered (has a URL).
    #[must_use]
    pub fn is_registered(&self) -> bool {
        !self.url.is_empty()
    }

    /// The JWK for this account's key.
    ///
    /// # Errors
    /// Propagates [`AccountKey::jwk`].
    pub fn jwk(&self) -> Result<Value> {
        Ok(self.key.jwk()?.value)
    }
}

/// Server-side view of an account (POST-as-GET body).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct AccountInfo {
    /// Account status.
    #[serde(default)]
    pub status: String,
    /// Contact URIs.
    #[serde(default)]
    pub contact: Vec<String>,
    /// TOS agreement flag as the server sees it.
    #[serde(rename = "termsOfServiceAgreed", default)]
    pub terms_of_service_agreed: bool,
    /// Orders URL for this account.
    #[serde(default)]
    pub orders: Option<String>,
}

/// Build the `externalAccountBinding` JWS: an HMAC-SHA256-signed JWS whose
/// payload is the account key's JWK (RFC 8555 §7.3.4).
///
/// # Errors
/// [`Error::Acme`] on HMAC key decode, JWK build, or serialization failure.
pub fn external_account_binding(
    eab: &EabCredentials,
    account_key: &AccountKey,
    new_account_url: &str,
) -> Result<Value> {
    let hmac_key_bytes = B64URL
        .decode(eab.hmac_key.as_bytes())
        .map_err(|e| Error::Acme(AcmeError::Account(format!("EAB hmac key: {e}"))))?;
    let jwk = account_key.jwk()?.value;
    let payload = serde_json::to_vec(&jwk)
        .map_err(|e| Error::Acme(AcmeError::Account(format!("jwk: {e}"))))?;

    let protected = json!({
        "alg": "HS256",
        "kid": eab.key_id,
        "url": new_account_url,
    });
    let protected_b64 = B64URL.encode(
        serde_json::to_vec(&protected)
            .map_err(|e| Error::Acme(AcmeError::Account(format!("protected: {e}"))))?,
    );
    let payload_b64 = B64URL.encode(&payload);

    let signing_input = format!("{protected_b64}.{payload_b64}");
    let signature = crate::acme::provider::hmac_sha256(&hmac_key_bytes, signing_input.as_bytes());

    Ok(json!({
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": B64URL.encode(signature),
    }))
}

// ---------------------------------------------------------------------------
// Interactive prompts
// ---------------------------------------------------------------------------

/// Prompt the user for an ACME account email address.
///
/// The prompt is deliberately opt-in: callers must invoke this function when
/// they are running an interactive command, rather than having certificate
/// issuance unexpectedly block on stdin. It returns `None` when stdin is not
/// a terminal, input is unavailable, or the user enters an empty line. This
/// makes it safe to call from services and other non-interactive processes.
///
/// The prompt is written to stderr so that stdout remains suitable for
/// command output or machine-readable responses.
#[must_use]
pub fn prompt_user_for_email() -> Option<String> {
    use std::io::{self, IsTerminal};

    if !io::stdin().is_terminal() {
        return None;
    }

    let stdin = io::stdin();
    let mut input = stdin.lock();
    let mut output = io::stderr();
    prompt_user_for_email_with_io(&mut input, &mut output)
        .ok()
        .flatten()
}

/// Prompt for an ACME account email using caller-provided I/O.
///
/// This lower-level variant is useful for CLI frontends and tests. Unlike
/// [`prompt_user_for_email`], it does not inspect whether the input is a
/// terminal; the caller has already selected the desired input source.
/// Empty or whitespace-only input is represented by `Ok(None)`.
///
/// # Errors
///
/// Returns an I/O error if prompting, flushing, or reading fails.
pub fn prompt_user_for_email_with_io<R, W>(
    input: &mut R,
    output: &mut W,
) -> std::io::Result<Option<String>>
where
    R: std::io::BufRead,
    W: std::io::Write,
{
    write!(
        output,
        "Your email address (for ACME account, Let's Encrypt notifications): "
    )?;
    output.flush()?;

    let mut line = String::new();
    input.read_line(&mut line)?;
    let trimmed = line.trim();
    Ok((!trimmed.is_empty()).then(|| trimmed.to_owned()))
}

/// Prompt the user to agree to the CA's terms of service.
///
/// Only `y` and `yes` (case-insensitive) are accepted. Non-interactive input,
/// an I/O failure, an empty response, and every other response are treated as
/// refusal. The function never panics and is therefore safe to use as a
/// [`crate::acme::acme_issuer::TosCallback`].
#[must_use]
pub fn prompt_user_agreement(tos_url: &str) -> bool {
    use std::io::{self, IsTerminal};

    if !io::stdin().is_terminal() {
        return false;
    }

    let stdin = io::stdin();
    let mut input = stdin.lock();
    let mut output = io::stderr();
    prompt_user_agreement_with_io(tos_url, &mut input, &mut output).unwrap_or(false)
}

/// Prompt for terms-of-service agreement using caller-provided I/O.
///
/// This variant is intended for CLI frontends and tests. It does not inspect
/// terminal status. The URL is displayed verbatim as informational text; it
/// is not fetched or interpreted by this function.
///
/// # Errors
///
/// Returns an I/O error if prompting, flushing, or reading fails.
pub fn prompt_user_agreement_with_io<R, W>(
    tos_url: &str,
    input: &mut R,
    output: &mut W,
) -> std::io::Result<bool>
where
    R: std::io::BufRead,
    W: std::io::Write,
{
    writeln!(output, "\nYour CA's Terms of Service:")?;
    writeln!(output, "  {tos_url}")?;
    write!(output, "Do you agree to the Terms of Service? (y/N): ")?;
    output.flush()?;

    let mut line = String::new();
    input.read_line(&mut line)?;
    Ok(matches!(
        line.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn review_eab_debug_redacts_hmac_secret() {
        let credentials = EabCredentials {
            key_id: "account".into(),
            hmac_key: "private-hmac-secret".into(),
        };
        assert!(!format!("{credentials:?}").contains("private-hmac-secret"));
    }

    #[test]
    fn eab_structure_and_signature() {
        // HMAC key "secret" base64url-encoded.
        let hmac_b64 = B64URL.encode(b"secret");
        let eab = EabCredentials {
            key_id: "kid-123".into(),
            hmac_key: hmac_b64,
        };
        let key = AccountKey::generate_es256().unwrap();
        let url = "https://ca/new-account";

        let binding = external_account_binding(&eab, &key, url).unwrap();

        let protected: Value = serde_json::from_slice(
            &B64URL
                .decode(binding["protected"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(protected["alg"], "HS256");
        assert_eq!(protected["kid"], "kid-123");
        assert_eq!(protected["url"], url);

        // Payload must be exactly the account JWK.
        let payload: Value =
            serde_json::from_slice(&B64URL.decode(binding["payload"].as_str().unwrap()).unwrap())
                .unwrap();
        assert_eq!(payload, key.jwk().unwrap().value);

        // Signature must verify with the shared HMAC key.
        let signing_input = format!(
            "{}.{}",
            binding["protected"].as_str().unwrap(),
            binding["payload"].as_str().unwrap()
        );
        let expected = crate::acme::provider::hmac_sha256(b"secret", signing_input.as_bytes());
        assert_eq!(
            binding["signature"].as_str().unwrap(),
            B64URL.encode(expected)
        );
    }

    #[test]
    fn account_registration_lifecycle() {
        let mut acct = Account::new_es256(&["mailto:a@b.c".into()]).unwrap();
        assert!(!acct.is_registered());
        acct.url = "https://ca/acct/1".into();
        acct.status = "valid".into();
        assert!(acct.is_registered());
        assert_eq!(acct.contacts, vec!["mailto:a@b.c"]);
    }

    #[test]
    fn email_prompt_trims_input_and_writes_to_output() {
        let mut input = std::io::Cursor::new(b"  admin@example.com  \n".to_vec());
        let mut output = Vec::new();

        let email = prompt_user_for_email_with_io(&mut input, &mut output).unwrap();

        assert_eq!(email.as_deref(), Some("admin@example.com"));
        assert!(
            String::from_utf8(output)
                .unwrap()
                .contains("Your email address")
        );
    }

    #[test]
    fn email_prompt_rejects_empty_or_eof_input() {
        let mut input = std::io::Cursor::new(b"  \n".to_vec());
        let mut output = Vec::new();
        assert_eq!(
            prompt_user_for_email_with_io(&mut input, &mut output).unwrap(),
            None
        );

        let mut input = std::io::Cursor::new(Vec::<u8>::new());
        assert_eq!(
            prompt_user_for_email_with_io(&mut input, &mut output).unwrap(),
            None
        );
    }

    #[test]
    fn agreement_prompt_accepts_only_yes_answers() {
        for answer in ["y\n", "Y\n", "yes\n", " YES  \n"] {
            let mut input = std::io::Cursor::new(answer.as_bytes().to_vec());
            let mut output = Vec::new();
            assert!(
                prompt_user_agreement_with_io("https://ca.example/tos", &mut input, &mut output)
                    .unwrap()
            );
        }

        for answer in ["\n", "n\n", "no\n", "yup\n", "1\n"] {
            let mut input = std::io::Cursor::new(answer.as_bytes().to_vec());
            let mut output = Vec::new();
            assert!(
                !prompt_user_agreement_with_io("https://ca.example/tos", &mut input, &mut output)
                    .unwrap()
            );
        }
    }

    #[test]
    fn agreement_prompt_displays_tos_url() {
        let mut input = std::io::Cursor::new(b"yes\n".to_vec());
        let mut output = Vec::new();
        prompt_user_agreement_with_io("https://ca.example/tos", &mut input, &mut output).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("https://ca.example/tos"));
        assert!(output.contains("(y/N)"));
    }
}
