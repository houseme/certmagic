//! ACME support: account keys and JWS primitives, directory discovery,
//! nonce management, accounts with EAB, the order state machine, ARI, and a
//! transport abstraction that keeps the protocol unit-testable.

pub mod account;
pub mod acme_issuer;
pub mod client;
pub mod directory;
pub mod nonce;
pub mod order;
pub mod problem;
pub mod protocol;
pub(crate) mod provider;
pub mod transport;

pub use account::{
    Account, EabCredentials, prompt_user_agreement, prompt_user_agreement_with_io,
    prompt_user_for_email, prompt_user_for_email_with_io,
};
pub use acme_issuer::{
    AcmeIssuer, AcmeIssuerBuilder, LETS_ENCRYPT_PRODUCTION_CA, LETS_ENCRYPT_STAGING_CA,
};
pub use client::AcmeClient;
pub use directory::{Directory, DirectoryMeta};
pub use order::{RenewalInfoResponse, SuggestedWindow};
pub use protocol::{AccountKey, JWS_CONTENT_TYPE, Jwk, SignatureAlgorithm, key_authorization};
pub use transport::{HttpRequest, HttpResponse, Transport};
