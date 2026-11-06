//! Explicit, restartable issuer-namespace migration with verified receipts.
//! Quiesce legacy writers before invoking migration. Complete destination data
//! is verified before retiring the old namespace; interrupted runs can resume.
use crate::error::{Error, Result, StorageError};
use crate::{CertificateResource, Config};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

#[derive(Serialize, Deserialize)]
struct Receipt {
    version: u8,
    source: String,
    destination: String,
    domain: String,
    digest: String,
    complete: bool,
}
fn digest(resource: &CertificateResource) -> Result<String> {
    use sha2::Digest;
    let mut hash = sha2::Sha256::new();
    let metadata = serde_json::to_vec(resource).map_err(|_| conflict())?;
    for bytes in [
        resource.certificate_pem.as_slice(),
        resource.private_key_pem.as_slice(),
        metadata.as_slice(),
    ] {
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    Ok(hex::encode(hash.finalize()))
}

fn conflict() -> Error {
    Error::Storage(StorageError::Conflict(
        "issuer migration receipt or resource changed".into(),
    ))
}
impl Config {
    /// Upgrade configured ACME accounts and selected certificate resource keys.
    /// Call with old-version writers quiesced before starting management.
    pub async fn migrate_legacy_acme(
        &self,
        ct: &CancellationToken,
        domains: &[String],
    ) -> Result<usize> {
        let mut count = 0;
        for issuer in &self.options.issuers {
            if let Some(acme) = issuer.as_any().downcast_ref::<crate::acme::AcmeIssuer>() {
                acme.migrate_legacy_account(ct).await?;
                count += self
                    .migrate_issuer_storage(
                        ct,
                        &acme.legacy_issuer_key(),
                        &acme.issuer_key(),
                        domains,
                    )
                    .await?;
            }
            #[cfg(feature = "zerossl")]
            if let Some(issuer) = issuer
                .as_any()
                .downcast_ref::<crate::zerossl::ZeroSslIssuer>()
            {
                issuer.inner.migrate_legacy_account(ct).await?;
                count += self
                    .migrate_issuer_storage(
                        ct,
                        &issuer.inner.legacy_issuer_key(),
                        &issuer.inner.issuer_key(),
                        domains,
                    )
                    .await?;
            }
        }
        Ok(count)
    }

    /// Copy selected resource keys to a configured issuer, verify them, and
    /// retire their old active copies. Receipts make retries idempotent.
    pub async fn migrate_issuer_storage(
        &self,
        ct: &CancellationToken,
        source: &str,
        destination: &str,
        domains: &[String],
    ) -> Result<usize> {
        if source == destination {
            return Ok(0);
        }
        if !self
            .options
            .issuers
            .iter()
            .any(|issuer| issuer.issuer_key() == destination)
        {
            return Err(conflict());
        }
        let storage = self.ground_truth_storage();
        let mut migrated = 0;
        for domain in domains {
            let domain = crate::certificate::normalized_name(domain);
            let guard =
                crate::storage::acquire_lock(ct, &storage, &format!("issue_cert_{domain}")).await?;
            self.cert_store().validate_write_guard(&guard)?;
            let key = format!(
                "migration-receipts/{}.json",
                crate::crypto::sha256_hex(format!("{source}\0{destination}\0{domain}").as_bytes())
            );
            let receipt = match storage.load(&key).await {
                Ok(bytes) => {
                    let receipt: Receipt =
                        serde_json::from_slice(&bytes).map_err(|_| conflict())?;
                    if receipt.version != 1
                        || receipt.source != source
                        || receipt.destination != destination
                        || receipt.domain != domain
                    {
                        return Err(conflict());
                    }
                    receipt
                }
                Err(Error::Storage(StorageError::NotFound(_))) => {
                    let Some(resource) = self.cert_store().load(source, &domain).await? else {
                        continue;
                    };
                    crate::certificate::make_certificate(
                        &resource.certificate_pem,
                        &resource.private_key_pem,
                    )?;
                    if let Some(existing) = self.cert_store().load(destination, &domain).await?
                        && digest(&existing)? != digest(&resource)?
                    {
                        return Err(conflict());
                    }
                    self.cert_store()
                        .save_with_lock(destination, &domain, &resource, &guard)
                        .await?;
                    let receipt = Receipt {
                        version: 1,
                        source: source.into(),
                        destination: destination.into(),
                        domain: domain.clone(),
                        digest: digest(&resource)?,
                        complete: false,
                    };
                    let verified = self
                        .cert_store()
                        .load(destination, &domain)
                        .await?
                        .ok_or_else(conflict)?;
                    if digest(&verified)? != receipt.digest {
                        return Err(conflict());
                    }
                    storage
                        .store_tx_with_lock(
                            &[(&key, serde_json::to_vec(&receipt).map_err(|_| conflict())?)],
                            &guard,
                        )
                        .await?;
                    receipt
                }
                Err(error) => return Err(error),
            };
            let verified = self
                .cert_store()
                .load(destination, &domain)
                .await?
                .ok_or_else(conflict)?;
            if digest(&verified)? != receipt.digest {
                return Err(conflict());
            }
            match self.cert_store().load(source, &domain).await {
                Ok(Some(current)) if digest(&current)? != receipt.digest => return Err(conflict()),
                Ok(_) => {}
                Err(error) => {
                    if let Some(public) =
                        self.cert_store().load_for_recovery(source, &domain).await?
                    {
                        if public.certificate_pem != verified.certificate_pem {
                            return Err(conflict());
                        }
                    } else {
                        return Err(error);
                    }
                }
            }
            let mut certificate = crate::certificate::make_certificate(
                &verified.certificate_pem,
                &verified.private_key_pem,
            )?;
            certificate.issuer_key = source.into();
            crate::ari::migrate(&storage, &certificate, destination, &guard).await?;
            let selection = format!(
                "certificate-selections/{}.json",
                crate::crypto::sha256_hex(domain.as_bytes())
            );
            storage
                .store_tx_with_lock(
                    &[(
                        &selection,
                        serde_json::to_vec(destination).map_err(|_| conflict())?,
                    )],
                    &guard,
                )
                .await?;
            self.cert_store()
                .remove_with_lock(source, &domain, &guard)
                .await?;
            let receipt = Receipt {
                complete: true,
                ..receipt
            };
            storage
                .store_tx_with_lock(
                    &[(&key, serde_json::to_vec(&receipt).map_err(|_| conflict())?)],
                    &guard,
                )
                .await?;
            migrated += 1;
        }
        Ok(migrated)
    }
}
