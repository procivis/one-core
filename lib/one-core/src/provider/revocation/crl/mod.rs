//! Implementation of ISO mDL (ISO/IEC 18013-5:2021).
//! https://www.iso.org/standard/69084.html

use std::sync::Arc;

use futures::FutureExt;
use num_traits::ToPrimitive;
use serde::{Deserialize, Serialize};
use serde_with::DurationSeconds;
use shared_types::{RevocationListEntryId, RevocationListId, RevocationMethodId};
use standardized_types::x509::CertificateSerial;
use time::OffsetDateTime;
use uuid::Uuid;

use super::model::{CredentialRevocationInfo, Operation};
use crate::mapper::x509::SigningKeyAdapter;
use crate::model::certificate::{Certificate, CertificateRelations};
use crate::model::credential::Credential;
use crate::model::identifier::Identifier;
use crate::model::revocation_list::{
    RevocationList, RevocationListEntityId, RevocationListEntityInfo, RevocationListEntryStatus,
    RevocationListPurpose, RevocationListRelations, StatusListCredentialFormat,
    UpdateRevocationListEntryId, UpdateRevocationListEntryRequest,
};
use crate::model::wallet_unit_attested_key::{
    WalletUnitAttestedKey, WalletUnitAttestedKeyRevocationInfo,
};
use crate::proto::certificate_validator::parse::extract_leaf_pem_from_chain;
use crate::proto::transaction_manager::TransactionManager;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{CredentialStatus, IdentifierDetails};
use crate::provider::key_storage::error::KeyStorageProviderError;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::RevocationMethod;
use crate::provider::revocation::error::RevocationError;
use crate::provider::revocation::model::{
    CredentialDataByRole, JsonLdContext, RevocationMethodCapabilities, RevocationState,
};
use crate::repository::error::DataLayerError;
use crate::repository::revocation_list_repository::RevocationListRepository;

#[cfg(test)]
mod test;

#[serde_with::serde_as]
#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    #[serde_as(as = "DurationSeconds<i64>")]
    pub refresh_interval: time::Duration,
}

pub struct CRLRevocation {
    config_id: RevocationMethodId,
    core_base_url: Option<String>,
    revocation_list_repository: Arc<dyn RevocationListRepository>,
    transaction_manager: Arc<dyn TransactionManager>,
    key_provider: Arc<dyn KeyProvider>,
    params: Params,
}

impl CRLRevocation {
    pub fn new(
        config_id: RevocationMethodId,
        core_base_url: Option<String>,
        revocation_list_repository: Arc<dyn RevocationListRepository>,
        transaction_manager: Arc<dyn TransactionManager>,
        key_provider: Arc<dyn KeyProvider>,
        params: Params,
    ) -> Self {
        Self {
            config_id,
            core_base_url,
            revocation_list_repository,
            transaction_manager,
            key_provider,
            params,
        }
    }
}

#[async_trait::async_trait]
impl RevocationMethod for CRLRevocation {
    fn get_status_type(&self) -> String {
        "CRL".to_string()
    }

    async fn add_issued_credential(
        &self,
        _credential: &Credential,
    ) -> Result<Vec<CredentialRevocationInfo>, RevocationError> {
        Err(RevocationError::OperationNotSupported(
            "CRL: credential revocation not supported".to_string(),
        ))
    }

    async fn mark_credential_as(
        &self,
        _credential: &Credential,
        _new_state: RevocationState,
    ) -> Result<(), RevocationError> {
        Err(RevocationError::OperationNotSupported(
            "CRL: credential revocation not supported".to_string(),
        ))
    }

    async fn check_credential_revocation_status(
        &self,
        _credential_status: &CredentialStatus,
        _issuer_details: &IdentifierDetails,
        _additional_credential_data: Option<CredentialDataByRole>,
        _force_refresh: bool,
    ) -> Result<RevocationState, RevocationError> {
        Err(RevocationError::OperationNotSupported(
            "CRL: credential revocation not supported".to_string(),
        ))
    }

    async fn add_issued_attestation(
        &self,
        _attestation: &WalletUnitAttestedKey,
    ) -> Result<CredentialRevocationInfo, RevocationError> {
        Err(RevocationError::OperationNotSupported(
            "CRL: attestation revocation not supported".to_string(),
        ))
    }

    async fn get_attestation_revocation_info(
        &self,
        _key_info: &WalletUnitAttestedKeyRevocationInfo,
    ) -> Result<CredentialRevocationInfo, RevocationError> {
        Err(RevocationError::OperationNotSupported(
            "CRL: attestation revocation not supported".to_string(),
        ))
    }

    async fn update_attestation_entries(
        &self,
        _keys: Vec<WalletUnitAttestedKeyRevocationInfo>,
        _new_state: RevocationState,
    ) -> Result<(), RevocationError> {
        Err(RevocationError::OperationNotSupported(
            "CRL: attestation revocation not supported".to_string(),
        ))
    }

    async fn add_signature(
        &self,
        signature_type: String,
        issuer: &Identifier,
        certificate: &Option<Certificate>,
    ) -> Result<(RevocationListEntryId, CredentialRevocationInfo), RevocationError> {
        let base_url = self
            .core_base_url
            .as_ref()
            .ok_or(RevocationError::MappingError(
                "Missing core_base_url".to_string(),
            ))?;

        let certificate = certificate.as_ref().ok_or(RevocationError::MappingError(
            "Missing certificate".to_string(),
        ))?;

        let list_id = self
            .transaction_manager
            .tx(async {
                let current_list = self
                    .revocation_list_repository
                    .get_revocation_by_issuer_identifier_id(
                        issuer.id,
                        Some(certificate.id),
                        RevocationListPurpose::Revocation,
                        &self.config_id,
                        &Default::default(),
                    )
                    .await?;

                Ok(match current_list {
                    Some(list) => list.id,
                    None => self
                        .start_new_list(issuer, certificate)
                        .await
                        .map_err(|e| DataLayerError::TransactionError(e.to_string()))?,
                })
            }
            .boxed())
            .await
            .flatten()
            .ok();

        let list_id = if let Some(list_id) = list_id {
            list_id
        } else {
            // this means the transaction failed, and a new list was created in parallel
            // fetch the newly created list instead
            self.revocation_list_repository
                .get_revocation_by_issuer_identifier_id(
                    issuer.id,
                    Some(certificate.id),
                    RevocationListPurpose::Revocation,
                    &self.config_id,
                    &Default::default(),
                )
                .await?
                .ok_or(RevocationError::MappingError(
                    "No revocation list found".to_string(),
                ))?
                .id
        };

        let serial = CertificateSerial::new_random();
        let entry_id = self
            .revocation_list_repository
            .create_entry(
                list_id,
                RevocationListEntityId::Signature(signature_type, Some(serial.to_owned())),
                None,
            )
            .await?;

        let crl_url = format!("{base_url}/ssi/revocation/v1/crl/{list_id}")
            .parse()
            .map_err(|e| RevocationError::ValidationError(format!("Failed to parse URL: `{e}`")))?;

        Ok((
            entry_id,
            CredentialRevocationInfo {
                credential_status: CredentialStatus {
                    id: Some(crl_url),
                    r#type: "CRL".to_string(),
                    status_purpose: None,
                    additional_fields: Default::default(),
                },
                serial: Some(serial),
            },
        ))
    }

    async fn revoke_signature(
        &self,
        signature_id: RevocationListEntryId,
    ) -> Result<(), RevocationError> {
        self.revocation_list_repository
            .update_entry(
                UpdateRevocationListEntryId::Id(signature_id),
                UpdateRevocationListEntryRequest {
                    status: Some(RevocationListEntryStatus::Revoked),
                },
            )
            .await?;

        let list = self
            .revocation_list_repository
            .get_revocation_list_by_entry_id(
                signature_id,
                &RevocationListRelations {
                    issuer_certificate: Some(CertificateRelations {
                        key: Some(Default::default()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
            .await?
            .ok_or(RevocationError::MappingError(
                "Missing revocation list".to_string(),
            ))?;

        let issuer_certificate = list
            .issuer_certificate
            .ok_or(RevocationError::MappingError(
                "Missing issuer_certificate".to_string(),
            ))?;

        let revoked_certificates = self
            .revocation_list_repository
            .get_entries(list.id)
            .await?
            .into_iter()
            .filter_map(|entry| {
                if entry.status == RevocationListEntryStatus::Revoked
                    && let RevocationListEntityInfo::Signature(_, Some(serial)) = entry.entity_info
                {
                    Some((serial, entry.last_modified))
                } else {
                    None
                }
            })
            .collect();

        let next_crl_number = match x509_parser::parse_x509_crl(&list.formatted_list) {
            Ok((_, previous_crl)) => {
                if let Some(previous_crl_number) =
                    previous_crl.crl_number().and_then(|n| n.to_u64())
                {
                    previous_crl_number + 1
                } else {
                    tracing::warn!("Previous CRL does not contain a valid CRL number");
                    0
                }
            }
            Err(e) => {
                tracing::warn!(%e, "Failed to parse previous CRL");
                0
            }
        };

        let formatted_list = self
            .format_list(next_crl_number, &issuer_certificate, revoked_certificates)
            .await?;

        self.revocation_list_repository
            .update_formatted_list(&list.id, formatted_list)
            .await?;

        Ok(())
    }

    fn get_capabilities(&self) -> RevocationMethodCapabilities {
        RevocationMethodCapabilities {
            operations: vec![Operation::Revoke],
        }
    }

    fn get_json_ld_context(&self) -> Result<JsonLdContext, RevocationError> {
        Err(RevocationError::OperationNotSupported(
            "CRL: json_ld not supported".to_string(),
        ))
    }
}

impl CRLRevocation {
    #[tracing::instrument(level = "debug", skip_all, err(level = "warn"))]
    async fn start_new_list(
        &self,
        issuer: &Identifier,
        certificate: &Certificate,
    ) -> Result<RevocationListId, RevocationError> {
        let formatted_list = self.format_list(0, certificate, vec![]).await?;

        let now = OffsetDateTime::now_utc();
        Ok(self
            .revocation_list_repository
            .create_revocation_list(RevocationList {
                id: Uuid::new_v4().into(),
                created_date: now,
                last_modified: now,
                formatted_list,
                format: StatusListCredentialFormat::X509Crl,
                r#type: self.config_id.to_owned(),
                purpose: RevocationListPurpose::Revocation,
                issuer_identifier: Some(issuer.to_owned()),
                issuer_certificate: Some(certificate.to_owned()),
            })
            .await?)
    }

    async fn format_list(
        &self,
        crl_number: u64,
        ca_certificate: &Certificate,
        revoked_certificates: Vec<(CertificateSerial, OffsetDateTime)>,
    ) -> Result<Vec<u8>, RevocationError> {
        let key = ca_certificate
            .key
            .as_ref()
            .ok_or(RevocationError::MappingError(
                "Missing certificate key".to_string(),
            ))?
            .to_owned();

        let key_storage = self.key_provider.get_key_storage(&key.storage_type).ok_or(
            KeyStorageProviderError::InvalidKeyStorage(key.storage_type.to_owned()),
        )?;

        let signing_key =
            SigningKeyAdapter::new(key, key_storage, tokio::runtime::Handle::current())
                .map_err(|e| RevocationError::ValidationError(e.to_string()))?;

        let pem = extract_leaf_pem_from_chain(ca_certificate.chain.as_bytes())
            .map_err(|e| RevocationError::ValidationError(e.to_string()))?;

        let ca_certificate = pem
            .parse_x509()
            .map_err(|e| RevocationError::ValidationError(e.to_string()))?;

        let key_identifier_method = ca_certificate
            .iter_extensions()
            .find_map(|ext| match ext.parsed_extension() {
                x509_parser::extensions::ParsedExtension::SubjectKeyIdentifier(key_id) => {
                    Some(rcgen::KeyIdMethod::PreSpecified(key_id.0.into()))
                }
                _ => None,
            })
            .unwrap_or(rcgen::KeyIdMethod::Sha256);

        let pem_str = pem::encode_config(
            &pem::Pem::new(pem.label, pem.contents),
            pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
        );

        let now = OffsetDateTime::now_utc();
        let crl_params = rcgen::CertificateRevocationListParams {
            this_update: now,
            next_update: now + self.params.refresh_interval,
            crl_number: crl_number.into(),
            issuing_distribution_point: None,
            revoked_certs: revoked_certificates
                .into_iter()
                .map(|(serial, revocation_time)| rcgen::RevokedCertParams {
                    serial_number: Vec::<u8>::from(serial).into(),
                    revocation_time,
                    reason_code: None,
                    invalidity_date: None,
                })
                .collect(),
            key_identifier_method,
        };

        let crl_issuer = rcgen::Issuer::from_ca_cert_pem(&pem_str, signing_key)
            .map_err(|e| RevocationError::ValidationError(e.to_string()))?;

        let crl = crl_params
            .signed_by(&crl_issuer)
            .map_err(|e| FormatterError::CouldNotSign(e.to_string()))?;

        Ok(crl.der().to_vec())
    }
}
