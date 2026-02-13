use std::sync::Arc;

use one_crypto::encryption::EncryptionError;
use shared_types::{CredentialId, CredentialSchemaId, RevocationMethodId};

use crate::config::core_config::{CoreConfig, FormatType};
use crate::error::{
    ContextWithErrorCode, ErrorCode, ErrorCodeMixin, ErrorCodeMixinExt, NestedError,
};
use crate::model::certificate::CertificateRelations;
use crate::model::credential::{
    Clearable, CredentialRelations, CredentialRole, CredentialStateEnum, UpdateCredentialRequest,
};
use crate::model::credential_schema::{CredentialSchema, CredentialSchemaRelations};
use crate::model::did::DidRelations;
use crate::model::identifier::{Identifier, IdentifierRelations, IdentifierType};
use crate::model::interaction::InteractionRelations;
use crate::model::key::KeyRelations;
use crate::model::organisation::OrganisationRelations;
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::http_client::HttpClient;
use crate::proto::session_provider::SessionProvider;
use crate::provider::blob_storage_provider::{BlobStorageProvider, BlobStorageType};
use crate::provider::credential_formatter::model::{CertificateDetails, IdentifierDetails};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::model::{CredentialDataByRole, RevocationState};
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::service::error::{EntityNotFoundError, MissingProviderError};
use crate::validator::{
    throw_if_credential_schema_not_in_session_org, throw_if_org_relation_not_matching_session,
};

mod mdoc;
#[cfg(test)]
mod test;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait CredentialValidityManager: Send + Sync {
    async fn change_credential_validity_state(
        &self,
        credential_id: &CredentialId,
        revocation_state: RevocationState,
    ) -> Result<(), Error>;

    async fn check_holder_credential_validity(
        &self,
        credential_id: CredentialId,
        force_refresh: bool,
    ) -> Result<CredentialValidityCheckResult, Error>;
}

#[derive(Clone, Debug)]
pub struct CredentialValidityCheckResult {
    pub credential_id: CredentialId,
    pub status: CredentialStateEnum,
    pub success: bool,
    pub reason: Option<String>,
}

#[derive(Debug, thiserror::Error)]
#[expect(clippy::enum_variant_names)]
pub enum Error {
    #[error("Mapping error: `{0}`")]
    MappingError(String),
    #[error("Json error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("No revocation method configured on credential schema {0}")]
    NoRevocationMethod(CredentialSchemaId),
    #[error("Suspension not supported by revocation method `{revocation_method}`")]
    SuspensionNotSupported { revocation_method: String },
    #[error("Invalid credential state transition from state `{current_state}` to `{target_state}`")]
    InvalidCredentialStateTransition {
        current_state: CredentialStateEnum,
        target_state: CredentialStateEnum,
    },
    #[error("Incompatible issuer identifier")]
    IncompatibleIssuerIdentifier,
    #[error("Credential role must be Holder, received {role}, credential id: {credential_id}")]
    RevocationCheckNotAllowedForRole {
        role: CredentialRole,
        credential_id: CredentialId,
    },
    #[error("Encryption error: {0}")]
    EncryptionError(#[from] EncryptionError),
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for Error {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::MappingError(_) => ErrorCode::BR_0000,
            Self::JsonError(_) => ErrorCode::BR_0189,
            Self::NoRevocationMethod(_) => ErrorCode::BR_0098,
            Self::SuspensionNotSupported { .. } => ErrorCode::BR_0162,
            Self::InvalidCredentialStateTransition { .. } => ErrorCode::BR_0366,
            Self::IncompatibleIssuerIdentifier => ErrorCode::BR_0218,
            Self::RevocationCheckNotAllowedForRole { .. } => ErrorCode::BR_0197,
            Self::EncryptionError(_) => ErrorCode::BR_0368,
            Self::Nested(nested_error) => nested_error.error_code(),
        }
    }
}

pub struct CredentialValidityManagerImpl {
    credential_repository: Arc<dyn CredentialRepository>,
    interaction_repository: Arc<dyn InteractionRepository>,
    client: Arc<dyn HttpClient>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    certificate_validator: Arc<dyn CertificateValidator>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    blob_storage_provider: Arc<dyn BlobStorageProvider>,
    session_provider: Arc<dyn SessionProvider>,
    config: Arc<CoreConfig>,
}

impl CredentialValidityManagerImpl {
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        credential_repository: Arc<dyn CredentialRepository>,
        interaction_repository: Arc<dyn InteractionRepository>,
        client: Arc<dyn HttpClient>,
        key_provider: Arc<dyn KeyProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        certificate_validator: Arc<dyn CertificateValidator>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        blob_storage_provider: Arc<dyn BlobStorageProvider>,
        session_provider: Arc<dyn SessionProvider>,
        config: Arc<CoreConfig>,
    ) -> Self {
        Self {
            credential_repository,
            interaction_repository,
            client,
            key_provider,
            key_algorithm_provider,
            certificate_validator,
            did_method_provider,
            revocation_method_provider,
            formatter_provider,
            blob_storage_provider,
            session_provider,
            config,
        }
    }
}

#[async_trait::async_trait]
impl CredentialValidityManager for CredentialValidityManagerImpl {
    async fn change_credential_validity_state(
        &self,
        credential_id: &CredentialId,
        revocation_state: RevocationState,
    ) -> Result<(), Error> {
        let credential = self
            .credential_repository
            .get_credential(
                credential_id,
                &CredentialRelations {
                    issuer_identifier: Some(IdentifierRelations {
                        did: Some(DidRelations {
                            keys: Some(KeyRelations::default()),
                            ..Default::default()
                        }),
                        certificates: Some(CertificateRelations {
                            key: Some(KeyRelations::default()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    issuer_certificate: Some(Default::default()),
                    holder_identifier: Some(IdentifierRelations {
                        did: Some(DidRelations {
                            keys: Some(KeyRelations::default()),
                            ..Default::default()
                        }),
                        key: Some(KeyRelations::default()),
                        ..Default::default()
                    }),
                    schema: Some(CredentialSchemaRelations {
                        organisation: Some(OrganisationRelations::default()),
                        ..Default::default()
                    }),
                    key: Some(KeyRelations::default()),
                    ..Default::default()
                },
            )
            .await
            .error_while("getting credential")?
            .ok_or(EntityNotFoundError::Credential(*credential_id))
            .error_while("getting credential")?;

        if credential.deleted_at.is_some() {
            return Err(EntityNotFoundError::Credential(*credential_id)
                .error_while("validating credential")
                .into());
        }

        let credential_schema = credential
            .schema
            .as_ref()
            .ok_or(Error::MappingError("credential schema is None".to_string()))?;

        throw_if_org_relation_not_matching_session(
            credential_schema.organisation.as_ref(),
            &*self.session_provider,
        )
        .error_while("verifying organisation")?;

        let revocation_method_id = credential_schema
            .revocation_method
            .as_ref()
            .ok_or(Error::NoRevocationMethod(credential_schema.id.to_owned()))?;
        verify_suspension_support(credential_schema, revocation_method_id, &revocation_state)?;
        validate_state_transition(credential.state, &revocation_state)?;

        let revocation_method = self
            .revocation_method_provider
            .get_revocation_method(revocation_method_id)
            .ok_or(MissingProviderError::RevocationMethod(
                revocation_method_id.to_owned(),
            ))
            .error_while("getting revocation method")?;

        revocation_method
            .mark_credential_as(&credential, revocation_state.to_owned())
            .await
            .error_while("marking credential status")?;

        let suspend_end_date =
            if let RevocationState::Suspended { suspend_end_date } = &revocation_state {
                suspend_end_date.to_owned()
            } else {
                None
            };
        self.credential_repository
            .update_credential(
                *credential_id,
                UpdateCredentialRequest {
                    state: Some(revocation_state.to_owned().into()),
                    suspend_end_date: Clearable::ForceSet(suspend_end_date),
                    ..Default::default()
                },
            )
            .await
            .error_while("updating credential")?;
        Ok(())
    }

    async fn check_holder_credential_validity(
        &self,
        credential_id: CredentialId,
        force_refresh: bool,
    ) -> Result<CredentialValidityCheckResult, Error> {
        let credential = self
            .credential_repository
            .get_credential(
                &credential_id,
                &CredentialRelations {
                    schema: Some(CredentialSchemaRelations {
                        organisation: Some(OrganisationRelations::default()),
                        ..Default::default()
                    }),
                    issuer_identifier: Some(IdentifierRelations {
                        did: Some(DidRelations {
                            keys: Some(KeyRelations::default()),
                            ..Default::default()
                        }),
                        certificates: Some(CertificateRelations {
                            key: Some(KeyRelations::default()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    holder_identifier: Some(IdentifierRelations {
                        did: Some(DidRelations {
                            keys: Some(KeyRelations::default()),
                            ..Default::default()
                        }),
                        key: Some(KeyRelations::default()),
                        ..Default::default()
                    }),
                    interaction: Some(InteractionRelations {
                        organisation: Some(OrganisationRelations::default()),
                    }),
                    key: Some(KeyRelations::default()),
                    ..Default::default()
                },
            )
            .await
            .error_while("getting credential")?
            .ok_or(
                EntityNotFoundError::Credential(credential_id).error_while("getting credential"),
            )?;
        throw_if_credential_schema_not_in_session_org(&credential, &*self.session_provider)
            .error_while("verifying credential schema organisation")?;

        if credential.deleted_at.is_some() {
            return Err(EntityNotFoundError::Credential(credential_id)
                .error_while("validating credential")
                .into());
        }
        if credential.role != CredentialRole::Holder {
            return Err(Error::RevocationCheckNotAllowedForRole {
                role: credential.role,
                credential_id,
            });
        }

        let current_state = credential.state;
        match current_state {
            CredentialStateEnum::Accepted | CredentialStateEnum::Suspended => {
                // continue flow
            }
            CredentialStateEnum::Revoked => {
                // credential already revoked, no need to check further
                return Ok(CredentialValidityCheckResult {
                    credential_id,
                    status: CredentialStateEnum::Revoked,
                    success: true,
                    reason: None,
                });
            }
            _ => {
                // cannot check pending/offered credentials etc
                return Ok(CredentialValidityCheckResult {
                    credential_id,
                    success: false,
                    reason: Some(format!("Invalid credential state: {current_state}")),
                    status: current_state,
                });
            }
        };

        let credential_schema = credential
            .schema
            .as_ref()
            .ok_or(Error::MappingError("schema is None".to_string()))?
            .clone();

        let credentials = if let Some(credential_blob_id) = credential.credential_blob_id {
            let blob_storage = self
                .blob_storage_provider
                .get_blob_storage(BlobStorageType::Db)
                .await
                .ok_or_else(|| MissingProviderError::BlobStorage(BlobStorageType::Db.to_string()))
                .error_while("getting blob storage")?;

            blob_storage
                .get(&credential_blob_id)
                .await
                .error_while("getting credential blob")?
                .ok_or(Error::MappingError("credential blob is None".to_string()))?
                .value
        } else {
            vec![]
        };

        let credential_str =
            String::from_utf8(credentials).map_err(|e| Error::MappingError(e.to_string()))?;

        let formatter = self
            .formatter_provider
            .get_credential_formatter(&credential_schema.format)
            .ok_or(MissingProviderError::Formatter(
                credential_schema.format.to_string(),
            ))
            .error_while("getting credential formatter")?;

        let detail_credential = formatter
            .extract_credentials_unverified(&credential_str, Some(&credential_schema))
            .await
            .error_while("extracting credential")?;

        let format_type = self
            .config
            .format
            .get_fields(&credential_schema.format)
            .error_while("getting credential format type")?
            .r#type;
        if format_type == FormatType::Mdoc {
            // Mdoc flow ends here. Nothing else to do for MDOC, since it does not have revocation mechanism
            return self
                .update_mdoc(&credential, &detail_credential, force_refresh)
                .await;
        }

        let credential_status = if !detail_credential.status.is_empty() {
            detail_credential.status
        } else {
            // no credential status -> credential is irrevocable
            return Ok(CredentialValidityCheckResult {
                credential_id,
                status: CredentialStateEnum::Accepted,
                success: true,
                reason: None,
            });
        };

        let revocation_method = match &credential_schema.revocation_method {
            Some(method_id) => self
                .revocation_method_provider
                .get_revocation_method(method_id)
                .ok_or(MissingProviderError::RevocationMethod(method_id.clone()))
                .error_while("getting revocation method")?,
            None => {
                return Ok(CredentialValidityCheckResult {
                    credential_id,
                    status: current_state,
                    success: false,
                    reason: Some("No revocation method specified for credential".to_owned()),
                });
            }
        };

        let issuer_identifier = credential
            .issuer_identifier
            .as_ref()
            .ok_or(Error::MappingError("issuer_identifier is None".to_string()))?;

        let credential_data_by_role = match credential.role {
            CredentialRole::Holder => {
                Some(CredentialDataByRole::Holder(Box::new(credential.clone())))
            }
            CredentialRole::Issuer | CredentialRole::Verifier => None,
        };

        let mut worst_revocation_state = RevocationState::Valid;
        for status in credential_status {
            match revocation_method
                .check_credential_revocation_status(
                    &status,
                    &issuer_details(issuer_identifier)?,
                    credential_data_by_role.to_owned(),
                    force_refresh,
                )
                .await
            {
                Err(error) => {
                    return Ok(CredentialValidityCheckResult {
                        credential_id,
                        status: current_state,
                        success: false,
                        reason: Some(error.to_string()),
                    });
                }
                Ok(state) => match state {
                    RevocationState::Valid => {}
                    RevocationState::Revoked => {
                        worst_revocation_state = state;
                        break;
                    }
                    RevocationState::Suspended { .. } => {
                        worst_revocation_state = state;
                    }
                },
            };
        }

        let suspend_end_date = match &worst_revocation_state {
            RevocationState::Suspended { suspend_end_date } => suspend_end_date.to_owned(),
            _ => None,
        };
        let detected_state = worst_revocation_state.into();

        // update local credential state if change detected
        if current_state != detected_state {
            self.credential_repository
                .update_credential(
                    credential_id,
                    UpdateCredentialRequest {
                        state: Some(detected_state),
                        suspend_end_date: Clearable::ForceSet(suspend_end_date),
                        ..Default::default()
                    },
                )
                .await
                .error_while("updating credential")?;
        }

        Ok(CredentialValidityCheckResult {
            credential_id,
            status: detected_state,
            success: true,
            reason: None,
        })
    }
}

fn verify_suspension_support(
    credential_schema: &CredentialSchema,
    revocation_method: &RevocationMethodId,
    revocation_state: &RevocationState,
) -> Result<(), Error> {
    if !credential_schema.allow_suspension
        && matches!(revocation_state, RevocationState::Suspended { .. })
    {
        return Err(Error::SuspensionNotSupported {
            revocation_method: revocation_method.to_string(),
        });
    }
    Ok(())
}

fn issuer_details(issuer_identifier: &Identifier) -> Result<IdentifierDetails, Error> {
    Ok(match issuer_identifier.r#type {
        IdentifierType::Did => {
            let issuer_did = issuer_identifier
                .did
                .as_ref()
                .ok_or(Error::MappingError("issuer_did is None".to_string()))?;

            IdentifierDetails::Did(issuer_did.did.clone())
        }
        IdentifierType::Certificate => {
            let certificate = issuer_identifier
                .certificates
                .as_ref()
                .ok_or(Error::MappingError(
                    "issuer certificates is None".to_string(),
                ))?
                .first()
                .ok_or(Error::MappingError(
                    "issuer certificate is missing".to_string(),
                ))?
                .to_owned();

            IdentifierDetails::Certificate(CertificateDetails {
                chain: certificate.chain,
                fingerprint: certificate.fingerprint,
                expiry: certificate.expiry_date,
                subject_common_name: None,
            })
        }
        _ => {
            return Err(Error::IncompatibleIssuerIdentifier);
        }
    })
}

fn validate_state_transition(
    current_state: CredentialStateEnum,
    target_state: &RevocationState,
) -> Result<(), Error> {
    let valid_states: &[CredentialStateEnum] = match target_state {
        RevocationState::Revoked => &[
            CredentialStateEnum::Accepted,
            CredentialStateEnum::Suspended,
        ],
        RevocationState::Valid => &[CredentialStateEnum::Suspended],
        RevocationState::Suspended { .. } => &[CredentialStateEnum::Accepted],
    };
    if !valid_states.contains(&current_state) {
        return Err(Error::InvalidCredentialStateTransition {
            current_state,
            target_state: target_state.clone().into(),
        });
    }
    Ok(())
}
