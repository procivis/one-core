use std::sync::Arc;

use futures::FutureExt;
use one_crypto::encryption::EncryptionError;
use shared_types::{CredentialId, CredentialSchemaId, RevocationMethodId};
use time::OffsetDateTime;
use tracing::warn;

use crate::config::core_config::{BlobStorageType, CoreConfig, FormatType};
use crate::error::{
    ContextWithErrorCode, ErrorCode, ErrorCodeMixin, ErrorCodeMixinExt, NestedError,
};
use crate::model::credential::{
    Clearable, Credential, CredentialFilterValue, CredentialRole, CredentialStateEnum,
    CredentialType, UpdateCredentialRequest,
};
use crate::model::credential_schema::CredentialSchema;
use crate::model::identifier::{Identifier, IdentifierData};
use crate::model::interaction::Interaction;
use crate::model::list_filter::ListFilterValue;
use crate::model::list_query::ListQuery;
use crate::proto::credential_validity_manager::dto::{
    ChangeCredentialState, ChangeType, ExpirationState,
};
use crate::proto::session_provider::SessionProvider;
use crate::proto::transaction_manager::TransactionManager;
use crate::provider::blob_storage::provider::BlobStorageProvider;
use crate::provider::credential_formatter::model::{CertificateDetails, IdentifierDetails};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::issuance_protocol::deserialize_interaction_data;
use crate::provider::issuance_protocol::provider::IssuanceProtocolProvider;
use crate::provider::revocation::RevocationMethod;
use crate::provider::revocation::mapper::revocation_state_from_credential_state;
use crate::provider::revocation::model::{CredentialDataByRole, RevocationState};
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::repository::credential_repository::CredentialRepository;
use crate::service::error::EntityNotFoundError;
use crate::validator::{
    throw_if_credential_schema_not_in_session_org, throw_if_org_id_not_matching_session,
};

pub mod dto;
mod mapper;
mod mdoc;
#[cfg(test)]
mod test;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait CredentialValidityManager: Send + Sync {
    async fn change_credential_state(
        &self,
        credential_id: &CredentialId,
        change_credential_state: ChangeCredentialState,
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
    #[error(
        "Invalid credential state transition from state `{current_state}` to `{target_state}` for type `{current_type}`"
    )]
    InvalidCredentialStateTransition {
        current_state: CredentialStateEnum,
        target_state: CredentialStateEnum,
        current_type: CredentialType,
    },
    #[error("Incompatible issuer identifier")]
    IncompatibleIssuerIdentifier,
    #[error("Invalid credential role `{role}`, credential id: {credential_id}")]
    InvalidCredentialRole {
        role: CredentialRole,
        credential_id: CredentialId,
    },
    #[error("Invalid credential type: {0}")]
    InvalidCredentialType(CredentialType),
    #[error("Encryption error: {0}")]
    EncryptionError(#[from] EncryptionError),
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for Error {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::MappingError(_) => ErrorCode::BR_0047,
            Self::JsonError(_) => ErrorCode::BR_0189,
            Self::NoRevocationMethod(_) => ErrorCode::BR_0098,
            Self::SuspensionNotSupported { .. } => ErrorCode::BR_0162,
            Self::InvalidCredentialStateTransition { .. } => ErrorCode::BR_0366,
            Self::IncompatibleIssuerIdentifier => ErrorCode::BR_0218,
            Self::InvalidCredentialRole { .. } => ErrorCode::BR_0197,
            Self::InvalidCredentialType(_) => ErrorCode::BR_0442,
            Self::EncryptionError(_) => ErrorCode::BR_0368,
            Self::Nested(nested_error) => nested_error.error_code(),
        }
    }
}

pub struct CredentialValidityManagerImpl {
    credential_repository: Arc<dyn CredentialRepository>,
    issuance_protocol_provider: Arc<dyn IssuanceProtocolProvider>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    blob_storage_provider: Arc<dyn BlobStorageProvider>,
    session_provider: Arc<dyn SessionProvider>,
    tx_manager: Arc<dyn TransactionManager>,
    config: Arc<CoreConfig>,
}

impl CredentialValidityManagerImpl {
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        credential_repository: Arc<dyn CredentialRepository>,
        issuance_protocol_provider: Arc<dyn IssuanceProtocolProvider>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        blob_storage_provider: Arc<dyn BlobStorageProvider>,
        session_provider: Arc<dyn SessionProvider>,
        tx_manager: Arc<dyn TransactionManager>,
        config: Arc<CoreConfig>,
    ) -> Self {
        Self {
            credential_repository,
            issuance_protocol_provider,
            revocation_method_provider,
            formatter_provider,
            blob_storage_provider,
            session_provider,
            tx_manager,
            config,
        }
    }

    async fn change_credential_revocation_state(
        &self,
        credential: Credential,
        credential_schema: CredentialSchema,
        revocation_state: RevocationState,
    ) -> Result<(), Error> {
        validate_revocation_state_transition(
            credential.state,
            credential.r#type,
            &revocation_state,
        )?;
        let format = credential_schema.format().await?;
        let formatter = self.formatter_provider.get_credential_formatter(&format)?;

        let revocation_method_id = credential_schema
            .revocation_method_id(formatter.as_ref())
            .ok_or(Error::NoRevocationMethod(credential_schema.id.to_owned()))?;
        verify_suspension_support(&credential_schema, revocation_method_id, &revocation_state)?;

        let revocation_method = self
            .revocation_method_provider
            .get_revocation_method(revocation_method_id)?;

        match credential.r#type {
            CredentialType::Single => {
                self.change_revocation_state(
                    credential.id,
                    revocation_state,
                    revocation_method.as_ref(),
                )
                .await?;
            }
            CredentialType::BatchItem => {
                // only batch members can be individually updated, not MDOC MSO's
                let parent = credential
                    .parent
                    .as_ref()
                    .ok_or(Error::MappingError(
                        "Missing parent of batch item".to_string(),
                    ))?
                    .as_ref()
                    .await?;
                if parent.r#type != CredentialType::BatchParent {
                    return Err(Error::InvalidCredentialType(credential.r#type));
                }

                let parent_status =
                    revocation_state_from_credential_state(parent.state, parent.suspend_end_date)
                        .error_while("parsing status")?;

                self.tx_manager
                    .tx(async {
                        self.change_revocation_state(
                            credential.id,
                            revocation_state,
                            revocation_method.as_ref(),
                        )
                        .await?;

                        // update parent state if needed
                        if parent_status != revocation_state {
                            let batch_items = self
                                .credential_repository
                                .get_credential_list(ListQuery {
                                    filtering: Some(
                                        CredentialFilterValue::ParentCredential(parent.id)
                                            .condition()
                                            & CredentialFilterValue::Deleted(false),
                                    ),
                                    ..Default::default()
                                })
                                .await
                                .error_while("getting batch items")?
                                .values;

                            let item_states = batch_items
                                .into_iter()
                                .map(|c| {
                                    revocation_state_from_credential_state(
                                        c.state,
                                        c.suspend_end_date,
                                    )
                                })
                                .collect::<Result<Vec<_>, _>>()
                                .error_while("getting batch items states")?;

                            self.update_batch_parent_state(&parent, &item_states)
                                .await?;
                        }

                        Ok::<_, Error>(())
                    }
                    .boxed())
                    .await
                    .error_while("changing batch item state")??;
            }
            CredentialType::BatchParent => {
                // all underlying batch items must be updated
                let credentials = self
                    .credential_repository
                    .get_credential_list(ListQuery {
                        filtering: Some(
                            CredentialFilterValue::ParentCredential(credential.id).condition()
                                & CredentialFilterValue::Deleted(false),
                        ),
                        ..Default::default()
                    })
                    .await
                    .error_while("getting batch items")?
                    .values;

                let mut batch_items_to_update = vec![];
                for credential in credentials {
                    // skipping items with the target state
                    // except Suspension, since there might be change in `suspend_end_date`
                    if credential.state != CredentialStateEnum::Suspended
                        && credential.state == revocation_state.into()
                    {
                        continue;
                    }

                    validate_revocation_state_transition(
                        credential.state,
                        credential.r#type,
                        &revocation_state,
                    )
                    .error_while(format!(
                        "checking state of batch credential `{}`",
                        credential.id
                    ))?;

                    batch_items_to_update.push(credential.id);
                }

                self.tx_manager
                    .tx(async {
                        for batch_item_id in batch_items_to_update {
                            self.change_revocation_state(
                                batch_item_id,
                                revocation_state,
                                revocation_method.as_ref(),
                            )
                            .await?;
                        }

                        // batch parent not linked directly with any technical credential, only update state
                        self.update_credential_state(credential.id, revocation_state)
                            .await?;

                        Ok::<_, Error>(())
                    }
                    .boxed())
                    .await
                    .error_while("changing batch parent state")??;
            }
        };

        Ok(())
    }

    async fn change_credential_expiration_state(
        &self,
        credential: Credential,
        expiration_state: ExpirationState,
    ) -> Result<(), Error> {
        validate_expiration_state_transition(
            credential.state,
            credential.r#type,
            &expiration_state,
        )?;
        match credential.r#type {
            CredentialType::BatchParent => {
                self.credential_repository
                    .update_credential(
                        credential.id,
                        UpdateCredentialRequest {
                            state: Some(expiration_state.into()),
                            ..Default::default()
                        },
                    )
                    .await
                    .error_while("updating credential")?;
                Ok(())
            }
            CredentialType::Single | CredentialType::BatchItem => {
                warn!(
                    "Credential expiration is not supported for {} credential",
                    credential.r#type
                );
                Err(Error::InvalidCredentialType(credential.r#type))
            }
        }
    }

    async fn change_revocation_state(
        &self,
        credential_id: CredentialId,
        revocation_state: RevocationState,
        revocation_method: &dyn RevocationMethod,
    ) -> Result<(), Error> {
        let credential = self
            .credential_repository
            .get_credential(&credential_id)
            .await
            .error_while("getting credential")?;

        revocation_method
            .mark_credential_as(&credential, revocation_state.to_owned())
            .await
            .error_while("marking credential status")?;

        self.update_credential_state(credential_id, revocation_state)
            .await?;

        Ok(())
    }

    async fn update_credential_state(
        &self,
        credential_id: CredentialId,
        revocation_state: RevocationState,
    ) -> Result<(), Error> {
        let suspend_end_date =
            if let RevocationState::Suspended { suspend_end_date } = &revocation_state {
                suspend_end_date.to_owned()
            } else {
                None
            };
        self.credential_repository
            .update_credential(
                credential_id,
                UpdateCredentialRequest {
                    state: Some(revocation_state.into()),
                    suspend_end_date: Clearable::ForceSet(suspend_end_date),
                    ..Default::default()
                },
            )
            .await
            .error_while("updating credential")?;
        Ok(())
    }

    async fn check_status_for_single_credential(
        &self,
        credential: &Credential,
        credential_schema: &CredentialSchema,
        force_refresh: bool,
    ) -> Result<(CredentialValidityCheckResult, Option<OffsetDateTime>), Error> {
        if let Some(result) = check_invalid_or_terminal_state(credential) {
            return Ok((result, None));
        }

        if credential
            .expires_at
            .is_some_and(|expires_at| expires_at < crate::clock::now_utc())
        {
            self.credential_repository
                .update_credential(
                    credential.id,
                    UpdateCredentialRequest {
                        state: Some(CredentialStateEnum::Expired),
                        ..Default::default()
                    },
                )
                .await
                .error_while("updating credential")?;

            return Ok((
                CredentialValidityCheckResult {
                    credential_id: credential.id,
                    status: CredentialStateEnum::Expired,
                    success: true,
                    reason: None,
                },
                None,
            ));
        }

        let Some(credential_blob_id) = credential.credential_blob_id else {
            return Err(Error::MappingError("no credential blob_id".to_string()));
        };

        let blob_storage = self
            .blob_storage_provider
            .get_blob_storage(BlobStorageType::Db)?;

        let blob = blob_storage
            .get(&credential_blob_id)
            .await
            .error_while("getting credential blob")?
            .ok_or(Error::MappingError("credential blob is None".to_string()))?;

        let credential_str = String::from_utf8(blob.value)
            .map_err(|e| Error::MappingError(e.to_string()))?
            .into();

        let format = credential_schema
            .format()
            .await
            .error_while("getting format")?;

        let formatter = self.formatter_provider.get_credential_formatter(&format)?;

        let detail_credential = formatter
            .extract_credentials_unverified(&credential_str, Some(credential_schema))
            .await
            .error_while("extracting credential")?;

        let credential_status = if !detail_credential.status.is_empty() {
            detail_credential.status
        } else {
            // no credential status -> credential is irrevocable
            return Ok((
                CredentialValidityCheckResult {
                    credential_id: credential.id,
                    status: CredentialStateEnum::Accepted,
                    success: true,
                    reason: None,
                },
                None,
            ));
        };

        let current_state = credential.state;
        let revocation_method = match credential_schema.revocation_method_id(formatter.as_ref()) {
            Some(method_id) => self
                .revocation_method_provider
                .get_revocation_method(method_id)?,
            None => {
                return Ok((
                    CredentialValidityCheckResult {
                        credential_id: credential.id,
                        status: current_state,
                        success: false,
                        reason: Some("No revocation method specified for credential".to_owned()),
                    },
                    None,
                ));
            }
        };

        let issuer_identifier = credential
            .issuer_identifier
            .as_ref()
            .ok_or(Error::MappingError("issuer_identifier is None".to_string()))?
            .as_ref()
            .await?;

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
                    &issuer_details(&issuer_identifier).await?,
                    credential_data_by_role.to_owned(),
                    force_refresh,
                )
                .await
            {
                Err(error) => {
                    return Ok((
                        CredentialValidityCheckResult {
                            credential_id: credential.id,
                            status: current_state,
                            success: false,
                            reason: Some(error.to_string()),
                        },
                        None,
                    ));
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
                    credential.id,
                    UpdateCredentialRequest {
                        state: Some(detected_state),
                        suspend_end_date: Clearable::ForceSet(suspend_end_date),
                        ..Default::default()
                    },
                )
                .await
                .error_while("updating credential")?;
        }

        Ok((
            CredentialValidityCheckResult {
                credential_id: credential.id,
                status: detected_state,
                success: true,
                reason: None,
            },
            suspend_end_date,
        ))
    }

    async fn update_batch_parent_state(
        &self,
        credential: &Credential,
        item_states: &[RevocationState],
    ) -> Result<(), Error> {
        if item_states.is_empty() {
            tracing::warn!("Empty batch parent");
            return Ok(());
        }

        let best_state = get_best_state(item_states);
        let overall_best_suspend_end_date =
            if let RevocationState::Suspended { suspend_end_date } = best_state {
                suspend_end_date
            } else {
                None
            };

        // update parent credential state if change detected (use the best state among the items)
        if credential.state != best_state.into()
            || (credential.state == CredentialStateEnum::Suspended
                && credential.suspend_end_date != overall_best_suspend_end_date)
        {
            self.credential_repository
                .update_credential(
                    credential.id,
                    UpdateCredentialRequest {
                        state: Some(best_state.into()),
                        suspend_end_date: Clearable::ForceSet(overall_best_suspend_end_date),
                        ..Default::default()
                    },
                )
                .await
                .error_while("updating batch parent credential")?;
        }

        Ok(())
    }

    /// Aggregates per-item states into the batch parent's state. A batch parent is only ever
    /// EXPIRED once its own business-level `expires_at` has passed, or sooner if the shared
    /// OAuth refresh token has already expired - `expires_at` is authoritative regardless of
    /// item states, and a still-valid refresh token past `expires_at` does not keep the batch
    /// alive. Otherwise, the parent's state is the best-state aggregation among its items.
    async fn finalize_batch_parent_state(
        &self,
        parent: &Credential,
        interaction: Option<&Interaction>,
        item_revocation_states: &[RevocationState],
    ) -> Result<CredentialStateEnum, Error> {
        if is_batch_parent_expired(parent, interaction, crate::clock::now_utc())? {
            if parent.state != CredentialStateEnum::Expired {
                self.credential_repository
                    .update_credential(
                        parent.id,
                        UpdateCredentialRequest {
                            state: Some(CredentialStateEnum::Expired),
                            ..Default::default()
                        },
                    )
                    .await
                    .error_while("updating batch parent credential")?;
            }
            return Ok(CredentialStateEnum::Expired);
        }

        if item_revocation_states.is_empty() {
            return Ok(parent.state);
        }

        self.update_batch_parent_state(parent, item_revocation_states)
            .await?;
        Ok(get_best_state(item_revocation_states).into())
    }
}

pub(crate) fn is_batch_parent_expired(
    parent: &Credential,
    interaction: Option<&Interaction>,
    now: OffsetDateTime,
) -> Result<bool, Error> {
    if parent.expires_at.is_some_and(|expires_at| expires_at < now) {
        return Ok(true);
    }
    batch_refresh_token_expired(interaction)
}

/// Only the `refresh_token_expires_at` field is relevant here, so we deserialize into this
/// minimal shape instead of the full `HolderInteractionData` - that struct requires fields
/// (e.g. `issuer_url`) that aren't present on every interaction (e.g. issuer-role ones),
/// which would otherwise make this fail for interactions it isn't meant to model.
#[derive(serde::Deserialize)]
struct RefreshTokenInteractionData {
    #[serde(default, with = "time::serde::rfc3339::option")]
    refresh_token_expires_at: Option<OffsetDateTime>,
}

fn batch_refresh_token_expired(interaction: Option<&Interaction>) -> Result<bool, Error> {
    let Some(interaction) = interaction else {
        return Ok(false);
    };
    let data: RefreshTokenInteractionData = deserialize_interaction_data(interaction.data.as_ref())
        .error_while("parsing interaction data")?;

    Ok(data
        .refresh_token_expires_at
        .is_some_and(|expires_at| expires_at < crate::clock::now_utc()))
}

#[async_trait::async_trait]
impl CredentialValidityManager for CredentialValidityManagerImpl {
    async fn change_credential_state(
        &self,
        credential_id: &CredentialId,
        change_credential_state: ChangeCredentialState,
    ) -> Result<(), Error> {
        let credential = self
            .credential_repository
            .get_credential(credential_id)
            .await
            .error_while("getting credential")?;

        if credential.deleted_at.is_some() {
            return Err(EntityNotFoundError::Credential(*credential_id)
                .error_while("validating credential")
                .into());
        }
        if credential.role != CredentialRole::Issuer {
            return Err(Error::InvalidCredentialRole {
                role: credential.role,
                credential_id: credential.id,
            });
        }

        let credential_schema = credential.schema.as_ref().await?.clone();

        throw_if_org_id_not_matching_session(
            credential_schema.organisation.id_ref(),
            &*self.session_provider,
        )
        .error_while("verifying organisation")?;

        match change_credential_state.to_change_type(&credential) {
            ChangeType::Expiration(expiration_state) => {
                self.change_credential_expiration_state(credential, expiration_state)
                    .await
            }
            ChangeType::Revocation(revocation_state) => {
                self.change_credential_revocation_state(
                    credential,
                    credential_schema,
                    revocation_state,
                )
                .await
            }
        }
    }

    async fn check_holder_credential_validity(
        &self,
        credential_id: CredentialId,
        force_refresh: bool,
    ) -> Result<CredentialValidityCheckResult, Error> {
        let credential = self
            .credential_repository
            .get_credential(&credential_id)
            .await
            .error_while("getting credential")?;
        throw_if_credential_schema_not_in_session_org(&credential, &*self.session_provider)
            .await
            .error_while("verifying credential schema organisation")?;

        if credential.deleted_at.is_some() {
            return Err(EntityNotFoundError::Credential(credential_id)
                .error_while("validating credential")
                .into());
        }
        if credential.role != CredentialRole::Holder {
            return Err(Error::InvalidCredentialRole {
                role: credential.role,
                credential_id,
            });
        }

        if let Some(result) = check_invalid_or_terminal_state(&credential) {
            return Ok(result);
        }

        let credential_schema = credential.schema.as_ref().await?;
        let format = credential_schema
            .format()
            .await
            .error_while("getting format")?;
        let format_type = self
            .config
            .format
            .get_fields(&format)
            .error_while("getting credential format type")?
            .r#type;

        if format_type == FormatType::Mdoc {
            // Mdoc flow ends here. Nothing else to do for MDOC, since it does not have revocation mechanism
            return self.update_mdoc(&credential, force_refresh).await;
        }

        match credential.r#type {
            CredentialType::Single => {
                let (result, _) = self
                    .check_status_for_single_credential(
                        &credential,
                        &credential_schema,
                        force_refresh,
                    )
                    .await?;
                Ok(result)
            }
            CredentialType::BatchParent => {
                let batch_items = self
                    .credential_repository
                    .get_credential_list(ListQuery {
                        filtering: Some(
                            CredentialFilterValue::ParentCredential(credential.id).condition()
                                & CredentialFilterValue::Deleted(false),
                        ),
                        ..Default::default()
                    })
                    .await
                    .error_while("getting batch items")?
                    .values;

                if batch_items.is_empty() {
                    return Ok(CredentialValidityCheckResult {
                        credential_id: credential.id,
                        status: credential.state,
                        success: false,
                        reason: Some("No batch items found".to_owned()),
                    });
                }

                let mut item_states = vec![];
                for batch_item in batch_items {
                    let batch_item = self
                        .credential_repository
                        .get_credential(&batch_item.id)
                        .await
                        .error_while("getting batch item")?;

                    let (result, suspend_end_date) = self
                        .check_status_for_single_credential(
                            &batch_item,
                            &credential_schema,
                            force_refresh,
                        )
                        .await?;

                    if !result.success {
                        return Ok(CredentialValidityCheckResult {
                            credential_id: credential.id,
                            status: credential.state,
                            ..result
                        });
                    }

                    if result.status != CredentialStateEnum::Expired {
                        item_states.push(
                            revocation_state_from_credential_state(result.status, suspend_end_date)
                                .error_while("parsing status")?,
                        );
                    }
                }

                let interaction = match credential.interaction.as_ref() {
                    Some(interaction) => Some(interaction.as_ref().await?.to_owned()),
                    None => None,
                };
                let status = self
                    .finalize_batch_parent_state(&credential, interaction.as_ref(), &item_states)
                    .await?;

                Ok(CredentialValidityCheckResult {
                    credential_id: credential.id,
                    status,
                    success: true,
                    reason: None,
                })
            }
            CredentialType::BatchItem => {
                let (result, _) = self
                    .check_status_for_single_credential(
                        &credential,
                        &credential_schema,
                        force_refresh,
                    )
                    .await?;

                if result.success {
                    let parent = credential
                        .parent
                        .as_ref()
                        .ok_or(Error::MappingError("Missing batch item parent".to_string()))?
                        .as_ref()
                        .await?;

                    if parent.r#type == CredentialType::BatchParent {
                        let batch_items = self
                            .credential_repository
                            .get_credential_list(ListQuery {
                                filtering: Some(
                                    CredentialFilterValue::ParentCredential(parent.id).condition()
                                        & CredentialFilterValue::Deleted(false),
                                ),
                                ..Default::default()
                            })
                            .await
                            .error_while("getting batch items")?
                            .values;

                        let item_states = batch_items
                            .iter()
                            .filter(|c| c.state != CredentialStateEnum::Expired)
                            .map(|c| {
                                revocation_state_from_credential_state(c.state, c.suspend_end_date)
                            })
                            .collect::<Result<Vec<_>, _>>()
                            .error_while("getting batch items states")?;

                        let interaction = match credential.interaction.as_ref() {
                            Some(interaction) => Some(interaction.as_ref().await?.to_owned()),
                            None => None,
                        };
                        self.finalize_batch_parent_state(
                            &parent,
                            interaction.as_ref(),
                            &item_states,
                        )
                        .await?;
                    }
                }

                Ok(result)
            }
        }
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

async fn issuer_details(issuer_identifier: &Identifier) -> Result<IdentifierDetails, Error> {
    Ok(match &issuer_identifier.data {
        IdentifierData::Did(issuer_did) => {
            let issuer_did = issuer_did.as_ref().await?;

            IdentifierDetails::Did(issuer_did.did.clone())
        }
        IdentifierData::Certificate(certificates) => {
            let certificate = certificates
                .as_ref()
                .await?
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
                x5_references: Default::default(),
            })
        }
        _ => {
            return Err(Error::IncompatibleIssuerIdentifier);
        }
    })
}

fn validate_revocation_state_transition(
    current_state: CredentialStateEnum,
    current_type: CredentialType,
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
            target_state: (*target_state).into(),
            current_type,
        });
    }
    Ok(())
}

fn validate_expiration_state_transition(
    current_state: CredentialStateEnum,
    current_type: CredentialType,
    target_state: &ExpirationState,
) -> Result<(), Error> {
    let valid_states: &[CredentialStateEnum] = match target_state {
        ExpirationState::Accepted => &[CredentialStateEnum::Expiring],
        ExpirationState::Expiring => &[
            CredentialStateEnum::Accepted,
            CredentialStateEnum::Suspended,
        ],
    };
    if !valid_states.contains(&current_state) {
        return Err(Error::InvalidCredentialStateTransition {
            current_state,
            target_state: (*target_state).into(),
            current_type,
        });
    }
    Ok(())
}

/// Give result if it can be determined based on the current state itself
fn check_invalid_or_terminal_state(
    credential: &Credential,
) -> Option<CredentialValidityCheckResult> {
    match credential.state {
        CredentialStateEnum::Accepted | CredentialStateEnum::Suspended => {
            // continue flow
            None
        }
        CredentialStateEnum::Revoked => {
            // credential already revoked, no need to check further
            Some(CredentialValidityCheckResult {
                credential_id: credential.id,
                status: CredentialStateEnum::Revoked,
                success: true,
                reason: None,
            })
        }
        CredentialStateEnum::Expired => {
            // credential already expired, no need to check further (refresh is not possible)
            Some(CredentialValidityCheckResult {
                credential_id: credential.id,
                status: CredentialStateEnum::Expired,
                success: true,
                reason: None,
            })
        }
        status => {
            // cannot check pending/offered credentials etc
            Some(CredentialValidityCheckResult {
                credential_id: credential.id,
                status,
                success: false,
                reason: Some(format!("Invalid credential state: {status}")),
            })
        }
    }
}

fn get_best_state(states: &[RevocationState]) -> RevocationState {
    let mut best_state = RevocationState::Revoked;

    for state in states {
        match state {
            RevocationState::Valid => {
                return RevocationState::Valid;
            }
            RevocationState::Suspended {
                suspend_end_date: parsed_suspend_end_date,
            } => {
                best_state = if let RevocationState::Suspended {
                    suspend_end_date: Some(current_best_suspend_end_date),
                } = best_state
                {
                    if let Some(parsed_suspend_end_date) = parsed_suspend_end_date {
                        RevocationState::Suspended {
                            suspend_end_date: Some(
                                current_best_suspend_end_date.min(*parsed_suspend_end_date),
                            ),
                        }
                    } else {
                        best_state
                    }
                } else {
                    *state
                };
            }
            RevocationState::Revoked => {
                // try next
            }
        };
    }

    best_state
}
