use std::collections::HashSet;

use futures::FutureExt;
use one_dto_mapper::convert_inner;
use shared_types::{CredentialFormat, CredentialId};
use uuid::Uuid;

use super::CredentialService;
use super::dto::{
    ChangeCredentialStateDTO, CreateCredentialRequestDTO, CredentialAttestationBlobs,
    CredentialDetailResponseDTO, CredentialFilterParamsDTO, CredentialRevocationCheckResponseDTO,
    DetailCredentialClaimResponseDTO, GetCredentialListResponseDTO, ShareCredentialResponseDTO,
    SuspendCredentialRequestDTO, WalletInstanceAttestationDTO,
};
use super::error::CredentialServiceError;
use super::mapper::{
    claims_from_create_request, credential_detail_response_from_model, from_create_request,
    get_credential_trust_information, get_remaining_batch_item_count, to_credential_list_response,
};
use super::validator::{
    throw_if_credential_state_eq, validate_create_request,
    validate_format_and_did_method_compatibility, validate_redirect_uri, validate_webhook_url,
};
use crate::config::core_config::BlobStorageType;
use crate::config::validator::protocol::validate_protocol_did_compatibility;
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::model::certificate::CertificateRole;
use crate::model::credential::{
    Credential, CredentialFilterValue, CredentialListIncludeEntityTypeEnum, CredentialRole,
    CredentialStateEnum, CredentialType, SortableCredentialColumn, UpdateCredentialRequest,
};
use crate::model::did::KeyRole;
use crate::model::identifier::{IdentifierState, IdentifierType};
use crate::model::interaction::InteractionType;
use crate::model::list_filter::ListFilterValue;
use crate::model::list_query::ListQuery;
use crate::model::relation::OptionalRelatedExt;
use crate::proto::credential_validity_manager::dto::ChangeCredentialState;
use crate::provider::credential_formatter::model::FormatterCapabilities;
use crate::provider::issuance_protocol::model::ShareResponse;
use crate::provider::issuance_protocol::openid4vci_final1_0::model::OpenID4VCIIssuerInteractionDataDTO;
use crate::provider::issuance_protocol::serialize_interaction_data;
use crate::service::common_dto::{ListQueryDTO, TrustInformationDetailResponseDTO};
use crate::service::common_mapper::recorded_ecosystem_outcomes;
use crate::service::credential_schema::validator::validate_key_storage_security_supported;
use crate::service::error::BusinessLogicError;
use crate::util::interactions::{add_new_interaction, clear_previous_interaction};
use crate::util::key_selection::{CertificateFilter, KeyFilter, KeySelection, SelectedKey};
use crate::validator::ecosystem::{SelectionRole, validate_ecosystem_selection_final};
use crate::validator::{
    throw_if_credential_schema_not_in_session_org, throw_if_org_id_not_matching_session,
};

impl CredentialService {
    /// Creates a credential according to request
    ///
    /// # Arguments
    ///
    /// * `request` - create credential request
    pub async fn create_credential(
        &self,
        mut request: CreateCredentialRequestDTO,
    ) -> Result<CredentialId, CredentialServiceError> {
        let issuer_identifier = match request.issuer {
            Some(issuer_identifier_id) => self
                .identifier_repository
                .get(issuer_identifier_id)
                .await
                .error_while("getting identifier")?,
            None => {
                let issuer_did_id = request.issuer_did.ok_or(CredentialServiceError::NoIssuer)?;

                self.identifier_repository
                    .get_from_did_id(issuer_did_id)
                    .await
                    .error_while("getting identifier")?
                    .ok_or(CredentialServiceError::MissingDid(issuer_did_id))?
            }
        };

        let schema = self
            .credential_schema_repository
            .get_credential_schema(&request.credential_schema_id)
            .await
            .error_while("getting credential schema")?;
        throw_if_org_id_not_matching_session(schema.organisation.id_ref(), &*self.session_provider)
            .error_while("checking session")?;

        validate_key_storage_security_supported(
            schema.wallet_attestation.key_storage_security_level,
            &self.config,
        )
        .error_while("validating key storage security")?;

        let mut formats = schema.formats.as_ref().await?.to_vec();
        if let Some(selected_formats) = &request.formats {
            let selected_formats =
                HashSet::<&CredentialFormat>::from_iter(selected_formats.as_slice());
            formats.retain(|f| selected_formats.contains(&f.format));
            if formats.len() != selected_formats.len() {
                return Err(CredentialServiceError::InvalidFormatSelection);
            }
        }

        let mut common_formatter_capabilities: Option<FormatterCapabilities> = None;
        for format in &formats {
            let capabilities = self
                .formatter_provider
                .get_credential_formatter(&format.format)?
                .get_capabilities();

            if let Some(previous_capabilities) = common_formatter_capabilities.as_mut() {
                previous_capabilities.combine_constraints(&capabilities);
            } else {
                common_formatter_capabilities = Some(capabilities);
            };
        }
        let formatter_capabilities =
            common_formatter_capabilities.ok_or(CredentialServiceError::InvalidFormatSelection)?;

        let exchange_capabilities = self
            .protocol_provider
            .get_protocol(&request.protocol)?
            .get_capabilities();

        let selection = issuer_identifier
            .select_key(KeySelection {
                did: request.issuer_did,
                key: KeyFilter::did_role(KeyRole::AssertionMethod)
                    .and_id(request.issuer_key)
                    .and_algorithms(formatter_capabilities.signing_key_algorithms.clone())
                    .error_while("selecting issuer identifier")?,
                certificate: CertificateFilter::role_filter(CertificateRole::AssertionMethod)
                    .and_id(request.issuer_certificate),
            })
            .await
            .error_while("selecting key")?;

        let (issuer_key, issuer_certificate) = match selection {
            SelectedKey::Key(_) => {
                return Err(CredentialServiceError::InvalidIdentifierType(
                    IdentifierType::Key,
                ));
            }
            SelectedKey::Certificate { certificate, key } => (*key, Some(*certificate)),
            SelectedKey::Did { did, key } => {
                validate_protocol_did_compatibility(
                    &exchange_capabilities.did_methods,
                    &did.did_method,
                    &self.config.did,
                )
                .error_while("checking did compatibility")?;
                validate_format_and_did_method_compatibility(
                    &did.did_method,
                    &formatter_capabilities,
                    &self.config,
                )?;
                (key.key.to_owned(), None)
            }
        };

        validate_create_request(
            &request.protocol,
            &mut request.claim_values,
            &schema,
            &formatter_capabilities,
            &self.config,
        )
        .await?;
        validate_redirect_uri(
            &request.protocol,
            request.redirect_uri.as_deref(),
            &self.config,
        )?;
        validate_webhook_url(
            request.webhook_destination_url.as_ref(),
            &request.protocol,
            &self.config,
            self.notification_scheduler.as_ref(),
        )?;

        let organisation = schema.organisation.as_ref().await?;
        validate_ecosystem_selection_final(
            request.ecosystem.as_ref(),
            &organisation,
            self.ecosystem_provider.as_ref(),
            SelectionRole::Issuer,
        )
        .error_while("validating ecosystem")?;
        drop(organisation);

        let credential_id = Uuid::new_v4().into();
        let claims = claims_from_create_request(
            request.claim_values.clone(),
            &schema.claim_schemas.as_ref().await?,
        )?;

        let success_log = format!(
            "Created credential {} using schema `{}` ({}) and issuer `{}` ({}): protocol `{}`",
            credential_id,
            schema.name,
            schema.id,
            issuer_identifier.name,
            issuer_identifier.id,
            request.protocol
        );

        let ecosystem = request.ecosystem.clone();
        let interaction = if request.formats.is_some() {
            let interaction_data = Some(
                serialize_interaction_data(&OpenID4VCIIssuerInteractionDataDTO {
                    pre_authorized_code_used: false,
                    access_token_hash: vec![],
                    access_token_expires_at: None,
                    refresh_token_hash: None,
                    refresh_token_expires_at: None,
                    notification_ids: Default::default(),
                    transaction_code: None,
                    formats: Some(formats.iter().map(|f| f.id).collect()),
                })
                .error_while("serializing interaction data")?,
            );

            Some(
                add_new_interaction(
                    Uuid::new_v4().into(),
                    &*self.interaction_repository,
                    interaction_data,
                    schema.organisation.to_owned(),
                    InteractionType::Issuance,
                    None,
                    ecosystem.clone(),
                )
                .await
                .error_while("adding interaction")?,
            )
        } else {
            None
        };

        let mut credential = from_create_request(
            request,
            credential_id,
            claims,
            issuer_identifier,
            issuer_certificate,
            schema,
            issuer_key,
            formats,
            &self.config,
        )?;
        credential.interaction = convert_inner(interaction);

        if let Some(ecosystem) = &ecosystem {
            let ecosystem = self.ecosystem_provider.get(ecosystem)?;
            ecosystem
                .validate_credential(&credential)
                .await
                .error_while("validating ecosystem")?;
        }

        let result = self
            .credential_repository
            .create_credential(credential)
            .await
            .error_while("creating credential")?;

        tracing::info!(message = success_log);
        Ok(result)
    }

    /// Deletes a credential
    ///
    /// # Arguments
    ///
    /// * `CredentialId` - Id of an existing credential
    pub async fn delete_credential(
        &self,
        credential_id: &CredentialId,
    ) -> Result<(), CredentialServiceError> {
        let credential = self
            .credential_repository
            .get_credential(credential_id)
            .await
            .error_while("getting credential")?;

        let schema = credential.schema.as_ref().await?;
        throw_if_org_id_not_matching_session(schema.organisation.id_ref(), &*self.session_provider)
            .error_while("checking session")?;

        if credential.r#type == CredentialType::BatchItem {
            return Err(CredentialServiceError::InvalidType(credential.r#type));
        }

        let is_issuer = credential.role == CredentialRole::Issuer;
        if is_issuer && schema.allow_revocation {
            throw_if_credential_state_eq(&credential, CredentialStateEnum::Accepted)?;
        }
        drop(schema);

        self.tx_manager
            .tx(async {
                let batch_items = self
                    .credential_repository
                    .get_credential_list(ListQuery {
                        include_count: false,
                        filtering: Some(
                            CredentialFilterValue::ParentCredential(*credential_id).condition(),
                        ),
                        ..Default::default()
                    })
                    .await
                    .error_while("getting batch items")?
                    .values;
                tracing::debug!("Batch items found: {}", batch_items.len());

                let items_to_delete = {
                    let mut items = batch_items;
                    items.push(credential);
                    items
                };

                self.credential_repository
                    .delete_credentials(&items_to_delete)
                    .await
                    .error_while("deleting credentials")?;

                Ok::<_, CredentialServiceError>(())
            }
            .boxed())
            .await
            .error_while("deleting credential")??;

        tracing::info!("Deleted credential {credential_id}");
        Ok(())
    }

    /// Returns details of a credential
    ///
    /// # Arguments
    ///
    /// * `CredentialId` - Id of an existing credential
    pub async fn get_credential(
        &self,
        credential_id: &CredentialId,
    ) -> Result<CredentialDetailResponseDTO<DetailCredentialClaimResponseDTO>, CredentialServiceError>
    {
        let credential = self
            .credential_repository
            .get_credential(credential_id)
            .await
            .error_while("getting credential")?;

        throw_if_credential_schema_not_in_session_org(&credential, &*self.session_provider)
            .await
            .error_while("checking session")?;

        if credential.deleted_at.is_some() {
            return Err(CredentialServiceError::NotFound(*credential_id));
        }

        let attestation_blobs = self.get_wallet_attestation_blobs(&credential).await?;

        let remaining_batch_item_count =
            get_remaining_batch_item_count(&credential, self.credential_repository.as_ref())
                .await?;

        let wallet_name = attestation_blobs
            .wallet_instance_attestation_blob
            .clone()
            .map(WalletInstanceAttestationDTO::try_from)
            .transpose()?
            .map(|attestation| attestation.name);
        let trust_information = get_credential_trust_information(
            &credential,
            wallet_name,
            self.ecosystem_provider.as_ref(),
            &*self.history_repository,
        )
        .await?;

        let claims = crate::mapper::credential::detail_claims(
            &credential,
            self.credential_repository.as_ref(),
        )
        .await?;
        let response = credential_detail_response_from_model(
            credential,
            claims,
            &self.config,
            attestation_blobs,
            trust_information,
            remaining_batch_item_count,
            self.credential_repository.as_ref(),
            self.formatter_provider.as_ref(),
            Some(self.blob_storage_provider.as_ref()),
        )
        .await?;

        Ok(response)
    }

    async fn get_wallet_attestation_blobs(
        &self,
        credential: &Credential,
    ) -> Result<CredentialAttestationBlobs, CredentialServiceError> {
        if credential.wallet_instance_attestation_blob_id.is_none()
            && credential.wallet_key_attestation_blob_id.is_none()
        {
            return Ok(CredentialAttestationBlobs::default());
        }

        let db_blob_storage = self
            .blob_storage_provider
            .get_blob_storage(BlobStorageType::Db)?;

        let wallet_instance_attestation_blob = match &credential.wallet_instance_attestation_blob_id
        {
            Some(blob_id) => Some(
                db_blob_storage
                    .get(blob_id)
                    .await
                    .error_while("getting WIA blob")?
                    .ok_or(CredentialServiceError::MappingError(
                        "wallet instance attestation blob is None".to_string(),
                    ))?,
            ),
            None => None,
        };
        let wallet_key_attestation_blob = match &credential.wallet_key_attestation_blob_id {
            Some(blob_id) => Some(
                db_blob_storage
                    .get(blob_id)
                    .await
                    .error_while("getting WUA blob")?
                    .ok_or(CredentialServiceError::MappingError(
                        "wallet unit attestation blob is None".to_string(),
                    ))?,
            ),
            None => None,
        };

        Ok(CredentialAttestationBlobs {
            wallet_instance_attestation_blob,
            wallet_key_attestation_blob,
        })
    }

    /// Returns list of credentials according to query
    ///
    /// # Arguments
    ///
    /// * `filter_params` - query parameters
    pub async fn get_credential_list(
        &self,
        filter_params: ListQueryDTO<
            SortableCredentialColumn,
            CredentialFilterParamsDTO,
            CredentialListIncludeEntityTypeEnum,
        >,
    ) -> Result<GetCredentialListResponseDTO, CredentialServiceError> {
        if filter_params.filter.name.is_some()
            && filter_params.filter.search_type.is_some()
            && filter_params.filter.search_text.is_some()
        {
            return Err(BusinessLogicError::GeneralInputValidationError
                .error_while("validating credential filter")
                .into());
        }

        throw_if_org_id_not_matching_session(
            &filter_params.filter.organisation_id,
            &*self.session_provider,
        )
        .error_while("checking session")?;

        let include_translations = filter_params
            .include
            .as_ref()
            .is_some_and(|i| i.contains(&CredentialListIncludeEntityTypeEnum::Translations));
        let result = self
            .credential_repository
            .get_credential_list(filter_params.into())
            .await
            .and_then(|list| list.require_count())
            .error_while("getting credentials")?;

        let mut response_dtos = Vec::with_capacity(result.values.len());
        for value in result.values {
            response_dtos.push(
                to_credential_list_response(
                    value,
                    include_translations,
                    &self.config,
                    self.formatter_provider.as_ref(),
                )
                .await?,
            );
        }
        Ok(GetCredentialListResponseDTO {
            values: response_dtos,
            total_pages: result.total_pages,
            total_items: result.total_items,
        })
    }

    pub async fn reactivate_credential(
        &self,
        credential_id: &CredentialId,
    ) -> Result<(), CredentialServiceError> {
        self.credential_validity_manager
            .change_credential_state(credential_id, ChangeCredentialState::Accepted)
            .await
            .error_while("reactivating credential")?;
        tracing::info!("Reactivated credential {credential_id}");
        Ok(())
    }

    pub async fn patch_credential_state(
        &self,
        credential_id: &CredentialId,
        change_credential_state: ChangeCredentialStateDTO,
    ) -> Result<(), CredentialServiceError> {
        self.credential_validity_manager
            .change_credential_state(credential_id, change_credential_state.into())
            .await
            .error_while("patching credential state")?;
        tracing::info!("Patched credential state {credential_id} to {change_credential_state:?}");
        Ok(())
    }

    pub async fn suspend_credential(
        &self,
        credential_id: &CredentialId,
        request: SuspendCredentialRequestDTO,
    ) -> Result<(), CredentialServiceError> {
        self.credential_validity_manager
            .change_credential_state(
                credential_id,
                ChangeCredentialState::Suspended {
                    suspend_end_date: request.suspend_end_date,
                },
            )
            .await
            .error_while("suspending credential")?;
        tracing::info!("Suspended credential {credential_id}");
        Ok(())
    }

    /// Revokes credential
    ///
    /// # Arguments
    ///
    /// * `CredentialId` - Id of an existing credential
    pub async fn revoke_credential(
        &self,
        credential_id: &CredentialId,
    ) -> Result<(), CredentialServiceError> {
        self.credential_validity_manager
            .change_credential_state(credential_id, ChangeCredentialState::Revoked)
            .await
            .error_while("revoking credential")?;
        tracing::info!("Revoked credential {credential_id}");
        Ok(())
    }

    /// Checks credentials' revocation status
    ///
    /// # Arguments
    ///
    /// * `credential_ids` - credentials to check
    pub async fn check_revocation(
        &self,
        credential_ids: Vec<CredentialId>,
        force_refresh: bool,
    ) -> Result<Vec<CredentialRevocationCheckResponseDTO>, CredentialServiceError> {
        let mut result = vec![];
        for credential_id in credential_ids {
            result.push(
                self.credential_validity_manager
                    .check_holder_credential_validity(credential_id, force_refresh)
                    .await
                    .error_while("checking credential validity")?,
            );
        }
        Ok(convert_inner(result))
    }

    /// Returns URL of shared credential
    ///
    /// # Arguments
    ///
    /// * `CredentialId` - Id of an existing credential
    pub async fn share_credential(
        &self,
        credential_id: &CredentialId,
    ) -> Result<ShareCredentialResponseDTO, CredentialServiceError> {
        let credential = self.get_credential_with_state(credential_id).await?;

        if credential.deleted_at.is_some() {
            return Err(CredentialServiceError::NotFound(*credential_id));
        }
        let credential_schema = credential
            .schema
            .as_ref()
            .await
            .error_while("loading credential schema")?;
        throw_if_org_id_not_matching_session(
            credential_schema.organisation.id_ref(),
            &*self.session_provider,
        )
        .error_while("checking session")?;

        if credential.r#type == CredentialType::BatchItem {
            return Err(CredentialServiceError::InvalidType(credential.r#type));
        }

        if !matches!(
            credential.state,
            CredentialStateEnum::Created
                | CredentialStateEnum::Pending
                | CredentialStateEnum::InteractionExpired
        ) {
            return Err(CredentialServiceError::InvalidState(credential.state));
        }

        let Some(issuer_identifier) = credential.issuer_identifier.as_ref() else {
            return Err(CredentialServiceError::MappingError(
                "Missing issuer identifier".to_string(),
            ));
        };
        if issuer_identifier.as_ref().await?.state != IdentifierState::Active {
            return Err(CredentialServiceError::IdentifierIsDeactivated(
                issuer_identifier.id(),
            ));
        }

        let credential_exchange = &credential.protocol;
        let exchange = self.protocol_provider.get_protocol(credential_exchange)?;

        let ShareResponse {
            url,
            interaction_id,
            interaction_data,
            expires_at,
            transaction_code,
        } = exchange
            .issuer_share_credential(&credential)
            .await
            .error_while("sharing credential")?;

        add_new_interaction(
            interaction_id,
            &*self.interaction_repository,
            interaction_data,
            credential_schema.organisation.to_owned(),
            InteractionType::Issuance,
            expires_at,
            credential.ecosystem,
        )
        .await
        .error_while("adding interaction")?;
        self.credential_repository
            .update_credential(
                *credential_id,
                UpdateCredentialRequest {
                    state: (credential.state != CredentialStateEnum::Pending)
                        .then_some(CredentialStateEnum::Pending),
                    interaction: Some(interaction_id),
                    ..Default::default()
                },
            )
            .await
            .error_while("updating credential")?;
        clear_previous_interaction(
            &*self.interaction_repository,
            credential.interaction.id_opt_ref(),
        )
        .await
        .error_while("clearing interaction")?;
        tracing::info!("Shared credential {credential_id}");
        Ok(ShareCredentialResponseDTO {
            url,
            expires_at,
            transaction_code,
        })
    }

    pub async fn get_trust_details(
        &self,
        id: CredentialId,
    ) -> Result<TrustInformationDetailResponseDTO, CredentialServiceError> {
        let credential = self
            .credential_repository
            .get_credential(&id)
            .await
            .error_while("getting credential")?;
        throw_if_credential_schema_not_in_session_org(&credential, &*self.session_provider)
            .await
            .error_while("checking session")?;
        if credential.r#type == CredentialType::BatchItem {
            return Err(CredentialServiceError::InvalidType(credential.r#type));
        }
        if credential.role != CredentialRole::Holder {
            return Err(CredentialServiceError::InvalidRole(credential.role));
        }

        let history_id = credential.ecosystem_history_id();
        let mut result = TrustInformationDetailResponseDTO {
            ecosystem_errors: recorded_ecosystem_outcomes(
                history_id.into(),
                &*self.history_repository,
            )
            .await?,
            ..Default::default()
        };

        if let Some(ecosystem_id) = credential.ecosystem {
            let ecosystem = self.ecosystem_provider.get(&ecosystem_id)?;
            let issuer = ecosystem
                .issuer_trust_details(&history_id)
                .await
                .error_while("getting ecosystem trust detail")?;

            result.ecosystem = Some(ecosystem_id);
            result.issuer = Some(issuer.info.into());
        }

        Ok(result)
    }

    /// Get credential with the latest credential state
    async fn get_credential_with_state(
        &self,
        id: &CredentialId,
    ) -> Result<Credential, CredentialServiceError> {
        let credential = self
            .credential_repository
            .get_credential(id)
            .await
            .error_while("getting credential")?;

        Ok(credential)
    }
}
