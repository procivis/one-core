use anyhow::Context;
use one_providers::credential_formatter::model::DetailCredential;
use one_providers::exchange_protocol::openid4vc::model::{
    OpenID4VCICredential, OpenID4VCIProof, OpenID4VCITokenResponseDTO, ShareResponse,
};
use one_providers::exchange_protocol::openid4vc::proof_formatter::OpenID4VCIProofJWTFormatter;
use one_providers::exchange_protocol::openid4vc::ExchangeProtocolError;
use one_providers::http_client::HttpClient;
use one_providers::key_storage::provider::KeyProvider;
use one_providers::revocation::model::{
    CredentialDataByRole, CredentialRevocationState, RevocationMethodCapabilities,
};
use shared_types::CredentialId;
use time::OffsetDateTime;
use uuid::Uuid;

use super::mapper::credential_detail_response_from_model;
use crate::common_mapper::list_response_try_into;
use crate::common_validator::{
    get_latest_state, throw_if_latest_credential_state_eq, throw_if_state_not_in,
};
use crate::config::core_config::RevocationType;
use crate::model::claim::ClaimRelations;
use crate::model::claim_schema::ClaimSchemaRelations;
use crate::model::common::EntityShareResponseDTO;
use crate::model::credential::{
    self, Credential, CredentialRelations, CredentialRole, CredentialState, CredentialStateEnum,
    CredentialStateRelations, UpdateCredentialRequest,
};
use crate::model::credential_schema::CredentialSchemaRelations;
use crate::model::did::{DidRelations, DidType, KeyRole, RelatedKey};
use crate::model::history::HistoryAction;
use crate::model::interaction::InteractionRelations;
use crate::model::key::KeyRelations;
use crate::model::organisation::OrganisationRelations;
use crate::model::validity_credential::ValidityCredentialType;
use crate::provider::exchange_protocol::deserialize_interaction_data;
use crate::provider::exchange_protocol::openid4vc::model::HolderInteractionData;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::error::DataLayerError;
use crate::repository::interaction_repository::InteractionRepository;
use crate::service::credential::dto::{
    CreateCredentialRequestDTO, CredentialDetailResponseDTO, CredentialRevocationCheckResponseDTO,
    GetCredentialListResponseDTO, GetCredentialQueryDTO, SuspendCredentialRequestDTO,
};
use crate::service::credential::mapper::{
    claims_from_create_request, credential_revocation_state_to_model_state, from_create_request,
};
use crate::service::credential::CredentialService;
use crate::service::error::{
    BusinessLogicError, EntityNotFoundError, MissingProviderError, ServiceError, ValidationError,
};
use crate::service::oidc::dto::OpenID4VCICredentialResponseDTO;
use crate::util::history::{log_history_event_credential, log_history_event_credential_revocation};
use crate::util::interactions::{
    add_new_interaction, clear_previous_interaction, update_credentials_interaction,
};
use crate::util::oidc::{detect_format_with_crypto_suite, map_core_to_oidc_format};
use crate::util::revocation_update::{generate_credential_additional_data, process_update};

impl CredentialService {
    /// Creates a credential according to request
    ///
    /// # Arguments
    ///
    /// * `request` - create credential request

    pub async fn create_credential(
        &self,
        request: CreateCredentialRequestDTO,
    ) -> Result<CredentialId, ServiceError> {
        let Some(issuer_did) = self
            .did_repository
            .get_did(
                &request.issuer_did,
                &DidRelations {
                    keys: Some(Default::default()),
                    ..Default::default()
                },
            )
            .await?
        else {
            return Err(EntityNotFoundError::Did(request.issuer_did).into());
        };

        if issuer_did.is_remote() {
            return Err(BusinessLogicError::IncompatibleDidType {
                reason: "Issuer did is remote".to_string(),
            }
            .into());
        }

        if issuer_did.deactivated {
            return Err(BusinessLogicError::DidIsDeactivated(issuer_did.id).into());
        }

        let Some(schema) = self
            .credential_schema_repository
            .get_credential_schema(
                &request.credential_schema_id,
                &CredentialSchemaRelations {
                    claim_schemas: Some(Default::default()),
                    organisation: Some(Default::default()),
                },
            )
            .await?
        else {
            return Err(EntityNotFoundError::CredentialSchema(request.credential_schema_id).into());
        };

        let claim_schemas = schema
            .claim_schemas
            .to_owned()
            .ok_or(ServiceError::MappingError(
                "claim_schemas is None".to_string(),
            ))?;

        let formatter_capabilities = self
            .formatter_provider
            .get_formatter(&schema.format)
            .ok_or(MissingProviderError::Formatter(schema.format.to_owned()))?
            .get_capabilities();

        super::validator::validate_create_request(
            &issuer_did.did_method,
            &request.exchange,
            &request.claim_values,
            &schema,
            &formatter_capabilities.clone().into(),
            &self.config,
        )?;

        let credential_id = Uuid::new_v4().into();
        let claims = claims_from_create_request(
            credential_id,
            request.claim_values.clone(),
            &claim_schemas,
        )?;

        let valid_keys_filter = |entry: &&RelatedKey| {
            entry.role == KeyRole::AssertionMethod
                && formatter_capabilities
                    .signing_key_algorithms
                    .contains(&entry.key.key_type)
        };

        let did_keys = issuer_did
            .keys
            .as_ref()
            .ok_or_else(|| ServiceError::MappingError("keys is None".to_string()))?;

        let key = match request.issuer_key {
            Some(key_id) => did_keys
                .iter()
                .filter(valid_keys_filter)
                .find(|entry| entry.key.id == key_id)
                .ok_or(ServiceError::Validation(ValidationError::InvalidKey(
                    "key not found or invalid".into(),
                )))?,
            // no explicit key specified, pick first valid key
            None => did_keys.iter().find(valid_keys_filter).ok_or_else(|| {
                ServiceError::Validation(ValidationError::InvalidKey(
                    "no valid keys found in did".to_string(),
                ))
            })?,
        }
        .key
        .clone();

        let credential =
            from_create_request(request, credential_id, claims, issuer_did, schema, key);

        let result = self
            .credential_repository
            .create_credential(credential.to_owned())
            .await?;

        let _ = log_history_event_credential(
            &*self.history_repository,
            &credential,
            HistoryAction::Created,
        )
        .await;

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
    ) -> Result<(), ServiceError> {
        let credential = self
            .credential_repository
            .get_credential(
                credential_id,
                &CredentialRelations {
                    state: Some(CredentialStateRelations::default()),
                    schema: Some(CredentialSchemaRelations::default()),
                    issuer_did: Some(DidRelations::default()),
                    ..Default::default()
                },
            )
            .await?;

        let Some(credential) = credential else {
            return Err(EntityNotFoundError::Credential(*credential_id).into());
        };

        let schema = credential
            .schema
            .as_ref()
            .ok_or(ServiceError::MappingError(
                "credential_schema is None".to_string(),
            ))?;

        let revocation_type = &self
            .config
            .revocation
            .get_fields(&schema.revocation_method)
            .map_err(|err| {
                ServiceError::MappingError(format!(
                    "Unknown revocation method: {}: {err}",
                    schema.revocation_method
                ))
            })?
            .r#type();

        let is_issuer = credential
            .issuer_did
            .as_ref()
            .is_some_and(|did| did.did_type == DidType::Local);
        if is_issuer && **revocation_type != RevocationType::None {
            throw_if_latest_credential_state_eq(&credential, CredentialStateEnum::Accepted)?;
        }

        self.credential_repository
            .delete_credential(credential_id)
            .await
            .map_err(|error| match error {
                // credential not found or already deleted
                DataLayerError::RecordNotUpdated => {
                    EntityNotFoundError::Credential(*credential_id).into()
                }
                error => ServiceError::from(error),
            })
    }

    /// Returns details of a credential
    ///
    /// # Arguments
    ///
    /// * `CredentialId` - Id of an existing credential
    pub async fn get_credential(
        &self,
        credential_id: &CredentialId,
    ) -> Result<CredentialDetailResponseDTO, ServiceError> {
        let credential = self
            .credential_repository
            .get_credential(
                credential_id,
                &CredentialRelations {
                    state: Some(CredentialStateRelations::default()),
                    claims: Some(ClaimRelations {
                        schema: Some(ClaimSchemaRelations::default()),
                    }),
                    schema: Some(CredentialSchemaRelations {
                        claim_schemas: Some(ClaimSchemaRelations::default()),
                        organisation: Some(OrganisationRelations::default()),
                    }),
                    issuer_did: Some(DidRelations::default()),
                    holder_did: Some(DidRelations::default()),
                    ..Default::default()
                },
            )
            .await?;

        let credential = credential.ok_or(EntityNotFoundError::Credential(*credential_id))?;

        if credential.deleted_at.is_some() {
            return Err(EntityNotFoundError::Credential(*credential_id).into());
        }

        let mut response = credential_detail_response_from_model(credential, &self.config)
            .map_err(|err| ServiceError::ResponseMapping(err.to_string()))?;

        if response.schema.revocation_method == "LVVC" {
            let latest_lvvc = self
                .validity_credential_repository
                .get_latest_by_credential_id(credential_id.to_owned(), ValidityCredentialType::Lvvc)
                .await?;

            if let Some(latest_lvvc) = latest_lvvc {
                response.lvvc_issuance_date = Some(latest_lvvc.created_date);
            }
        }

        Ok(response)
    }

    /// Returns list of credentials according to query
    ///
    /// # Arguments
    ///
    /// * `query` - query parameters
    pub async fn get_credential_list(
        &self,
        query: GetCredentialQueryDTO,
    ) -> Result<GetCredentialListResponseDTO, ServiceError> {
        let result = self
            .credential_repository
            .get_credential_list(query)
            .await?;

        list_response_try_into(result)
    }

    pub async fn reactivate_credential(
        &self,
        credential_id: &CredentialId,
    ) -> Result<(), ServiceError> {
        self.change_issued_credential_revocation_state(
            credential_id,
            CredentialRevocationState::Valid,
        )
        .await?;
        Ok(())
    }

    pub async fn suspend_credential(
        &self,
        credential_id: &CredentialId,
        request: SuspendCredentialRequestDTO,
    ) -> Result<(), ServiceError> {
        self.change_issued_credential_revocation_state(
            credential_id,
            CredentialRevocationState::Suspended {
                suspend_end_date: request.suspend_end_date,
            },
        )
        .await?;
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
    ) -> Result<(), ServiceError> {
        self.change_issued_credential_revocation_state(
            credential_id,
            CredentialRevocationState::Revoked,
        )
        .await?;
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
    ) -> Result<Vec<CredentialRevocationCheckResponseDTO>, ServiceError> {
        let mut result = vec![];
        for credential_id in credential_ids {
            result.push(
                self.check_credential_revocation_status(credential_id)
                    .await?,
            );
        }
        Ok(result)
    }

    /// Returns URL of shared credential
    ///
    /// # Arguments
    ///
    /// * `CredentialId` - Id of an existing credential
    pub async fn share_credential(
        &self,
        credential_id: &CredentialId,
    ) -> Result<EntityShareResponseDTO, ServiceError> {
        let (credential, credential_state) = self.get_credential_with_state(credential_id).await?;

        let now = OffsetDateTime::now_utc();

        match credential_state {
            CredentialStateEnum::Created => {
                self.credential_repository
                    .update_credential(UpdateCredentialRequest {
                        id: credential_id.to_owned(),
                        state: Some(CredentialState {
                            created_date: now,
                            state: credential::CredentialStateEnum::Pending,
                            suspend_end_date: None,
                        }),
                        credential: None,
                        holder_did_id: None,
                        issuer_did_id: None,
                        interaction: None,
                        key: None,
                        redirect_uri: None,
                    })
                    .await?;
            }
            CredentialStateEnum::Pending => {}
            state => return Err(BusinessLogicError::InvalidCredentialState { state }.into()),
        }

        let credential_exchange = &credential.exchange;

        let credential_schema = credential
            .schema
            .as_ref()
            .ok_or(ExchangeProtocolError::Failed(
                "credential schema missing".to_string(),
            ))?;

        let format = if credential_exchange == "OPENID4VC" {
            map_core_to_oidc_format(&credential_schema.format)
                .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?
        } else {
            credential_schema.format.to_owned()
        };

        let exchange_instance = &self
            .config
            .exchange
            .get_fields(credential_exchange)
            .map_err(|err| {
                ServiceError::MissingExchangeProtocol(format!("{credential_exchange}: {err}"))
            })?
            .r#type()
            .to_string();

        let exchange = self
            .protocol_provider
            .get_protocol(exchange_instance)
            .ok_or(MissingProviderError::ExchangeProtocol(
                exchange_instance.clone(),
            ))?;

        let ShareResponse {
            url,
            id: interaction_id,
            context,
        } = exchange
            .share_credential(&credential.clone().into(), &format)
            .await?;

        add_new_interaction(
            interaction_id,
            &self.base_url,
            &*self.interaction_repository,
            serde_json::to_vec(&context).ok(),
        )
        .await?;
        update_credentials_interaction(credential.id, interaction_id, &*self.credential_repository)
            .await?;
        clear_previous_interaction(&*self.interaction_repository, &credential.interaction).await?;

        let _ = log_history_event_credential(
            &*self.history_repository,
            &credential,
            HistoryAction::Offered,
        )
        .await;

        Ok(EntityShareResponseDTO { url })
    }

    // ============ Private methods

    /// Get credential with the latest credential state
    async fn get_credential_with_state(
        &self,
        id: &CredentialId,
    ) -> Result<(Credential, CredentialStateEnum), ServiceError> {
        let credential = self
            .credential_repository
            .get_credential(
                id,
                &CredentialRelations {
                    state: Some(CredentialStateRelations::default()),
                    claims: Some(ClaimRelations {
                        schema: Some(ClaimSchemaRelations::default()),
                    }),
                    schema: Some(CredentialSchemaRelations {
                        claim_schemas: Some(ClaimSchemaRelations::default()),
                        organisation: Some(OrganisationRelations::default()),
                    }),
                    issuer_did: Some(DidRelations::default()),
                    holder_did: Some(DidRelations::default()),
                    interaction: Some(InteractionRelations::default()),
                    ..Default::default()
                },
            )
            .await?
            .ok_or(EntityNotFoundError::Credential(*id))?;

        let credential_states = credential
            .state
            .as_ref()
            .ok_or(ServiceError::MappingError("state is None".to_string()))?;
        let latest_state = credential_states
            .first()
            .ok_or(ServiceError::MappingError("state is missing".to_string()))?
            .state
            .clone();
        Ok((credential, latest_state))
    }

    async fn change_issued_credential_revocation_state(
        &self,
        credential_id: &CredentialId,
        revocation_state: CredentialRevocationState,
    ) -> Result<(), ServiceError> {
        let credential = self
            .credential_repository
            .get_credential(
                credential_id,
                &CredentialRelations {
                    state: Some(CredentialStateRelations::default()),
                    issuer_did: Some(DidRelations {
                        keys: Some(KeyRelations::default()),
                        ..Default::default()
                    }),
                    holder_did: Some(DidRelations::default()),
                    schema: Some(CredentialSchemaRelations {
                        organisation: Some(OrganisationRelations::default()),
                        ..Default::default()
                    }),
                    key: Some(KeyRelations::default()),
                    ..Default::default()
                },
            )
            .await?;

        let Some(credential) = credential else {
            return Err(EntityNotFoundError::Credential(*credential_id).into());
        };

        let latest_state = &get_latest_state(&credential)?.state;

        let valid_states: &[CredentialStateEnum] = match revocation_state {
            CredentialRevocationState::Revoked => &[
                CredentialStateEnum::Accepted,
                CredentialStateEnum::Suspended,
            ],
            CredentialRevocationState::Valid => &[CredentialStateEnum::Suspended],
            CredentialRevocationState::Suspended { .. } => &[CredentialStateEnum::Accepted],
        };
        throw_if_state_not_in(latest_state, valid_states)?;

        let revocation_method_key = &credential
            .schema
            .as_ref()
            .ok_or(ServiceError::MappingError(
                "credential schema is None".to_string(),
            ))?
            .revocation_method;

        let revocation_method = self
            .revocation_method_provider
            .get_revocation_method(revocation_method_key)
            .ok_or(MissingProviderError::RevocationMethod(
                revocation_method_key.to_owned(),
            ))?;

        let capabilities: RevocationMethodCapabilities = revocation_method.get_capabilities();
        let required_capability = match revocation_state {
            CredentialRevocationState::Valid | CredentialRevocationState::Suspended { .. } => {
                "SUSPEND"
            }
            CredentialRevocationState::Revoked => "REVOKE",
        }
        .to_string();
        if !capabilities.operations.contains(&required_capability) {
            return Err(
                BusinessLogicError::OperationNotSupportedByRevocationMethod {
                    operation: revocation_state.to_string(),
                }
                .into(),
            );
        }

        let update = revocation_method
            .mark_credential_as(
                &credential.to_owned().into(),
                revocation_state.to_owned(),
                generate_credential_additional_data(
                    &credential,
                    &*self.credential_repository,
                    &*self.revocation_list_repository,
                    &*self.revocation_method_provider,
                    &self.key_provider,
                    &self.base_url,
                )
                .await?,
            )
            .await?;
        process_update(
            update,
            &*self.validity_credential_repository,
            &*self.revocation_list_repository,
        )
        .await?;

        let now: OffsetDateTime = OffsetDateTime::now_utc();
        let suspend_end_date =
            if let CredentialRevocationState::Suspended { suspend_end_date } = &revocation_state {
                suspend_end_date.to_owned()
            } else {
                None
            };
        self.credential_repository
            .update_credential(UpdateCredentialRequest {
                id: credential_id.to_owned(),
                state: Some(CredentialState {
                    created_date: now,
                    state: credential_revocation_state_to_model_state(revocation_state.to_owned()),
                    suspend_end_date,
                }),
                credential: None,
                holder_did_id: None,
                issuer_did_id: None,
                interaction: None,
                key: None,
                redirect_uri: None,
            })
            .await?;

        let _ = log_history_event_credential_revocation(
            &*self.history_repository,
            &credential,
            revocation_state,
        )
        .await;

        Ok(())
    }

    async fn check_credential_revocation_status(
        &self,
        credential_id: CredentialId,
    ) -> Result<CredentialRevocationCheckResponseDTO, ServiceError> {
        let mut credential = self
            .credential_repository
            .get_credential(
                &credential_id,
                &CredentialRelations {
                    state: Some(CredentialStateRelations::default()),
                    schema: Some(CredentialSchemaRelations {
                        organisation: Some(OrganisationRelations::default()),
                        ..Default::default()
                    }),
                    issuer_did: Some(DidRelations {
                        keys: Some(KeyRelations::default()),
                        ..Default::default()
                    }),
                    holder_did: Some(DidRelations {
                        keys: Some(KeyRelations::default()),
                        ..Default::default()
                    }),
                    interaction: Some(InteractionRelations::default()),
                    key: Some(KeyRelations::default()),
                    ..Default::default()
                },
            )
            .await?
            .ok_or(ServiceError::EntityNotFound(
                EntityNotFoundError::Credential(credential_id),
            ))?;

        let credential_schema = credential
            .schema
            .as_ref()
            .ok_or(ServiceError::MappingError("schema is None".to_string()))?
            .clone();

        let credential_str = String::from_utf8(credential.credential.clone())
            .map_err(|e| ServiceError::MappingError(e.to_string()))?;

        // Workaround credential format detection
        let format = detect_format_with_crypto_suite(&credential_schema.format, &credential_str)?;

        let mut current_state = credential
            .state
            .as_ref()
            .ok_or(ServiceError::MappingError("state is None".to_string()))?
            .first()
            .ok_or(ServiceError::MappingError(
                "latest state not found".to_string(),
            ))?
            .to_owned()
            .state;

        let formatter = self.formatter_provider.get_formatter(&format).ok_or(
            MissingProviderError::Formatter(credential_schema.format.clone()),
        )?;

        // we will update that later
        let mut detail_credential = formatter
            .extract_credentials_unverified(&credential_str)
            .await?;

        if format == "MDOC" {
            let interaction_data: HolderInteractionData = deserialize_interaction_data(
                credential
                    .interaction
                    .as_ref()
                    .and_then(|i| i.data.as_ref()),
            )?;

            let result = update_mso_interaction_access_token(
                &mut credential,
                &*self.interaction_repository,
                interaction_data.clone(),
                &*self.client,
            )
            .await;

            if result.is_ok() && mso_requires_update(&detail_credential) {
                let result = obtain_and_update_new_mso(
                    &mut credential,
                    &*self.credential_repository,
                    &*self.key_provider,
                    interaction_data,
                    &*self.client,
                )
                .await;

                // If we have managed to refresh mso
                if result.is_ok() {
                    let credential_str = String::from_utf8(credential.credential.clone())
                        .map_err(|e| ServiceError::MappingError(e.to_string()))?;

                    detail_credential = formatter
                        .extract_credentials_unverified(&credential_str)
                        .await?;
                }
            }

            // If update could not be fetched and mso is outdated
            // mark as revoked
            if !is_mso_up_to_date(&detail_credential) {
                let update_request = UpdateCredentialRequest {
                    id: credential.id,
                    credential: None,
                    holder_did_id: None,
                    issuer_did_id: None,
                    state: Some(CredentialState {
                        created_date: OffsetDateTime::now_utc(),
                        state: CredentialStateEnum::Revoked,
                        suspend_end_date: None,
                    }),
                    interaction: None,
                    key: None,
                    redirect_uri: None,
                };

                let _ = &self
                    .credential_repository
                    .update_credential(update_request)
                    .await?;

                current_state = CredentialStateEnum::Revoked;
            }
        }

        let credential_status = match current_state {
            CredentialStateEnum::Accepted | CredentialStateEnum::Suspended => {
                if !detail_credential.status.is_empty() {
                    detail_credential.status
                } else {
                    // no credential status -> credential is irrevocable
                    return Ok(CredentialRevocationCheckResponseDTO {
                        credential_id,
                        status: CredentialStateEnum::Accepted.into(),
                        success: true,
                        reason: None,
                    });
                }
            }
            CredentialStateEnum::Revoked => {
                // credential already revoked, no need to check further
                return Ok(CredentialRevocationCheckResponseDTO {
                    credential_id,
                    status: CredentialStateEnum::Revoked.into(),
                    success: true,
                    reason: None,
                });
            }
            _ => {
                // cannot check pending credentials etc
                return Ok(CredentialRevocationCheckResponseDTO {
                    credential_id,
                    success: false,
                    reason: Some(format!("Invalid credential state: {current_state}")),
                    status: current_state.into(),
                });
            }
        };

        let revocation_method = self
            .revocation_method_provider
            .get_revocation_method(&credential_schema.revocation_method)
            .ok_or(MissingProviderError::RevocationMethod(
                credential_schema.revocation_method.clone(),
            ))?;

        let issuer_did = credential
            .issuer_did
            .to_owned()
            .ok_or(ServiceError::MappingError("issuer_did is None".to_string()))?;

        let credential_data_by_role = match credential.role {
            CredentialRole::Holder => {
                Some(CredentialDataByRole::Holder(credential.to_owned().into()))
            }
            CredentialRole::Issuer => {
                Some(CredentialDataByRole::Issuer(credential.to_owned().into()))
            }
            CredentialRole::Verifier => None,
        };

        let mut worst_revocation_state = CredentialRevocationState::Valid;
        for status in credential_status {
            match revocation_method
                .check_credential_revocation_status(
                    &status,
                    &issuer_did.did.to_owned().into(),
                    credential_data_by_role.to_owned(),
                )
                .await
            {
                Err(error) => {
                    return Ok(CredentialRevocationCheckResponseDTO {
                        credential_id,
                        status: current_state.into(),
                        success: false,
                        reason: Some(error.to_string()),
                    })
                }
                Ok(state) => match state {
                    CredentialRevocationState::Valid => {}
                    CredentialRevocationState::Revoked => {
                        worst_revocation_state = state;
                        break;
                    }
                    CredentialRevocationState::Suspended { .. } => {
                        worst_revocation_state = state;
                    }
                },
            };
        }

        let detected_state =
            credential_revocation_state_to_model_state(worst_revocation_state.to_owned());

        let suspend_end_date = match worst_revocation_state {
            CredentialRevocationState::Suspended { suspend_end_date } => suspend_end_date,
            _ => None,
        };

        // update local credential state if change detected
        if current_state != detected_state {
            self.credential_repository
                .update_credential(UpdateCredentialRequest {
                    id: credential_id,
                    state: Some(CredentialState {
                        created_date: OffsetDateTime::now_utc(),
                        state: detected_state.to_owned(),
                        suspend_end_date,
                    }),
                    credential: None,
                    holder_did_id: None,
                    issuer_did_id: None,
                    interaction: None,
                    key: None,
                    redirect_uri: None,
                })
                .await?;

            let _ = log_history_event_credential_revocation(
                &*self.history_repository,
                &credential,
                worst_revocation_state,
            )
            .await;
        }

        Ok(CredentialRevocationCheckResponseDTO {
            credential_id,
            status: detected_state.into(),
            success: true,
            reason: None,
        })
    }
}

async fn obtain_and_update_new_mso(
    credential: &mut Credential,
    credentials: &dyn CredentialRepository,
    key_provider: &dyn KeyProvider,
    interaction_data: HolderInteractionData,
    client: &dyn HttpClient,
) -> Result<(), ServiceError> {
    let key = credential
        .key
        .as_ref()
        .ok_or(ServiceError::Other("Missing key".to_owned()))?
        .clone();
    let holder_did = credential
        .holder_did
        .as_ref()
        .ok_or(ServiceError::Other("Missing holder did".to_owned()))?
        .clone();

    let auth_fn = key_provider
        .get_signature_provider(&key.to_owned(), None)
        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

    let proof_jwt = OpenID4VCIProofJWTFormatter::format_proof(
        interaction_data.issuer_url,
        &holder_did.clone().into(),
        key.key_type.to_owned(),
        auth_fn,
    )
    .await
    .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

    let schema = credential
        .schema
        .as_ref()
        .ok_or(ExchangeProtocolError::Failed("schema is None".to_string()))?;

    let body = OpenID4VCICredential {
        proof: OpenID4VCIProof {
            proof_type: "jwt".to_string(),
            jwt: proof_jwt,
        },
        format: "mso_mdoc".to_owned(),
        credential_definition: None,
        doctype: Some(schema.schema_id.to_owned()),
    };

    let response = client
        .post(&interaction_data.credential_endpoint)
        .bearer_auth(&interaction_data.access_token)
        .json(&body)
        .context("json error")
        .map_err(ExchangeProtocolError::Transport)?
        .send()
        .await
        .context("send error")
        .map_err(ExchangeProtocolError::Transport)?;
    let response = response
        .error_for_status()
        .context("status error")
        .map_err(ExchangeProtocolError::Transport)?;

    let result: OpenID4VCICredentialResponseDTO =
        serde_json::from_slice(&response.body).map_err(ExchangeProtocolError::JsonError)?;

    // Update credential value
    credential.credential = result.credential.as_bytes().to_vec();

    let update_request = UpdateCredentialRequest {
        id: credential.id,
        credential: Some(credential.credential.clone()),
        holder_did_id: None,
        issuer_did_id: None,
        state: None,
        interaction: None,
        key: None,
        redirect_uri: None,
    };

    credentials.update_credential(update_request).await?;
    Ok(())
}

async fn update_mso_interaction_access_token(
    credential: &mut Credential,
    interactions: &dyn InteractionRepository,
    mut interaction_data: HolderInteractionData,
    client: &dyn HttpClient,
) -> Result<(), ServiceError> {
    let now = OffsetDateTime::now_utc();

    let access_token_expires_at =
        interaction_data
            .access_token_expires_at
            .ok_or(ServiceError::Other(
                "Missing expires_at in interaction data for mso".to_owned(),
            ))?;

    if access_token_expires_at <= now {
        // Fetch a new one
        let url = format!("{}/token", interaction_data.issuer_url);
        let refresh_token = interaction_data
            .refresh_token
            .ok_or(ServiceError::Other("Missing refresh token".to_owned()))?;

        let token_response: OpenID4VCITokenResponseDTO = client
            .post(&url)
            .form(&[
                ("refresh_token", refresh_token),
                ("grant_type", "refresh_token".to_string()),
            ])
            .context("form error")
            .map_err(ExchangeProtocolError::Transport)?
            .send()
            .await
            .context("send error")
            .map_err(ExchangeProtocolError::Transport)?
            .error_for_status()
            .context("status error")
            .map_err(ExchangeProtocolError::Transport)?
            .json()
            .context("parsing error")
            .map_err(ExchangeProtocolError::Transport)?;

        interaction_data.access_token = token_response.access_token;
        interaction_data.access_token_expires_at =
            OffsetDateTime::from_unix_timestamp(token_response.expires_in.0).ok();

        interaction_data.refresh_token = token_response.refresh_token;
        interaction_data.refresh_token_expires_at = token_response
            .refresh_token_expires_in
            .and_then(|expires_in| OffsetDateTime::from_unix_timestamp(expires_in.0).ok());

        let mut interaction = credential
            .interaction
            .as_ref()
            .ok_or(ServiceError::Other("Missing interaction".to_owned()))?
            .clone();

        interaction.data = Some(
            serde_json::to_vec(&interaction_data)
                .map_err(|e| ServiceError::MappingError(e.to_string()))?,
        );

        // Update in database
        interactions.update_interaction(interaction.clone()).await?;

        // Update local copy as well
        credential.interaction = Some(interaction);
    }

    Ok(())
}

fn is_mso_up_to_date(detail_credential: &DetailCredential) -> bool {
    let now = OffsetDateTime::now_utc();

    if let Some(expires_at) = detail_credential.valid_until {
        return expires_at > now;
    }

    false
}

fn mso_requires_update(detail_credential: &DetailCredential) -> bool {
    let now = OffsetDateTime::now_utc();

    if let Some(update_at) = detail_credential.update_at {
        return update_at < now;
    }

    false
}
