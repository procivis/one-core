use shared_types::CredentialId;
use uuid::Uuid;

use super::mapper::credential_detail_response_from_model;
use super::validator::{validate_redirect_uri, verify_suspension_support};
use crate::common_mapper::list_response_try_into;
use crate::common_validator::{throw_if_credential_state_eq, throw_if_state_not_in};
use crate::config::core_config::RevocationType;
use crate::model::claim::ClaimRelations;
use crate::model::claim_schema::ClaimSchemaRelations;
use crate::model::common::EntityShareResponseDTO;
use crate::model::credential::{
    Clearable, Credential, CredentialRelations, CredentialRole, CredentialStateEnum,
    UpdateCredentialRequest,
};
use crate::model::credential_schema::CredentialSchemaRelations;
use crate::model::did::{DidRelations, DidType, KeyRole, RelatedKey};
use crate::model::history::HistoryAction;
use crate::model::interaction::InteractionRelations;
use crate::model::key::KeyRelations;
use crate::model::organisation::OrganisationRelations;
use crate::model::validity_credential::ValidityCredentialType;
use crate::provider::exchange_protocol::error::ExchangeProtocolError;
use crate::provider::exchange_protocol::openid4vc::model::ShareResponse;
use crate::provider::revocation::error::RevocationError;
use crate::provider::revocation::model::{
    CredentialDataByRole, CredentialRevocationState, Operation, RevocationMethodCapabilities,
};
use crate::repository::error::DataLayerError;
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
use crate::util::history::log_history_event_credential;
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

        let exchange_capabilities = self
            .protocol_provider
            .get_protocol(&request.exchange)
            .ok_or(MissingProviderError::ExchangeProtocol(
                request.exchange.to_owned(),
            ))?
            .get_capabilities();

        super::validator::validate_create_request(
            &issuer_did.did_method,
            &request.exchange,
            &exchange_capabilities,
            &request.claim_values,
            &schema,
            &formatter_capabilities,
            &self.config,
        )?;
        validate_redirect_uri(
            &request.exchange,
            request.redirect_uri.as_deref(),
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
            throw_if_credential_state_eq(&credential, CredentialStateEnum::Accepted)?;
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

        let mdoc_validity_credentials = match &credential.schema {
            Some(schema) if schema.format == "MDOC" => {
                self.validity_credential_repository
                    .get_latest_by_credential_id(*credential_id, ValidityCredentialType::Mdoc)
                    .await?
            }
            _ => None,
        };

        let mut response = credential_detail_response_from_model(
            credential,
            &self.config,
            mdoc_validity_credentials,
        )
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
        force_refresh: bool,
    ) -> Result<Vec<CredentialRevocationCheckResponseDTO>, ServiceError> {
        let mut result = vec![];
        for credential_id in credential_ids {
            result.push(
                self.check_credential_revocation_status(credential_id, force_refresh)
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
        let credential = self.get_credential_with_state(credential_id).await?;

        if credential.deleted_at.is_some() {
            return Err(EntityNotFoundError::Credential(*credential_id).into());
        }

        match credential.state {
            CredentialStateEnum::Created => {
                self.credential_repository
                    .update_credential(
                        *credential_id,
                        UpdateCredentialRequest {
                            state: Some(CredentialStateEnum::Pending),
                            suspend_end_date: Clearable::DontTouch,
                            ..Default::default()
                        },
                    )
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
            let format_type = self
                .config
                .format
                .get_fields(&credential_schema.format)
                .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?
                .r#type;

            map_core_to_oidc_format(&format_type)
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
            interaction_id,
            context,
        } = exchange
            .issuer_share_credential(&credential, &format)
            .await?;

        let organisation = if let Some(organisation) = credential
            .schema
            .as_ref()
            .and_then(|schema| schema.organisation.as_ref())
        {
            organisation
        } else {
            return Err(ServiceError::MappingError(
                "Missing organisation".to_string(),
            ));
        };

        add_new_interaction(
            interaction_id,
            &self.base_url,
            &*self.interaction_repository,
            serde_json::to_vec(&context).ok(),
            Some(organisation.to_owned()),
        )
        .await?;
        update_credentials_interaction(credential.id, interaction_id, &*self.credential_repository)
            .await?;
        clear_previous_interaction(&*self.interaction_repository, &credential.interaction).await?;

        log_history_event_credential(
            &*self.history_repository,
            &credential,
            HistoryAction::Shared,
        )
        .await;

        Ok(EntityShareResponseDTO { url })
    }

    // ============ Private methods

    /// Get credential with the latest credential state
    async fn get_credential_with_state(
        &self,
        id: &CredentialId,
    ) -> Result<Credential, ServiceError> {
        let credential = self
            .credential_repository
            .get_credential(
                id,
                &CredentialRelations {
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

        Ok(credential)
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

        if credential.deleted_at.is_some() {
            return Err(EntityNotFoundError::Credential(*credential_id).into());
        }

        let credential_schema = credential
            .schema
            .as_ref()
            .ok_or(ServiceError::MappingError(
                "credential schema is None".to_string(),
            ))?;

        verify_suspension_support(credential_schema, &revocation_state)?;

        let issuer = credential
            .issuer_did
            .as_ref()
            .ok_or(ServiceError::MappingError("issuer_did is None".to_string()))?;

        let did_document = self.did_method_provider.resolve(&issuer.did).await?;

        let Some(verification_method) =
            did_document.find_verification_method(None, Some(KeyRole::AssertionMethod))
        else {
            return Err(ServiceError::Revocation(
                RevocationError::KeyWithRoleNotFound(KeyRole::AssertionMethod),
            ));
        };

        let current_state = &credential.state;

        let valid_states: &[CredentialStateEnum] = match revocation_state {
            CredentialRevocationState::Revoked => &[
                CredentialStateEnum::Accepted,
                CredentialStateEnum::Suspended,
            ],
            CredentialRevocationState::Valid => &[CredentialStateEnum::Suspended],
            CredentialRevocationState::Suspended { .. } => &[CredentialStateEnum::Accepted],
        };
        throw_if_state_not_in(current_state, valid_states)?;

        let revocation_method_key = &credential_schema.revocation_method;

        let revocation_method = self
            .revocation_method_provider
            .get_revocation_method(revocation_method_key)
            .ok_or(MissingProviderError::RevocationMethod(
                revocation_method_key.to_owned(),
            ))?;

        let capabilities: RevocationMethodCapabilities = revocation_method.get_capabilities();
        let required_capability = match revocation_state {
            CredentialRevocationState::Valid | CredentialRevocationState::Suspended { .. } => {
                Operation::Suspend
            }
            CredentialRevocationState::Revoked => Operation::Revoke,
        };
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
                &credential,
                revocation_state.to_owned(),
                generate_credential_additional_data(
                    &credential,
                    &*self.credential_repository,
                    &*self.revocation_list_repository,
                    &*revocation_method,
                    &*self.formatter_provider,
                    &self.key_provider,
                    &self.key_algorithm_provider,
                    &self.base_url,
                    verification_method.id.to_owned(),
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

        let suspend_end_date =
            if let CredentialRevocationState::Suspended { suspend_end_date } = &revocation_state {
                suspend_end_date.to_owned()
            } else {
                None
            };
        self.credential_repository
            .update_credential(
                *credential_id,
                UpdateCredentialRequest {
                    state: Some(credential_revocation_state_to_model_state(
                        revocation_state.to_owned(),
                    )),
                    suspend_end_date: Clearable::ForceSet(suspend_end_date),
                    ..Default::default()
                },
            )
            .await?;

        Ok(())
    }

    async fn check_credential_revocation_status(
        &self,
        credential_id: CredentialId,
        force_refresh: bool,
    ) -> Result<CredentialRevocationCheckResponseDTO, ServiceError> {
        let credential = self
            .credential_repository
            .get_credential(
                &credential_id,
                &CredentialRelations {
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
                    interaction: Some(InteractionRelations {
                        organisation: Some(OrganisationRelations::default()),
                    }),
                    key: Some(KeyRelations::default()),
                    ..Default::default()
                },
            )
            .await?
            .ok_or(ServiceError::EntityNotFound(
                EntityNotFoundError::Credential(credential_id),
            ))?;

        if credential.deleted_at.is_some() {
            return Err(EntityNotFoundError::Credential(credential_id).into());
        }

        if credential.role != CredentialRole::Holder {
            return Err(BusinessLogicError::RevocationCheckNotAllowedForRole {
                role: credential.role,
                credential_id,
            }
            .into());
        }

        let credential_schema = credential
            .schema
            .as_ref()
            .ok_or(ServiceError::MappingError("schema is None".to_string()))?
            .clone();

        let credential_str = String::from_utf8(credential.credential.clone())
            .map_err(|e| ServiceError::MappingError(e.to_string()))?;

        // Workaround credential format detection
        let format = detect_format_with_crypto_suite(&credential_schema.format, &credential_str)?;

        let current_state = credential.state;

        let formatter = self.formatter_provider.get_formatter(&format).ok_or(
            MissingProviderError::Formatter(credential_schema.format.clone()),
        )?;

        let detail_credential = formatter
            .extract_credentials_unverified(&credential_str)
            .await?;

        if format == "MDOC" {
            let new_state = self
                .check_mdoc_update(&credential, &detail_credential, force_refresh)
                .await?;

            if new_state != current_state {
                let update_request = UpdateCredentialRequest {
                    state: Some(new_state),
                    suspend_end_date: Clearable::DontTouch,
                    ..Default::default()
                };

                self.credential_repository
                    .update_credential(credential_id, update_request)
                    .await?;
            }

            //Mdoc flow ends here. Nothing else to do for MDOC
            return Ok(CredentialRevocationCheckResponseDTO {
                credential_id,
                status: new_state.into(),
                success: true,
                reason: None,
            });
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
                Some(CredentialDataByRole::Holder(Box::new(credential.clone())))
            }
            CredentialRole::Issuer | CredentialRole::Verifier => None,
        };

        let mut worst_revocation_state = CredentialRevocationState::Valid;
        for status in credential_status {
            match revocation_method
                .check_credential_revocation_status(
                    &status,
                    &issuer_did.did,
                    credential_data_by_role.to_owned(),
                    force_refresh,
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
                .update_credential(
                    credential_id,
                    UpdateCredentialRequest {
                        state: Some(detected_state.to_owned()),
                        suspend_end_date: Clearable::ForceSet(suspend_end_date),
                        ..Default::default()
                    },
                )
                .await?;
        }

        Ok(CredentialRevocationCheckResponseDTO {
            credential_id,
            status: detected_state.into(),
            success: true,
            reason: None,
        })
    }
}
