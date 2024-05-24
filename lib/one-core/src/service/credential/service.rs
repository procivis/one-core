use shared_types::CredentialId;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::provider::revocation::{CredentialRevocationState, RevocationMethodCapabilities};
use crate::service::credential::dto::SuspendCredentialRequestDTO;
use crate::service::credential::mapper::{
    credential_revocation_history_event, credential_revocation_state_to_model_state,
};
use crate::{
    common_mapper::list_response_try_into,
    common_validator::{
        get_latest_state, throw_if_latest_credential_state_eq, throw_if_state_not_in,
    },
    config::core_config::RevocationType,
    model::{
        claim::ClaimRelations,
        claim_schema::ClaimSchemaRelations,
        common::EntityShareResponseDTO,
        credential::{
            self, Credential, CredentialRelations, CredentialRole, CredentialState,
            CredentialStateEnum, CredentialStateRelations, UpdateCredentialRequest,
        },
        credential_schema::CredentialSchemaRelations,
        did::{DidRelations, DidType, KeyRole, RelatedKey},
        key::KeyRelations,
        organisation::OrganisationRelations,
    },
    provider::revocation::CredentialDataByRole,
    repository::error::DataLayerError,
    service::{
        credential::{
            dto::{
                CreateCredentialRequestDTO, CredentialDetailResponseDTO,
                CredentialRevocationCheckResponseDTO, GetCredentialListResponseDTO,
                GetCredentialQueryDTO,
            },
            mapper::{
                claims_from_create_request, credential_created_history_event, from_create_request,
            },
            CredentialService,
        },
        error::{
            BusinessLogicError, EntityNotFoundError, MissingProviderError, ServiceError,
            ValidationError,
        },
    },
    util::oidc::detect_correct_format,
};

use super::mapper::credential_offered_history_event;

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
            &request.transport,
            &request.claim_values,
            &schema,
            &formatter_capabilities,
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

        let _ = self
            .history_repository
            .create_history(credential_created_history_event(credential)?)
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

        let mut response = CredentialDetailResponseDTO::try_from(credential)
            .map_err(|err| ServiceError::ResponseMapping(err.to_string()))?;

        if response.schema.revocation_method == "LVVC" {
            let latest_lvvc = self
                .lvvc_repository
                .get_latest_by_credential_id(credential_id.to_owned())
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

        let credential_transport = &credential.transport;

        let transport_instance = &self
            .config
            .exchange
            .get_fields(credential_transport)
            .map_err(|err| {
                ServiceError::MissingTransportProtocol(format!("{credential_transport}: {err}"))
            })?
            .r#type()
            .to_string();

        let transport = self
            .protocol_provider
            .get_protocol(transport_instance)
            .ok_or(MissingProviderError::TransportProtocol(
                transport_instance.clone(),
            ))?;

        let url = transport.share_credential(&credential).await?;

        let _ = self
            .history_repository
            .create_history(credential_offered_history_event(credential))
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
                    schema: Some(CredentialSchemaRelations {
                        organisation: Some(OrganisationRelations::default()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
            .await?;

        let Some(credential) = credential else {
            return Err(EntityNotFoundError::Credential(*id).into());
        };

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

        revocation_method
            .mark_credential_as(&credential, revocation_state.to_owned())
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

        let _ = self
            .history_repository
            .create_history(credential_revocation_history_event(
                *credential_id,
                revocation_state,
                credential.schema.and_then(|c| c.organisation),
            ))
            .await;

        Ok(())
    }

    async fn check_credential_revocation_status(
        &self,
        credential_id: CredentialId,
    ) -> Result<CredentialRevocationCheckResponseDTO, ServiceError> {
        let credential = self
            .credential_repository
            .get_credential(
                &credential_id,
                &CredentialRelations {
                    state: Some(CredentialStateRelations::default()),
                    schema: Some(CredentialSchemaRelations {
                        organisation: Some(OrganisationRelations::default()),
                        ..Default::default()
                    }),
                    issuer_did: Some(DidRelations::default()),
                    ..Default::default()
                },
            )
            .await?;

        let Some(credential) = credential else {
            return Err(EntityNotFoundError::Credential(credential_id).into());
        };

        let current_state = credential
            .state
            .as_ref()
            .ok_or(ServiceError::MappingError("state is None".to_string()))?
            .first()
            .ok_or(ServiceError::MappingError(
                "latest state not found".to_string(),
            ))?
            .to_owned()
            .state;

        let credential_schema = credential
            .schema
            .ok_or(ServiceError::MappingError("schema is None".to_string()))?;

        let credential_str = String::from_utf8(credential.credential)
            .map_err(|e| ServiceError::MappingError(e.to_string()))?;

        // Workaround credential format detection
        let format = detect_correct_format(&credential_schema, &credential_str)?;

        let credential_status = match current_state {
            CredentialStateEnum::Accepted | CredentialStateEnum::Suspended => {
                let formatter = self
                    .formatter_provider
                    .get_formatter(&format)
                    .ok_or(MissingProviderError::Formatter(credential_schema.format))?;

                let credential = formatter
                    .extract_credentials_unverified(&credential_str)
                    .await?;

                if !credential.status.is_empty() {
                    credential.status
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
                credential_schema.revocation_method,
            ))?;

        let issuer_did = credential
            .issuer_did
            .ok_or(ServiceError::MappingError("issuer_did is None".to_string()))?;

        let credential_data_by_role = match credential.role {
            CredentialRole::Holder => Some(CredentialDataByRole::Holder(credential_id)),
            CredentialRole::Issuer => Some(CredentialDataByRole::Issuer(credential_id)),
            CredentialRole::Verifier => None,
        };

        let mut worst_revocation_state = CredentialRevocationState::Valid;
        for status in credential_status {
            match revocation_method
                .check_credential_revocation_status(
                    &status,
                    &issuer_did.did,
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

            let _ = self
                .history_repository
                .create_history(credential_revocation_history_event(
                    credential_id,
                    worst_revocation_state,
                    credential_schema.organisation,
                ))
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
