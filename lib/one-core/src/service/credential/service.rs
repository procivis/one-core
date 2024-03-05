use shared_types::CredentialId;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    common_mapper::list_response_try_into,
    common_validator::{
        throw_if_latest_credential_state_eq, throw_if_latest_credential_state_not_eq,
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
        did::{DidRelations, DidType, KeyRole},
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

use super::mapper::{credential_offered_history_event, credential_revoked_history_event};

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

        super::validator::validate_create_request(
            &request.transport,
            &request.claim_values,
            &schema,
            &self.config,
        )?;

        let credential_id = Uuid::new_v4().into();
        let claims = claims_from_create_request(
            credential_id,
            request.claim_values.clone(),
            &claim_schemas,
        )?;

        let key = match request.issuer_key {
            Some(key_id) => issuer_did
                .keys
                .as_ref()
                .ok_or_else(|| ServiceError::MappingError("keys is None".to_string()))?
                .iter()
                .filter(|entry| entry.role == KeyRole::AssertionMethod)
                .find(|entry| entry.key.id == key_id)
                .ok_or(ServiceError::Validation(ValidationError::InvalidKey(
                    "key not found or has wrong role".into(),
                )))?,
            None => issuer_did
                .keys
                .as_ref()
                .ok_or_else(|| ServiceError::MappingError("keys is None".to_string()))?
                .iter()
                .find(|entry| entry.role == KeyRole::AssertionMethod)
                .ok_or_else(|| {
                    ServiceError::Validation(ValidationError::InvalidKey(
                        "no assertion method keys found in did".to_string(),
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

    /// Revokes credential
    ///
    /// # Arguments
    ///
    /// * `CredentialId` - Id of an existing credential
    pub async fn revoke_credential(
        &self,
        credential_id: &CredentialId,
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
                    ..Default::default()
                },
            )
            .await?;

        let Some(credential) = credential else {
            return Err(EntityNotFoundError::Credential(*credential_id).into());
        };

        throw_if_latest_credential_state_not_eq(&credential, CredentialStateEnum::Accepted)?;

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

        revocation_method
            .mark_credential_revoked(&credential)
            .await?;

        let now: OffsetDateTime = OffsetDateTime::now_utc();
        self.credential_repository
            .update_credential(UpdateCredentialRequest {
                id: credential_id.to_owned(),
                state: Some(CredentialState {
                    created_date: now,
                    state: CredentialStateEnum::Revoked,
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
            .create_history(credential_revoked_history_event(
                *credential_id,
                credential.schema.and_then(|c| c.organisation),
            ))
            .await;

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
        let mut result: Vec<CredentialRevocationCheckResponseDTO> = vec![];
        for credential_id in credential_ids {
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
                CredentialStateEnum::Accepted => {
                    let formatter = self
                        .formatter_provider
                        .get_formatter(&format)
                        .ok_or(MissingProviderError::Formatter(credential_schema.format))?;

                    let credential = formatter
                        .extract_credentials_unverified(&credential_str)
                        .await?;

                    if let Some(status) = credential.status {
                        status
                    } else {
                        result.push(CredentialRevocationCheckResponseDTO {
                            credential_id,
                            status: CredentialStateEnum::Accepted.into(),
                            success: true,
                            reason: None,
                        });
                        continue;
                    }
                }
                CredentialStateEnum::Revoked => {
                    result.push(CredentialRevocationCheckResponseDTO {
                        credential_id,
                        status: CredentialStateEnum::Revoked.into(),
                        success: true,
                        reason: None,
                    });
                    continue;
                }
                _ => {
                    result.push(CredentialRevocationCheckResponseDTO {
                        credential_id,
                        status: current_state.into(),
                        success: false,
                        reason: Some("Invalid credential state".to_string()),
                    });
                    continue;
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
                CredentialRole::Holder => {
                    Some(CredentialDataByRole::Holder(credential_id.to_owned()))
                }
                CredentialRole::Issuer => {
                    Some(CredentialDataByRole::Issuer(credential_id.to_owned()))
                }
                CredentialRole::Verifier => None,
            };

            let revoked = match revocation_method
                .check_credential_revocation_status(
                    &credential_status,
                    &issuer_did.did,
                    credential_data_by_role,
                )
                .await
            {
                Err(error) => {
                    result.push(CredentialRevocationCheckResponseDTO {
                        credential_id,
                        status: current_state.into(),
                        success: false,
                        reason: Some(error.to_string()),
                    });
                    continue;
                }
                Ok(revoked) => revoked,
            };

            result.push(CredentialRevocationCheckResponseDTO {
                credential_id,
                status: if revoked {
                    CredentialStateEnum::Revoked.into()
                } else {
                    CredentialStateEnum::Accepted.into()
                },
                success: true,
                reason: None,
            });
            // update local credential state if revoked on the list
            if revoked {
                self.credential_repository
                    .update_credential(UpdateCredentialRequest {
                        id: credential_id.to_owned(),
                        state: Some(CredentialState {
                            created_date: OffsetDateTime::now_utc(),
                            state: CredentialStateEnum::Revoked,
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
                    .create_history(credential_revoked_history_event(
                        credential_id,
                        credential_schema.organisation,
                    ))
                    .await;
            }
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
}
