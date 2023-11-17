use time::OffsetDateTime;

use crate::common_validator::{throw_if_did_type_is_eq, throw_if_latest_credential_state_not_eq};
use crate::model::credential::CredentialStateEnum;
use crate::model::did::DidType;
use crate::{
    common_mapper::list_response_try_into,
    model::{
        claim::ClaimRelations,
        claim_schema::ClaimSchemaRelations,
        common::EntityShareResponseDTO,
        credential::{
            self, Credential, CredentialId, CredentialRelations, CredentialState,
            CredentialStateRelations, UpdateCredentialRequest,
        },
        credential_schema::CredentialSchemaRelations,
        did::DidRelations,
        key::KeyRelations,
        organisation::OrganisationRelations,
    },
    provider::credential_formatter::jwt::SkipVerification,
    service::{
        credential::{
            dto::{
                CreateCredentialRequestDTO, CredentialDetailResponseDTO,
                CredentialRevocationCheckResponseDTO, GetCredentialListResponseDTO,
                GetCredentialQueryDTO,
            },
            mapper::{claims_from_create_request, from_create_request},
            CredentialService,
        },
        error::ServiceError,
    },
};

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
        let issuer_did = self
            .did_repository
            .get_did(&request.issuer_did, &DidRelations::default())
            .await
            .map_err(ServiceError::from)?;

        throw_if_did_type_is_eq(&issuer_did, DidType::Remote)?;

        let schema = self
            .credential_schema_repository
            .get_credential_schema(
                &request.credential_schema_id,
                &CredentialSchemaRelations {
                    claim_schemas: Some(ClaimSchemaRelations::default()),
                    organisation: None,
                },
            )
            .await
            .map_err(ServiceError::from)?;

        super::validator::validate_create_request(
            &request.transport,
            &request.claim_values,
            &schema,
            &self.config,
        )?;

        let claim_schemas = schema
            .claim_schemas
            .to_owned()
            .ok_or(ServiceError::MappingError(
                "claim_schemas is None".to_string(),
            ))?;

        let claims = claims_from_create_request(request.claim_values.clone(), &claim_schemas)?;
        let credential = from_create_request(request, claims, issuer_did, schema);

        let result = self
            .credential_repository
            .create_credential(credential)
            .await
            .map_err(ServiceError::from)?;
        Ok(result)
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
            .await
            .map_err(ServiceError::from)?;

        credential.try_into()
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
            .await
            .map_err(ServiceError::from)?;
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
                    schema: Some(CredentialSchemaRelations::default()),
                    ..Default::default()
                },
            )
            .await?;

        throw_if_latest_credential_state_not_eq(&credential, CredentialStateEnum::Accepted)?;

        let revocation_method = self.revocation_method_provider.get_revocation_method(
            &credential
                .schema
                .as_ref()
                .ok_or(ServiceError::MappingError(
                    "credential schema is None".to_string(),
                ))?
                .revocation_method,
        )?;
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
                ..Default::default()
            })
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
        let mut result: Vec<CredentialRevocationCheckResponseDTO> = vec![];

        for credential_id in credential_ids {
            let credential = self
                .credential_repository
                .get_credential(
                    &credential_id,
                    &CredentialRelations {
                        state: Some(CredentialStateRelations::default()),
                        schema: Some(CredentialSchemaRelations::default()),
                        issuer_did: Some(DidRelations::default()),
                        ..Default::default()
                    },
                )
                .await?;

            let current_state = credential
                .state
                .as_ref()
                .ok_or(ServiceError::MappingError("state is None".to_string()))?
                .get(0)
                .ok_or(ServiceError::MappingError(
                    "latest state not found".to_string(),
                ))?
                .to_owned()
                .state;

            let credential_schema = credential
                .schema
                .ok_or(ServiceError::MappingError("schema is None".to_string()))?;

            let credential_status = match current_state {
                CredentialStateEnum::Accepted => {
                    let formatter = self
                        .formatter_provider
                        .get_formatter(&credential_schema.format)?;

                    let credential = String::from_utf8(credential.credential)
                        .map_err(|e| ServiceError::MappingError(e.to_string()))?;

                    let credential = formatter
                        .extract_credentials(&credential, Box::new(SkipVerification))
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
                .get_revocation_method(&credential_schema.revocation_method)?;

            let issuer_did = credential
                .issuer_did
                .ok_or(ServiceError::MappingError("issuer_did is None".to_string()))?;

            let revoked = match revocation_method
                .check_credential_revocation_status(&credential_status, &issuer_did.did)
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
                            state: credential::CredentialStateEnum::Revoked,
                        }),
                        ..Default::default()
                    })
                    .await?;
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
                        ..Default::default()
                    })
                    .await
                    .map_err(ServiceError::from)?;
            }
            CredentialStateEnum::Pending => {}
            _ => return Err(ServiceError::AlreadyShared),
        }

        let transport_instance = &self
            .config
            .exchange
            .get(&credential.transport)
            .ok_or(ServiceError::MissingTransportProtocol(
                credential.transport.to_owned(),
            ))?
            .r#type;

        let transport = self.protocol_provider.get_protocol(transport_instance)?;

        let url = transport.share_credential(&credential).await?;

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
                    ..Default::default()
                },
            )
            .await?;

        let credential_states = credential
            .state
            .as_ref()
            .ok_or(ServiceError::MappingError("state is None".to_string()))?;
        let latest_state = credential_states
            .get(0)
            .ok_or(ServiceError::MappingError("state is missing".to_string()))?
            .state
            .clone();
        Ok((credential, latest_state))
    }
}
