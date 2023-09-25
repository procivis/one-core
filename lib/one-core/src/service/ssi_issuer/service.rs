use super::{dto::IssuerResponseDTO, SSIIssuerService};
use crate::{
    model::{
        claim::ClaimRelations,
        claim_schema::ClaimSchemaRelations,
        credential::{
            CredentialId, CredentialRelations, CredentialState, CredentialStateEnum,
            CredentialStateRelations, UpdateCredentialRequest,
        },
        credential_schema::CredentialSchemaRelations,
        did::{Did, DidId, DidRelations, DidType},
        organisation::OrganisationRelations,
    },
    repository::error::DataLayerError,
    service::{credential::dto::CredentialResponseDTO, error::ServiceError},
};
use time::OffsetDateTime;

impl SSIIssuerService {
    pub async fn issuer_connect(
        &self,
        credential_id: &CredentialId,
        holder_did_value: &String,
    ) -> Result<CredentialResponseDTO, ServiceError> {
        let mut credential = self
            .credential_repository
            .get_credential(
                credential_id,
                &CredentialRelations {
                    state: Some(CredentialStateRelations::default()),
                    schema: Some(CredentialSchemaRelations {
                        organisation: Some(OrganisationRelations::default()),
                        claim_schemas: Some(ClaimSchemaRelations::default()),
                    }),
                    claims: Some(ClaimRelations {
                        schema: Some(ClaimSchemaRelations::default()),
                    }),
                    issuer_did: Some(DidRelations::default()),
                    ..Default::default()
                },
            )
            .await?;

        let latest_state = credential
            .state
            .as_ref()
            .ok_or(ServiceError::MappingError("state is None".to_string()))?
            .get(0)
            .ok_or(ServiceError::MappingError("state is missing".to_string()))?;
        if latest_state.state != CredentialStateEnum::Pending {
            return Err(ServiceError::AlreadyExists);
        }

        let credential_schema = credential
            .schema
            .as_ref()
            .ok_or(ServiceError::MappingError("schema is None".to_string()))?;

        let holder_did =
            match self
                .did_repository
                .get_did_by_value(holder_did_value, &DidRelations::default())
                .await
            {
                Ok(did) => did,
                Err(DataLayerError::RecordNotFound) => {
                    let organisation = credential_schema.organisation.as_ref().ok_or(
                        ServiceError::MappingError("organisation is None".to_string()),
                    )?;

                    let did = Did {
                        id: DidId::new_v4(),
                        created_date: OffsetDateTime::now_utc(),
                        last_modified: OffsetDateTime::now_utc(),
                        name: "holder".to_string(),
                        organisation_id: organisation.id,
                        did: holder_did_value.clone(),
                        did_method: "KEY".to_string(),
                        did_type: DidType::Remote,
                    };
                    self.did_repository.create_did(did.clone()).await?;
                    did
                }
                Err(e) => {
                    return Err(ServiceError::from(e));
                }
            };

        let now: OffsetDateTime = OffsetDateTime::now_utc();
        let new_state = CredentialStateEnum::Offered;

        self.credential_repository
            .update_credential(UpdateCredentialRequest {
                id: credential_id.to_owned(),
                credential: None,
                holder_did_id: Some(holder_did.id),
                state: Some(CredentialState {
                    created_date: now,
                    state: new_state.clone(),
                }),
            })
            .await?;

        // Update local copy for conversion.
        credential.holder_did = Some(holder_did);
        if let Some(states) = &mut credential.state {
            states.push(CredentialState {
                created_date: now,
                state: new_state,
            });
        }

        credential.try_into()
    }

    pub async fn issuer_submit(
        &self,
        credential_id: &CredentialId,
    ) -> Result<IssuerResponseDTO, ServiceError> {
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

        let latest_state = credential
            .state
            .as_ref()
            .ok_or(ServiceError::MappingError("state is None".to_string()))?
            .get(0)
            .ok_or(ServiceError::MappingError("state is missing".to_string()))?;
        if latest_state.state != CredentialStateEnum::Offered {
            return Err(ServiceError::AlreadyExists);
        }

        let credential_schema = credential
            .schema
            .as_ref()
            .ok_or(ServiceError::MappingError("schema is None".to_string()))?;

        let holder_did = credential
            .holder_did
            .as_ref()
            .ok_or(ServiceError::MappingError("holder did is None".to_string()))?
            .clone();

        let token = self
            .formatter_provider
            .get_formatter(&credential_schema.format)?
            .format_credentials(&credential.try_into()?, &holder_did.did)?;

        self.credential_repository
            .update_credential(UpdateCredentialRequest {
                id: credential_id.to_owned(),
                credential: Some(token.bytes().collect()),
                holder_did_id: None,
                state: Some(CredentialState {
                    created_date: OffsetDateTime::now_utc(),
                    state: CredentialStateEnum::Accepted,
                }),
            })
            .await?;

        Ok(IssuerResponseDTO {
            credential: token,
            format: "JWT".to_string(),
        })
    }

    pub async fn issuer_reject(&self, credential_id: &CredentialId) -> Result<(), ServiceError> {
        let credential = self
            .credential_repository
            .get_credential(
                credential_id,
                &CredentialRelations {
                    state: Some(CredentialStateRelations::default()),
                    schema: Some(CredentialSchemaRelations {
                        organisation: Some(OrganisationRelations::default()),
                        ..Default::default()
                    }),
                    claims: Some(ClaimRelations {
                        schema: Some(ClaimSchemaRelations::default()),
                    }),
                    ..Default::default()
                },
            )
            .await?;

        let latest_state = credential
            .state
            .as_ref()
            .ok_or(ServiceError::MappingError("state is None".to_string()))?
            .get(0)
            .ok_or(ServiceError::MappingError("state is missing".to_string()))?;
        if latest_state.state != CredentialStateEnum::Offered {
            return Err(ServiceError::AlreadyExists);
        }

        self.credential_repository
            .update_credential(UpdateCredentialRequest {
                id: credential_id.to_owned(),
                credential: None,
                holder_did_id: None,
                state: Some(CredentialState {
                    created_date: OffsetDateTime::now_utc(),
                    state: CredentialStateEnum::Rejected,
                }),
            })
            .await?;

        Ok(())
    }
}
