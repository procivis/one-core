use super::{dto::IssuerResponseDTO, SSIIssuerService};
use crate::common_validator::throw_if_latest_credential_state_not_eq;
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
    service::{credential::dto::CredentialDetailResponseDTO, error::ServiceError},
};
use time::OffsetDateTime;

impl SSIIssuerService {
    pub async fn issuer_connect(
        &self,
        credential_id: &CredentialId,
        holder_did_value: &String,
    ) -> Result<CredentialDetailResponseDTO, ServiceError> {
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

        throw_if_latest_credential_state_not_eq(&credential, CredentialStateEnum::Pending)?;

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
                        organisation: Some(organisation.to_owned()),
                        did: holder_did_value.clone(),
                        did_method: "KEY".to_string(),
                        did_type: DidType::Remote,
                        keys: None,
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
        let token = self
            .protocol_provider
            .issue_credential(credential_id)
            .await?;
        Ok(IssuerResponseDTO {
            credential: token.credential,
            format: token.format,
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

        throw_if_latest_credential_state_not_eq(&credential, CredentialStateEnum::Offered)?;

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
