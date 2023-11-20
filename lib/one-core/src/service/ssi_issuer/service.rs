use super::{dto::IssuerResponseDTO, SSIIssuerService};
use crate::common_mapper::get_or_create_did;
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
        did::DidRelations,
        organisation::OrganisationRelations,
    },
    service::{credential::dto::CredentialDetailResponseDTO, error::ServiceError},
};
use shared_types::DidValue;
use time::OffsetDateTime;

impl SSIIssuerService {
    pub async fn issuer_connect(
        &self,
        credential_id: &CredentialId,
        holder_did_value: &DidValue,
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

        /*
         * TODO: holder_did_value is not verified if it's a valid/supported DID
         * I was able to insert 'test' string as a DID value and it got accepted
         */
        let holder_did = get_or_create_did(
            &self.did_repository,
            &credential_schema.organisation,
            holder_did_value,
        )
        .await?;

        let now: OffsetDateTime = OffsetDateTime::now_utc();
        let new_state = CredentialStateEnum::Offered;

        self.credential_repository
            .update_credential(UpdateCredentialRequest {
                id: credential_id.to_owned(),
                holder_did_id: Some(holder_did.id.clone()),
                state: Some(CredentialState {
                    created_date: now,
                    state: new_state.clone(),
                }),
                ..Default::default()
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
                state: Some(CredentialState {
                    created_date: OffsetDateTime::now_utc(),
                    state: CredentialStateEnum::Rejected,
                }),
                ..Default::default()
            })
            .await?;

        Ok(())
    }
}
