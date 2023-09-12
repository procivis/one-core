use super::{dto::ConnectIssuerResponseDTO, SSIIssuerService};
use crate::{
    model::{
        claim::ClaimRelations,
        claim_schema::ClaimSchemaRelations,
        credential::{
            CredentialId, CredentialRelations, CredentialStateEnum, CredentialStateRelations,
            UpdateCredentialRequest,
        },
        credential_schema::CredentialSchemaRelations,
        did::{Did, DidId, DidRelations, DidType},
        organisation::OrganisationRelations,
    },
    repository::error::DataLayerError,
    service::error::ServiceError,
};
use time::OffsetDateTime;

impl SSIIssuerService {
    pub async fn issuer_connect(
        &self,
        credential_id: &CredentialId,
        holder_did_value: &String,
    ) -> Result<ConnectIssuerResponseDTO, ServiceError> {
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

        let token = self
            .formatter_provider
            .get_formatter(&credential_schema.format)?
            .format_credentials(&credential.try_into()?, holder_did_value)?;

        self.credential_repository
            .update_credential(UpdateCredentialRequest {
                id: credential_id.to_owned(),
                credential: Some(token.bytes().collect()),
                holder_did_id: Some(holder_did.id),
                state: None,
            })
            .await?;

        Ok(ConnectIssuerResponseDTO {
            credential: token,
            format: "JWT".to_string(),
        })
    }
}
