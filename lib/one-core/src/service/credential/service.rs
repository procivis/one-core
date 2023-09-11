use crate::model::credential;
use crate::model::credential::{
    CredentialState, CredentialStateRelations, UpdateCredentialRequest,
};
use crate::service::credential::dto::{
    CreateCredentialFromJwtRequestDTO, CredentialStateEnum, EntityShareResponseDTO,
};
use crate::service::credential::mapper::{claims_from_create_request, from_jwt_create_request};
use crate::{
    model::{
        claim::ClaimRelations, claim_schema::ClaimSchemaRelations, credential::CredentialId,
        credential::CredentialRelations, credential_schema::CredentialSchemaRelations,
        did::DidRelations, organisation::OrganisationRelations,
    },
    service::{
        credential::{
            dto::{
                CreateCredentialRequestDTO, CredentialListItemResponseDTO, CredentialResponseDTO,
                GetCredentialListResponseDTO, GetCredentialQueryDTO,
            },
            mapper::from_create_request,
            CredentialService,
        },
        error::ServiceError,
    },
};
use time::OffsetDateTime;

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
        let did = self
            .did_repository
            .get_did(&request.issuer_did, &DidRelations {})
            .await
            .map_err(ServiceError::from)?;
        let schema = self
            .credential_schema_repository
            .get_credential_schema(
                &request.credential_schema_id,
                &CredentialSchemaRelations {
                    claim_schema: Some(ClaimSchemaRelations {}),
                    organisation: None,
                },
            )
            .await
            .map_err(ServiceError::from)?;

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

        let claims = claims_from_create_request(request.claim_values.clone(), &claim_schemas)?;
        let credential = from_create_request(request, claims, did, schema);

        let result = self
            .credential_repository
            .create_credential(credential)
            .await
            .map_err(ServiceError::from)?;
        Ok(result)
    }

    /// Creates a credential according to request
    ///
    /// # Arguments
    ///
    /// * `request` - create credential request
    pub async fn create_credential_from_jwt(
        &self,
        request: CreateCredentialFromJwtRequestDTO,
    ) -> Result<CredentialId, ServiceError> {
        let issuer_did = self
            .did_repository
            .get_did(&request.issuer_did_id, &DidRelations {})
            .await
            .map_err(ServiceError::from)?;
        let holder_did = match &request.holder_did_id {
            None => None,
            Some(holder_did_id) => Some(
                self.did_repository
                    .get_did(holder_did_id, &DidRelations {})
                    .await
                    .map_err(ServiceError::from)?,
            ),
        };
        let schema = self
            .credential_schema_repository
            .get_credential_schema(
                &request.credential_schema_id,
                &CredentialSchemaRelations {
                    claim_schema: Some(ClaimSchemaRelations {}),
                    organisation: None,
                },
            )
            .await
            .map_err(ServiceError::from)?;

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

        let claims = claims_from_create_request(request.claim_values.clone(), &claim_schemas)?;
        let credential = from_jwt_create_request(request, claims, holder_did, issuer_did, schema);

        let result = self
            .credential_repository
            .create_credential(credential)
            .await
            .map_err(ServiceError::from)?;
        Ok(result)
    }

    /// Returns list of all credentials
    ///
    /// # Arguments
    ///
    /// * `query` - query parameters
    pub async fn get_all_credential_list(
        &self,
    ) -> Result<Vec<CredentialListItemResponseDTO>, ServiceError> {
        let credentials = self
            .credential_repository
            .get_all_credential_list()
            .await
            .map_err(ServiceError::from)?;

        credentials
            .into_iter()
            .map(|credential| credential.try_into().map_err(ServiceError::from))
            .collect::<Result<Vec<CredentialListItemResponseDTO>, ServiceError>>()
            .map_err(ServiceError::from)
    }

    /// Returns details of a credential
    ///
    /// # Arguments
    ///
    /// * `CredentialId` - Id of an existing credential
    pub async fn get_credential(
        &self,
        credential_id: &CredentialId,
    ) -> Result<CredentialResponseDTO, ServiceError> {
        let schema = self
            .credential_repository
            .get_credential(
                credential_id,
                &CredentialRelations {
                    state: Some(CredentialStateRelations {}),
                    claims: Some(ClaimRelations {
                        schema: Some(ClaimSchemaRelations {}),
                    }),
                    schema: Some(CredentialSchemaRelations {
                        claim_schema: None,
                        organisation: Some(OrganisationRelations {}),
                    }),
                    issuer_did: Some(DidRelations {}),
                    holder_did: Some(DidRelations {}),
                },
            )
            .await
            .map_err(ServiceError::from)?;

        schema.try_into()
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
        result.try_into()
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
        let current_state = self.get_credential(credential_id).await?.state;

        match current_state {
            CredentialStateEnum::Created
            | CredentialStateEnum::Offered
            | CredentialStateEnum::Pending => {
                let now = OffsetDateTime::now_utc();

                if current_state == CredentialStateEnum::Created {
                    self.credential_repository
                        .update_credential(UpdateCredentialRequest {
                            id: credential_id.to_owned(),
                            credential: None,
                            holder_did_id: None,
                            state: Some(CredentialState {
                                created_date: now,
                                state: credential::CredentialStateEnum::Created,
                            }),
                        })
                        .await
                        .map_err(ServiceError::from)?;
                }

                Ok(EntityShareResponseDTO {
                    credential_id: credential_id.to_string(),
                    transport: "PROCIVIS_TEMPORARY".to_string(),
                })
            }

            _ => Err(ServiceError::AlreadyExists),
        }
    }
}
