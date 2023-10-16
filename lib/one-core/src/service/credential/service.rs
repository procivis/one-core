use time::OffsetDateTime;

use crate::{
    common_mapper::list_response_try_into,
    model::{
        claim::ClaimRelations,
        claim_schema::ClaimSchemaRelations,
        common::EntityShareResponseDTO,
        credential::{
            self, CredentialId, CredentialRelations, CredentialState, CredentialStateRelations,
            UpdateCredentialRequest,
        },
        credential_schema::CredentialSchemaRelations,
        did::DidRelations,
        organisation::OrganisationRelations,
    },
    service::{
        credential::{
            dto::{
                CreateCredentialRequestDTO, CredentialDetailResponseDTO, CredentialStateEnum,
                GetCredentialListResponseDTO, GetCredentialQueryDTO,
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
                    issuer_did: Some(DidRelations::default()),
                    schema: Some(CredentialSchemaRelations::default()),
                    ..Default::default()
                },
            )
            .await?;

        super::validator::validate_state_for_revocation(&credential.state)?;

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
                credential: None,
                holder_did_id: None,
                state: Some(CredentialState {
                    created_date: now,
                    state: credential::CredentialStateEnum::Revoked,
                }),
            })
            .await?;

        Ok(())
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
            CredentialStateEnum::Created | CredentialStateEnum::Pending => {
                let now = OffsetDateTime::now_utc();

                if current_state == CredentialStateEnum::Created {
                    self.credential_repository
                        .update_credential(UpdateCredentialRequest {
                            id: credential_id.to_owned(),
                            credential: None,
                            holder_did_id: None,
                            state: Some(CredentialState {
                                created_date: now,
                                state: credential::CredentialStateEnum::Pending,
                            }),
                        })
                        .await
                        .map_err(ServiceError::from)?;
                }

                Ok(EntityShareResponseDTO {
                    id: credential_id.to_owned(),
                    transport: "PROCIVIS_TEMPORARY".to_string(),
                })
            }

            _ => Err(ServiceError::AlreadyExists),
        }
    }
}
