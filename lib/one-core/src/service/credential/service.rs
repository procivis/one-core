use crate::{
    bitstring::generate_bitstring,
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
        did::{DidId, DidRelations},
        organisation::OrganisationRelations,
        revocation_list::RevocationListRelations,
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
                    ..Default::default()
                },
            )
            .await?;

        super::validator::validate_state_for_revocation(credential.state)?;

        let now = OffsetDateTime::now_utc();
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
            .await
            .map_err(ServiceError::from)?;

        let issuer_did_value = credential
            .issuer_did
            .as_ref()
            .ok_or(ServiceError::MappingError("issuer_did is None".to_string()))?;
        let issuer_did = self
            .did_repository
            .get_did_by_value(&issuer_did_value.did, &DidRelations::default())
            .await
            .map_err(ServiceError::from)?;
        let revocation_bitstring = self
            .generate_bitstring_from_credentials(&issuer_did.id)
            .await?;
        let revocation_list = self
            .revocation_list_repository
            .get_revocation_by_issuer_did_id(&issuer_did.id, &RevocationListRelations::default())
            .await?;

        self.revocation_list_repository
            .update_credentials(
                &revocation_list.id,
                revocation_bitstring.as_bytes().to_vec(),
            )
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

    async fn generate_bitstring_from_credentials(
        &self,
        issuer_did_id: &DidId,
    ) -> Result<String, ServiceError> {
        let credentials = self
            .credential_repository
            .get_credentials_by_issuer_did_id(
                issuer_did_id,
                &CredentialRelations {
                    state: Some(CredentialStateRelations {}),
                    ..Default::default()
                },
            )
            .await
            .map_err(ServiceError::from)?;

        let states: Vec<bool> = credentials
            .into_iter()
            .map(|credential| {
                let states = credential
                    .state
                    .ok_or(ServiceError::MappingError("state is None".to_string()))?;

                match states
                    .get(0)
                    .ok_or(ServiceError::MappingError(
                        "latest state not found".to_string(),
                    ))?
                    .state
                {
                    credential::CredentialStateEnum::Revoked => Ok(true),
                    _ => Ok(false),
                }
            })
            .collect::<Result<Vec<bool>, ServiceError>>()?;

        generate_bitstring(states).map_err(ServiceError::from)
    }
}
