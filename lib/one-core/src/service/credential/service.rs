use crate::{
    common_mapper::list_response_try_into,
    model::{
        claim::ClaimRelations,
        claim_schema::ClaimSchemaRelations,
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
                CreateCredentialRequestDTO, CredentialResponseDTO, CredentialStateEnum,
                EntityShareResponseDTO, GetCredentialListResponseDTO, GetCredentialQueryDTO,
            },
            mapper::{claims_from_create_request, from_create_request},
            CredentialService,
        },
        error::ServiceError,
    },
};
use std::fmt::Debug;
use time::OffsetDateTime;

pub trait TraceableError {
    fn trace_if_err(self) -> Self;
}

impl<T, E: Debug> TraceableError for Result<T, E> {
    #[track_caller]
    fn trace_if_err(self) -> Self {
        if let Err(error) = &self {
            let caller = std::panic::Location::caller();
            tracing::error!(
                "Traceable error: {}:{} - {:?}",
                caller.file(),
                caller.line(),
                error
            );
        }

        self
    }
}

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
        )
        .trace_if_err()?;

        let claim_schemas = schema
            .claim_schemas
            .to_owned()
            .ok_or(ServiceError::MappingError(
                "claim_schemas is None".to_string(),
            ))?;

        let claims = claims_from_create_request(request.claim_values.clone(), &claim_schemas)?;
        let credential = from_create_request(request, claims, did, schema);

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
    ) -> Result<CredentialResponseDTO, ServiceError> {
        let credential = self
            .credential_repository
            .get_credential(
                credential_id,
                &CredentialRelations {
                    state: Some(CredentialStateRelations {}),
                    claims: Some(ClaimRelations {
                        schema: Some(ClaimSchemaRelations {}),
                    }),
                    schema: Some(CredentialSchemaRelations {
                        claim_schemas: Some(ClaimSchemaRelations::default()),
                        organisation: Some(OrganisationRelations {}),
                    }),
                    issuer_did: Some(DidRelations {}),
                    holder_did: Some(DidRelations {}),
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
                    credential_id: credential_id.to_string(),
                    transport: "PROCIVIS_TEMPORARY".to_string(),
                })
            }

            _ => Err(ServiceError::AlreadyExists),
        }
    }
}
