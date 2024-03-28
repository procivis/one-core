use super::{
    dto::{
        CreateProofSchemaRequestDTO, GetProofSchemaListResponseDTO, GetProofSchemaQueryDTO,
        GetProofSchemaResponseDTO, ProofSchemaId,
    },
    mapper::{
        proof_schema_created_history_event, proof_schema_deleted_history_event,
        proof_schema_from_create_request,
    },
    validator::{proof_schema_name_already_exists, validate_create_request},
    ProofSchemaService,
};
use crate::service::proof_schema::mapper::convert_proof_schema_to_response;
use crate::{
    common_mapper::list_response_into,
    model::{
        claim_schema::ClaimSchemaRelations,
        credential_schema::{
            CredentialSchemaId, CredentialSchemaRelations, GetCredentialSchemaQuery,
        },
        organisation::OrganisationRelations,
        proof_schema::{
            ProofInputSchemaRelations, ProofSchemaClaimRelations, ProofSchemaRelations,
        },
    },
    repository::error::DataLayerError,
    service::error::{BusinessLogicError, EntityNotFoundError, ServiceError},
};
use shared_types::ClaimSchemaId;
use time::OffsetDateTime;

impl ProofSchemaService {
    /// Returns details of a proof schema
    ///
    /// # Arguments
    ///
    /// * `id` - Proof schema uuid
    pub async fn get_proof_schema(
        &self,
        id: &ProofSchemaId,
    ) -> Result<GetProofSchemaResponseDTO, ServiceError> {
        let result = self
            .proof_schema_repository
            .get_proof_schema(
                id,
                &ProofSchemaRelations {
                    organisation: Some(OrganisationRelations::default()),
                    proof_inputs: Some(ProofInputSchemaRelations {
                        claim_schemas: Some(ProofSchemaClaimRelations::default()),
                        credential_schema: Some(CredentialSchemaRelations {
                            claim_schemas: Some(ClaimSchemaRelations::default()),
                            ..Default::default()
                        }),
                    }),
                },
            )
            .await?
            .ok_or(EntityNotFoundError::ProofSchema(*id))?;

        if result.deleted_at.is_some() {
            return Err(EntityNotFoundError::ProofSchema(*id).into());
        }

        convert_proof_schema_to_response(result, &self.config.datatype)
    }

    /// Returns list of proof schemas according to query
    ///
    /// # Arguments
    ///
    /// * `query` - query parameters
    pub async fn get_proof_schema_list(
        &self,
        query: GetProofSchemaQueryDTO,
    ) -> Result<GetProofSchemaListResponseDTO, ServiceError> {
        let result = self
            .proof_schema_repository
            .get_proof_schema_list(query)
            .await?;
        Ok(list_response_into(result))
    }

    /// Creates a new proof schema
    ///
    /// # Arguments
    ///
    /// * `request` - data
    pub async fn create_proof_schema(
        &self,
        request: CreateProofSchemaRequestDTO,
    ) -> Result<ProofSchemaId, ServiceError> {
        validate_create_request(&request)?;

        proof_schema_name_already_exists(
            &self.proof_schema_repository,
            &request.name,
            request.organisation_id,
        )
        .await?;

        let organisation = self
            .organisation_repository
            .get_organisation(&request.organisation_id, &OrganisationRelations::default())
            .await?;

        let Some(organisation) = organisation else {
            return Err(BusinessLogicError::MissingOrganisation(request.organisation_id).into());
        };

        let claim_schema_ids: Vec<ClaimSchemaId> = request
            .proof_input_schemas
            .iter()
            .flat_map(|proof_input_schema| {
                proof_input_schema.claim_schemas.iter().map(|item| item.id)
            })
            .collect();

        let claim_schemas = self
            .claim_schema_repository
            .get_claim_schema_list(claim_schema_ids, &ClaimSchemaRelations::default())
            .await
            .map_err(|error| match error {
                DataLayerError::IncompleteClaimsSchemaList { .. } => {
                    BusinessLogicError::MissingClaimSchemas.into()
                }
                error => ServiceError::from(error),
            })?;

        let credential_schema_ids: Vec<CredentialSchemaId> = request
            .proof_input_schemas
            .iter()
            .map(|proof_input_schema| proof_input_schema.credential_schema_id)
            .collect();

        let expected_credential_schemas = credential_schema_ids.len();
        let credential_schemas = self
            .credential_schema_repository
            .get_credential_schema_list(GetCredentialSchemaQuery {
                page: 0,
                page_size: 1000,
                sort: None,
                sort_direction: None,
                name: None,
                organisation_id: request.organisation_id,
                exact: None,
                ids: Some(credential_schema_ids),
            })
            .await?
            .values;

        if credential_schemas.len() != expected_credential_schemas {
            return Err(BusinessLogicError::MissingCredentialSchema.into());
        }

        let now = OffsetDateTime::now_utc();
        let proof_schema = proof_schema_from_create_request(
            request,
            now,
            claim_schemas,
            credential_schemas,
            organisation.clone(),
        )?;

        let id = self
            .proof_schema_repository
            .create_proof_schema(proof_schema)
            .await?;

        let _ = self
            .history_repository
            .create_history(proof_schema_created_history_event(id, organisation))
            .await;

        Ok(id)
    }

    /// Removes a proof schema
    ///
    /// # Arguments
    ///
    /// * `request` - data
    pub async fn delete_proof_schema(&self, id: &ProofSchemaId) -> Result<(), ServiceError> {
        let proof_schema = self
            .proof_schema_repository
            .get_proof_schema(
                id,
                &ProofSchemaRelations {
                    organisation: Some(OrganisationRelations::default()),
                    ..Default::default()
                },
            )
            .await?
            .ok_or(BusinessLogicError::MissingProofSchema {
                proof_schema_id: *id,
            })?;

        let now = OffsetDateTime::now_utc();
        self.proof_schema_repository
            .delete_proof_schema(id, now)
            .await
            .map_err(|error| match error {
                // proof schema not found or already deleted
                DataLayerError::RecordNotUpdated => BusinessLogicError::MissingProofSchema {
                    proof_schema_id: *id,
                }
                .into(),
                error => ServiceError::from(error),
            })?;

        let _ = self
            .history_repository
            .create_history(proof_schema_deleted_history_event(proof_schema))
            .await;

        Ok(())
    }
}
