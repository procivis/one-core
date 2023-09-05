use super::{
    dto::{
        CreateProofSchemaRequestDTO, GetProofSchemaListResponseDTO, GetProofSchemaQueryDTO,
        GetProofSchemaResponseDTO, ProofSchemaId,
    },
    mapper::proof_schema_from_create_request,
    validator::proof_schema_name_already_exists,
    ProofSchemaService,
};
use crate::{
    common_mapper::list_response_into,
    model::{
        claim_schema::{ClaimSchemaId, ClaimSchemaRelations},
        credential_schema::CredentialSchemaRelations,
        organisation::OrganisationRelations,
        proof_schema::{ProofSchemaClaim, ProofSchemaClaimRelations, ProofSchemaRelations},
    },
    service::error::ServiceError,
};
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
                    claim_schemas: Some(ProofSchemaClaimRelations {
                        credential_schema: Some(CredentialSchemaRelations {
                            claim_schema: None,
                            organisation: None,
                        }),
                    }),
                    organisation: Some(OrganisationRelations::default()),
                },
            )
            .await
            .map_err(ServiceError::from)?;
        result.try_into()
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
            .await
            .map_err(ServiceError::from)?;
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
        if proof_schema_name_already_exists(
            &self.proof_schema_repository,
            &request.name,
            &request.organisation_id,
        )
        .await?
        {
            return Err(ServiceError::AlreadyExists);
        }

        let claim_schema_ids: Vec<ClaimSchemaId> =
            request.claim_schemas.iter().map(|item| item.id).collect();

        let claim_schemas = self
            .claim_schema_repository
            .get_claim_schema_list(claim_schema_ids, &ClaimSchemaRelations::default())
            .await?;

        let claim_schemas: Vec<ProofSchemaClaim> = claim_schemas
            .into_iter()
            .zip(&request.claim_schemas)
            .map(|(schema, request)| ProofSchemaClaim {
                schema,
                required: request.required,
                credential_schema: None,
            })
            .collect();

        let organisation = self
            .organisation_repository
            .get_organisation(&request.organisation_id, &OrganisationRelations::default())
            .await?;

        let now = OffsetDateTime::now_utc();
        let proof_schema =
            proof_schema_from_create_request(request, now, claim_schemas, organisation);

        self.proof_schema_repository
            .create_proof_schema(proof_schema)
            .await
            .map_err(ServiceError::from)
    }

    /// Removes a proof schema
    ///
    /// # Arguments
    ///
    /// * `request` - data
    pub async fn delete_proof_schema(&self, id: &ProofSchemaId) -> Result<(), ServiceError> {
        let now = OffsetDateTime::now_utc();
        self.proof_schema_repository
            .delete_proof_schema(id, now)
            .await
            .map_err(ServiceError::from)
    }
}
