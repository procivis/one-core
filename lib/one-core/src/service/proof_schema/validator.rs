use super::dto::{CreateProofSchemaRequestDTO, ProofInputSchemaRequestDTO};
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential_schema::CredentialSchema;
use crate::service::error::{BusinessLogicError, ValidationError};
use crate::service::proof_schema::mapper::create_unique_name_check_request;
use crate::{
    repository::proof_schema_repository::ProofSchemaRepository, service::error::ServiceError,
};
use itertools::Itertools;
use shared_types::OrganisationId;
use std::collections::HashSet;
use std::sync::Arc;

pub async fn proof_schema_name_already_exists(
    repository: &Arc<dyn ProofSchemaRepository>,
    name: &str,
    organisation_id: OrganisationId,
) -> Result<(), ServiceError> {
    let proof_schemas = repository
        .get_proof_schema_list(create_unique_name_check_request(name, organisation_id)?)
        .await?;
    if proof_schemas.total_items > 0 {
        return Err(BusinessLogicError::ProofSchemaAlreadyExists.into());
    }
    Ok(())
}

pub fn validate_create_request(
    request: &CreateProofSchemaRequestDTO,
) -> Result<(), ValidationError> {
    if request.proof_input_schemas.is_empty() {
        return Err(ValidationError::ProofSchemaMissingClaims);
    }

    let mut uniq = HashSet::new();

    for proof_input in &request.proof_input_schemas {
        if proof_input.claim_schemas.is_empty() {
            return Err(ValidationError::ProofSchemaMissingClaims);
        }

        // at least one claim must be required
        if !proof_input.claim_schemas.iter().any(|claim| claim.required) {
            return Err(ValidationError::ProofSchemaNoRequiredClaim);
        }

        if !proof_input
            .claim_schemas
            .iter()
            .all(|claim| uniq.insert(claim.id))
        {
            return Err(ValidationError::ProofSchemaDuplicitClaim);
        }
    }

    Ok(())
}

pub fn extract_claims_from_credential_schema(
    proof_input: &[ProofInputSchemaRequestDTO],
    schemas: &[CredentialSchema],
) -> Result<Vec<ClaimSchema>, ServiceError> {
    proof_input
        .iter()
        .map(|proof_input| {
            let schema = schemas
                .iter()
                .find(|schema| schema.id == proof_input.credential_schema_id)
                .ok_or_else(|| ServiceError::MappingError("Missing credential schema".into()))?;

            let claims = schema.claim_schemas.as_ref().ok_or_else(|| {
                ServiceError::MappingError("Missing credential schema claims".into())
            })?;

            Ok::<_, ServiceError>(proof_input.claim_schemas.iter().map(|proof_claim| {
                claims
                    .iter()
                    .find(|schema_claim| schema_claim.schema.id == proof_claim.id)
                    .map(|schema_claim| schema_claim.schema.clone())
                    .ok_or_else(|| {
                        ServiceError::BusinessLogic(BusinessLogicError::MissingClaimSchema {
                            claim_schema_id: proof_claim.id,
                        })
                    })
            }))
        })
        .flatten_ok()
        .map(|r| r.and_then(std::convert::identity))
        .collect()
}
