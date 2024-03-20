use shared_types::OrganisationId;

use super::dto::CreateProofSchemaRequestDTO;
use crate::service::error::{BusinessLogicError, ValidationError};
use crate::service::proof_schema::mapper::create_unique_name_check_request;
use crate::{
    repository::proof_schema_repository::ProofSchemaRepository, service::error::ServiceError,
};
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
