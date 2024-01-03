use super::dto::CreateProofSchemaRequestDTO;
use crate::service::error::BusinessLogicError;
use crate::service::proof_schema::mapper::create_unique_name_check_request;
use crate::{
    model::organisation::OrganisationId,
    repository::proof_schema_repository::ProofSchemaRepository, service::error::ServiceError,
};
use std::collections::HashSet;
use std::sync::Arc;

pub async fn proof_schema_name_already_exists(
    repository: &Arc<dyn ProofSchemaRepository + Send + Sync>,
    name: &str,
    organisation_id: &OrganisationId,
) -> Result<(), ServiceError> {
    let proof_schemas = repository
        .get_proof_schema_list(create_unique_name_check_request(name, organisation_id)?)
        .await
        .map_err(ServiceError::from)?;
    if proof_schemas.total_items > 0 {
        return Err(BusinessLogicError::ProofSchemaAlreadyExists.into());
    }
    Ok(())
}

pub fn validate_create_request(request: &CreateProofSchemaRequestDTO) -> Result<(), ServiceError> {
    if request.claim_schemas.is_empty() {
        return Err(ServiceError::IncorrectParameters);
    }

    // at least one claim must be required
    if !request.claim_schemas.iter().any(|claim| claim.required) {
        return Err(ServiceError::IncorrectParameters);
    }

    // no claim duplicates allowed
    let mut uniq = HashSet::new();
    if !request
        .claim_schemas
        .iter()
        .all(move |claim| uniq.insert(claim.id))
    {
        return Err(ServiceError::IncorrectParameters);
    }

    Ok(())
}
