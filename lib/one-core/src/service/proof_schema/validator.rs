use super::dto::CreateProofSchemaRequestDTO;
use crate::{
    model::organisation::OrganisationId,
    repository::proof_schema_repository::ProofSchemaRepository, service::error::ServiceError,
};
use std::sync::Arc;

pub async fn proof_schema_name_already_exists(
    _repository: &Arc<dyn ProofSchemaRepository + Send + Sync>,
    _name: &str,
    _organisation_id: &OrganisationId,
) -> Result<bool, ServiceError> {
    // FIXME: todo ONE-547
    Ok(false)
}

pub fn validate_create_request(request: &CreateProofSchemaRequestDTO) -> Result<(), ServiceError> {
    if request.claim_schemas.is_empty() {
        return Err(ServiceError::IncorrectParameters);
    }

    // at least one claim must be required
    if !request.claim_schemas.iter().any(|claim| claim.required) {
        return Err(ServiceError::IncorrectParameters);
    }

    Ok(())
}
