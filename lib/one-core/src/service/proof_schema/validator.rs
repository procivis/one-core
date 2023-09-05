use std::sync::Arc;

use crate::{
    model::organisation::OrganisationId,
    repository::proof_schema_repository::ProofSchemaRepository, service::error::ServiceError,
};

pub async fn proof_schema_name_already_exists(
    _repository: &Arc<dyn ProofSchemaRepository + Send + Sync>,
    _name: &str,
    _organisation_id: &OrganisationId,
) -> Result<bool, ServiceError> {
    // FIXME: todo ONE-547
    Ok(false)
}
