use std::sync::Arc;

use uuid::Uuid;

use crate::{
    repository::{error::DataLayerError, organisation_repository::OrganisationRepository},
    service::error::ServiceError,
};

pub(crate) async fn organisation_already_exists(
    repository: &Arc<dyn OrganisationRepository + Send + Sync>,
    id: &Uuid,
) -> Result<bool, ServiceError> {
    let result = repository.get_organisation(id).await;

    match result {
        Ok(_) => Ok(true),
        Err(DataLayerError::RecordNotFound) => Ok(false),
        Err(e) => Err(e.into()),
    }
}
