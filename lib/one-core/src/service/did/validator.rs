use std::sync::Arc;

use crate::{
    repository::{did_repository::DidRepository, error::DataLayerError},
    service::error::ServiceError,
};

pub(crate) async fn did_already_exists(
    repository: &Arc<dyn DidRepository + Send + Sync>,
    did_value: &str,
) -> Result<bool, ServiceError> {
    let result = repository.get_did_by_value(&did_value.to_string()).await;

    match result {
        Ok(_) => Ok(true),
        Err(DataLayerError::RecordNotFound) => Ok(false),
        Err(e) => Err(e.into()),
    }
}
