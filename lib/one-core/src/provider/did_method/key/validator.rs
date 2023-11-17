use std::sync::Arc;

use crate::{
    model::did::DidRelations,
    provider::did_method::{key::mapper::DidKeyType, DidMethodError},
    repository::{did_repository::DidRepository, error::DataLayerError},
};
use shared_types::DidValue;

pub(super) async fn did_already_exists(
    repository: &Arc<dyn DidRepository + Send + Sync>,
    did_value: &DidValue,
) -> Result<bool, DidMethodError> {
    let result = repository
        .get_did_by_value(did_value, &DidRelations::default())
        .await;

    match result {
        Ok(_) => Ok(true),
        Err(DataLayerError::RecordNotFound) => Ok(false),
        Err(e) => Err(DidMethodError::from(e)),
    }
}

pub(super) fn validate_public_key_length(
    public_key: &[u8],
    key_type: DidKeyType,
) -> Result<(), DidMethodError> {
    let is_correct_length = match key_type {
        DidKeyType::Eddsa => public_key.len() == 32,
        DidKeyType::Es256 => public_key.len() == 33,
    };

    if is_correct_length {
        Ok(())
    } else {
        Err(DidMethodError::ResolutionError(
            "Invalid key length".to_string(),
        ))
    }
}
