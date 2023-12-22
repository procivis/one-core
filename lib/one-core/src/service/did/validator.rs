use std::{collections::HashSet, sync::Arc};

use shared_types::DidValue;

use crate::model::did::Did;
use crate::{
    model::{did::DidRelations, key::KeyId},
    provider::did_method::DidMethodError,
    repository::{did_repository::DidRepository, error::DataLayerError},
    service::{did::dto::CreateDidRequestKeysDTO, error::ServiceError},
};

pub(crate) fn throw_if_did_method_not_eq(did: &Did, method_type: &str) -> Result<(), ServiceError> {
    if did.did_method != method_type {
        return Err(ServiceError::AlreadyExists);
    }
    Ok(())
}

pub(crate) fn throw_if_did_method_deactivated(did: &Did) -> Result<(), ServiceError> {
    if did.deactivated {
        return Err(ServiceError::AlreadyExists);
    }
    Ok(())
}

pub(crate) fn validate_request_only_one_key_of_each_type(
    keys: CreateDidRequestKeysDTO,
) -> Result<(), ServiceError> {
    if keys.authentication.len() > 1
        || keys.assertion.len() > 1
        || keys.key_agreement.len() > 1
        || keys.capability_invocation.len() > 1
        || keys.capability_delegation.len() > 1
    {
        return Err(ServiceError::ValidationError(
            "Each key type must contain maximum one key".to_string(),
        ));
    }

    let key_ids = HashSet::<KeyId>::from_iter(
        [
            keys.authentication,
            keys.assertion,
            keys.key_agreement,
            keys.capability_invocation,
            keys.capability_delegation,
        ]
        .concat(),
    );

    if key_ids.len() > 1 {
        Err(ServiceError::ValidationError(
            "Only one unique key can be used".to_string(),
        ))
    } else {
        Ok(())
    }
}

pub(super) async fn did_already_exists(
    repository: &Arc<dyn DidRepository>,
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
