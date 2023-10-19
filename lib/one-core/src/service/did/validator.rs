use std::collections::HashSet;

use crate::{
    model::key::KeyId,
    service::{did::dto::CreateDidRequestKeysDTO, error::ServiceError},
};

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
