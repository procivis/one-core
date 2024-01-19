use std::collections::HashSet;

use crate::model::did::Did;
use crate::provider::did_method::DidMethod;
use crate::service::error::BusinessLogicError;
use crate::{
    model::key::KeyId,
    service::{did::dto::CreateDidRequestKeysDTO, error::ServiceError},
};

use super::DidDeactivationError;

pub(super) fn validate_request_only_one_key_of_each_type(
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

pub(super) fn validate_deactivation_request(
    did: &Did,
    did_method: &dyn DidMethod,
    deactivate: bool,
) -> Result<(), BusinessLogicError> {
    if did.did_type.is_remote() {
        return Err(DidDeactivationError::RemoteDid.into());
    }

    if !did_method.can_be_deactivated() {
        return Err(DidDeactivationError::CannotBeDeactivated {
            method: did.did_method.to_owned(),
        }
        .into());
    }

    if deactivate == did.deactivated {
        return Err(DidDeactivationError::DeactivatedSameValue {
            value: did.deactivated,
            method: did.did_method.to_owned(),
        }
        .into());
    }

    Ok(())
}
