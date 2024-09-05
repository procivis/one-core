use std::collections::HashSet;
use std::hash::Hash;

use one_providers::did::model::AmountOfKeys;
use one_providers::did::DidMethod;

use super::DidDeactivationError;
use crate::model::did::Did;
use crate::service::did::dto::CreateDidRequestKeysDTO;
use crate::service::error::{BusinessLogicError, ServiceError, ValidationError};

fn count_uniq<T: Eq + Hash>(vec: impl IntoIterator<Item = T>) -> usize {
    vec.into_iter().collect::<HashSet<_>>().len()
}

pub(super) fn validate_request_amount_of_keys(
    did_method: &dyn DidMethod,
    keys: CreateDidRequestKeysDTO,
) -> Result<(), ServiceError> {
    let keys = AmountOfKeys {
        global: count_uniq(
            keys.authentication
                .iter()
                .chain(&keys.assertion_method)
                .chain(&keys.key_agreement)
                .chain(&keys.capability_invocation)
                .chain(&keys.capability_delegation),
        ),
        authentication: count_uniq(&keys.authentication),
        assertion_method: count_uniq(&keys.assertion_method),
        key_agreement: count_uniq(&keys.key_agreement),
        capability_invocation: count_uniq(&keys.capability_invocation),
        capability_delegation: count_uniq(&keys.capability_delegation),
    };

    if !did_method.validate_keys(keys) {
        Err(ServiceError::Validation(
            ValidationError::DidInvalidKeyNumber,
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
