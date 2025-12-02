use std::collections::HashSet;
use std::hash::Hash;

use super::DidDeactivationError;
use crate::model::did::Did;
use crate::provider::did_method::DidMethod;
use crate::provider::did_method::model::{AmountOfKeys, Operation};
use crate::service::did::dto::CreateDidRequestKeysDTO;
use crate::service::error::{BusinessLogicError, ServiceError, ValidationError};

fn count_uniq<T: Eq + Hash>(vec: impl IntoIterator<Item = T>) -> usize {
    vec.into_iter().collect::<HashSet<_>>().len()
}

pub(crate) fn validate_request_amount_of_keys(
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

    if deactivate
        && !did_method
            .get_capabilities()
            .operations
            .contains(&Operation::DEACTIVATE)
    {
        return Err(DidDeactivationError::CannotBeDeactivated {
            method: did.did_method.to_owned(),
        }
        .into());
    }

    if !deactivate {
        return Err(DidDeactivationError::CannotBeReactivated {
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
