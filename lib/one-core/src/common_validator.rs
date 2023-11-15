use crate::model::credential::{Credential, CredentialStateEnum};
use crate::model::did::{Did, DidType};
use crate::model::proof::{Proof, ProofStateEnum};
use crate::service::error::ServiceError;

pub(crate) fn throw_if_latest_credential_state_not_eq(
    credential: &Credential,
    state: CredentialStateEnum,
) -> Result<(), ServiceError> {
    let latest_state = credential
        .state
        .as_ref()
        .ok_or(ServiceError::MappingError("state is None".to_string()))?
        .get(0)
        .ok_or(ServiceError::MappingError("state is missing".to_string()))?;

    if latest_state.state != state {
        return Err(ServiceError::AlreadyExists);
    }
    Ok(())
}

pub(crate) fn throw_if_latest_proof_state_not_eq(
    proof: &Proof,
    state: ProofStateEnum,
) -> Result<(), ServiceError> {
    let latest_state = proof
        .state
        .as_ref()
        .ok_or(ServiceError::MappingError("state is None".to_string()))?
        .get(0)
        .ok_or(ServiceError::MappingError("state is missing".to_string()))?
        .to_owned();

    if latest_state.state != state {
        return Err(ServiceError::AlreadyExists);
    }
    Ok(())
}

pub(crate) fn throw_if_did_type_is_eq(did: &Did, did_type: DidType) -> Result<(), ServiceError> {
    if did.did_type == did_type {
        return Err(ServiceError::IncorrectParameters);
    }
    Ok(())
}
