use crate::model::did::DidType;
use crate::model::proof::{Proof, ProofStateEnum};
use crate::service::error::ServiceError;

pub(crate) fn check_holder_did_is_local(proof: &Proof) -> Result<(), ServiceError> {
    if proof
        .holder_did
        .as_ref()
        .ok_or(ServiceError::MappingError("holder did is None".to_string()))?
        .did_type
        != DidType::Local
    {
        return Err(ServiceError::IncorrectParameters);
    }
    Ok(())
}

pub(crate) fn check_last_proof_state(
    proof: &Proof,
    state: ProofStateEnum,
) -> Result<(), ServiceError> {
    let latest_state = proof
        .state
        .to_owned()
        .ok_or(ServiceError::MappingError("state is None".to_string()))?
        .get(0)
        .ok_or(ServiceError::MappingError("state is missing".to_string()))?
        .to_owned();

    if latest_state.state != state {
        return Err(ServiceError::AlreadyExists);
    }
    Ok(())
}
