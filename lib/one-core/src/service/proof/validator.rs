use crate::model::did::DidType;
use crate::model::proof::Proof;
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
