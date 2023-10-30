use crate::model::credential::{Credential, CredentialStateEnum};
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
