use std::ops::{Add, Sub};
use std::time::Duration;
use time::OffsetDateTime;

use crate::model::credential::{Credential, CredentialState, CredentialStateEnum};
use crate::model::proof::{Proof, ProofStateEnum};
use crate::service::error::{BusinessLogicError, ServiceError};

pub(crate) fn throw_if_latest_credential_state_eq(
    credential: &Credential,
    state: CredentialStateEnum,
) -> Result<(), ServiceError> {
    let latest_state = &get_latest_state(credential)?.state;
    if latest_state == &state {
        return Err(BusinessLogicError::InvalidCredentialState {
            state: latest_state.to_owned(),
        }
        .into());
    }
    Ok(())
}

pub(crate) fn throw_if_latest_credential_state_not_eq(
    credential: &Credential,
    state: CredentialStateEnum,
) -> Result<(), ServiceError> {
    let latest_state = &get_latest_state(credential)?.state;
    if latest_state != &state {
        return Err(BusinessLogicError::InvalidCredentialState {
            state: latest_state.to_owned(),
        }
        .into());
    }
    Ok(())
}

pub(crate) fn throw_if_state_not_in(
    state: &CredentialStateEnum,
    valid_states: &[CredentialStateEnum],
) -> Result<(), ServiceError> {
    if !valid_states.contains(state) {
        return Err(BusinessLogicError::InvalidCredentialState {
            state: state.to_owned(),
        }
        .into());
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
        .first()
        .ok_or(ServiceError::MappingError("state is missing".to_string()))?
        .to_owned();

    if latest_state.state != state {
        return Err(BusinessLogicError::InvalidProofState {
            state: latest_state.state,
        }
        .into());
    }
    Ok(())
}

pub(crate) fn validate_issuance_time(
    issued_at: &Option<OffsetDateTime>,
    leeway: u64,
) -> Result<(), ServiceError> {
    if issued_at.is_none() {
        return Ok(());
    }

    let now = OffsetDateTime::now_utc();
    let issued = issued_at.ok_or(ServiceError::ValidationError(
        "Missing issuance date".to_owned(),
    ))?;

    if issued > now.add(Duration::from_secs(leeway)) {
        return Err(ServiceError::ValidationError("Issued in future".to_owned()));
    }

    Ok(())
}

pub(crate) fn validate_expiration_time(
    expires_at: &Option<OffsetDateTime>,
    leeway: u64,
) -> Result<(), ServiceError> {
    if expires_at.is_none() {
        return Ok(());
    }

    let now = OffsetDateTime::now_utc();
    let expires = expires_at.ok_or(ServiceError::ValidationError(
        "Missing expiration date".to_owned(),
    ))?;

    if expires < now.sub(Duration::from_secs(leeway)) {
        return Err(ServiceError::ValidationError("Expired".to_owned()));
    }

    Ok(())
}

pub(crate) fn get_latest_state(credential: &Credential) -> Result<&CredentialState, ServiceError> {
    credential
        .state
        .as_ref()
        .ok_or(ServiceError::MappingError("state is None".to_string()))?
        .first()
        .ok_or(ServiceError::MappingError("state is missing".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_issuance_time() {
        let leeway = 5u64;

        let correctly_issued = validate_issuance_time(&Some(OffsetDateTime::now_utc()), leeway);
        assert!(correctly_issued.is_ok());

        let now_plus_minute = OffsetDateTime::now_utc().add(Duration::from_secs(60));
        let issued_in_future = validate_issuance_time(&Some(now_plus_minute), leeway);
        assert!(issued_in_future.is_err());

        let missing_date = validate_issuance_time(&None, leeway);
        assert!(missing_date.is_ok());
    }

    #[test]
    fn test_validate_expiration_time() {
        let leeway = 5u64;

        let correctly_issued = validate_expiration_time(&Some(OffsetDateTime::now_utc()), leeway);
        assert!(correctly_issued.is_ok());

        let now_minus_minute = OffsetDateTime::now_utc().sub(Duration::from_secs(60));
        let issued_in_future = validate_expiration_time(&Some(now_minus_minute), leeway);
        assert!(issued_in_future.is_err());

        let missing_date = validate_expiration_time(&None, leeway);
        assert!(missing_date.is_ok());
    }
}
