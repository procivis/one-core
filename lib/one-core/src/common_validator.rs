use std::ops::{Add, Sub};
use std::time::Duration;

use time::OffsetDateTime;

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
pub(crate) fn validate_issuance_time(
    issued_at: Option<OffsetDateTime>,
    leeway: u64,
) -> Result<(), ServiceError> {
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
    expires_at: Option<OffsetDateTime>,
    leeway: u64,
) -> Result<(), ServiceError> {
    let now = OffsetDateTime::now_utc();
    let expires = expires_at.ok_or(ServiceError::ValidationError(
        "Missing expiration date".to_owned(),
    ))?;

    if expires < now.sub(Duration::from_secs(leeway)) {
        return Err(ServiceError::ValidationError("Expired".to_owned()));
    }

    Ok(())
}
