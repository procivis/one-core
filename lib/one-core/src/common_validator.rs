use std::ops::{Add, Sub};
use std::time::Duration;

use shared_types::OrganisationId;
use time::OffsetDateTime;

use crate::model::credential::{Credential, CredentialStateEnum};
use crate::model::organisation::Organisation;
use crate::model::proof::{Proof, ProofStateEnum};
use crate::proto::session_provider::SessionProvider;
use crate::service::error::{BusinessLogicError, ServiceError, ValidationError};

pub(crate) fn throw_if_credential_state_eq(
    credential: &Credential,
    state: CredentialStateEnum,
) -> Result<(), ServiceError> {
    let current_state = credential.state;
    if current_state == state {
        return Err(BusinessLogicError::InvalidCredentialState {
            state: current_state.to_owned(),
        }
        .into());
    }
    Ok(())
}

pub(crate) fn throw_if_org_not_matching_session(
    organisation_id: &OrganisationId,
    session_provider: &dyn SessionProvider,
) -> Result<(), ServiceError> {
    let Some(session) = session_provider.session() else {
        return Ok(());
    };
    if &session.organisation_id != organisation_id {
        return Err(ValidationError::Forbidden.into());
    }
    Ok(())
}

pub(crate) fn throw_if_org_relation_not_matching_session(
    org_relation: Option<&Organisation>,
    session_provider: &dyn SessionProvider,
) -> Result<(), ServiceError> {
    throw_if_org_not_matching_session(
        &org_relation
            .ok_or(ServiceError::MappingError(
                "organisation is None".to_string(),
            ))?
            .id,
        session_provider,
    )
}

pub(crate) fn throw_if_credential_state_not_eq(
    credential: &Credential,
    state: CredentialStateEnum,
) -> Result<(), ServiceError> {
    let current_state = credential.state;
    if current_state != state {
        return Err(BusinessLogicError::InvalidCredentialState {
            state: current_state.to_owned(),
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
    if proof.state != state {
        return Err(BusinessLogicError::InvalidProofState {
            state: proof.state.clone(),
        }
        .into());
    }
    Ok(())
}

pub(crate) fn validate_issuance_time(
    issued_at: &Option<OffsetDateTime>,
    leeway: u64,
) -> Result<(), ServiceError> {
    let Some(issued_at) = issued_at else {
        return Ok(());
    };

    let now = OffsetDateTime::now_utc();
    if *issued_at > now.add(Duration::from_secs(leeway)) {
        return Err(ServiceError::ValidationError("Issued in future".to_owned()));
    }
    Ok(())
}

pub(crate) fn validate_not_before_time(
    not_before: &Option<OffsetDateTime>,
    leeway: u64,
) -> Result<(), ServiceError> {
    let Some(not_before) = not_before else {
        return Ok(());
    };

    let now = OffsetDateTime::now_utc();
    if *not_before > now.add(Duration::from_secs(leeway)) {
        return Err(ServiceError::ValidationError(
            "Not before in future".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_expiration_time(
    expires_at: &Option<OffsetDateTime>,
    leeway: u64,
) -> Result<(), ServiceError> {
    let Some(expires_at) = expires_at else {
        return Ok(());
    };

    let now = OffsetDateTime::now_utc();
    if *expires_at < now.sub(Duration::from_secs(leeway)) {
        return Err(ServiceError::ValidationError("Expired".to_owned()));
    }
    Ok(())
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

    #[test]
    fn test_validate_not_before_time() {
        let leeway = 5u64;

        let correct_not_before = validate_not_before_time(&Some(OffsetDateTime::now_utc()), leeway);
        assert!(correct_not_before.is_ok());

        let now_plus_minute = OffsetDateTime::now_utc().add(Duration::from_secs(60));
        let not_before_in_future = validate_not_before_time(&Some(now_plus_minute), leeway);
        assert!(not_before_in_future.is_err());

        let missing_date = validate_not_before_time(&None, leeway);
        assert!(missing_date.is_ok());
    }
}
