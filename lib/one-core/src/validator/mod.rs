use std::ops::{Add, Sub};
use std::sync::Arc;

use shared_types::OrganisationId;
use time::{Duration, OffsetDateTime};

use crate::config::ConfigValidationError;
use crate::config::core_config::{CoreConfig, VerificationProtocolType};
use crate::error::{ContextWithErrorCode, ErrorCode, ErrorCodeMixin};
use crate::model::credential::{Credential, CredentialStateEnum};
use crate::model::proof::{Proof, ProofStateEnum};
use crate::proto::session_provider::SessionProvider;
use crate::provider::credential_formatter::model::DetailCredential;
use crate::provider::verification_protocol::VerificationProtocol;
use crate::provider::verification_protocol::dto::PresentationDefinitionVersion;
use crate::repository::organisation_repository::OrganisationRepository;
use crate::service::error::{BusinessLogicError, ServiceError, ValidationError};

pub(crate) mod ecosystem;
pub(crate) mod key_security;
pub(crate) mod permissions;
pub mod proof_schema;
pub(crate) mod schema;
pub(crate) mod x509;

pub(crate) fn throw_if_org_id_not_matching_session(
    organisation_id: &OrganisationId,
    session_provider: &dyn SessionProvider,
) -> Result<(), ServiceError> {
    let Some(session) = session_provider.session() else {
        return Ok(());
    };
    if session.organisation_id.ok_or(ValidationError::Forbidden)? != *organisation_id {
        return Err(ValidationError::Forbidden.into());
    }
    Ok(())
}

/// Whether the specified organisation is allowed to be the parent of the session organisation.
pub(crate) enum ParentOrg {
    /// The specified organisation must either match exactly or be the parent of the session organisation.
    Allow(Arc<dyn OrganisationRepository>),
    /// The specified organisation must match the session organisation.
    #[expect(unused)]
    // Even if unused, this enum makes the semantics of the parent check more explicit
    Deny,
}

pub(crate) async fn throw_if_org_id_not_matching_session_with_parent_check(
    organisation_id: OrganisationId,
    parent_org_check: ParentOrg,
    session_provider: &dyn SessionProvider,
) -> Result<(), ServiceError> {
    let Some(session) = session_provider.session() else {
        return Ok(());
    };

    let session_org_id = session.organisation_id.ok_or(ValidationError::Forbidden)?;
    if session_org_id == organisation_id {
        return Ok(());
    }

    if let ParentOrg::Allow(organisations_repository) = parent_org_check {
        let session_org = organisations_repository
            .get_organisation(&session_org_id)
            .await
            .error_while("fetching organisation")?;
        if session_org
            .parent_organisation
            .is_some_and(|parent_organisation| parent_organisation.id() == organisation_id)
        {
            return Ok(());
        }
    }
    Err(ValidationError::Forbidden.into())
}

pub(crate) async fn throw_if_credential_schema_not_in_session_org(
    credential: &Credential,
    session_provider: &dyn SessionProvider,
) -> Result<(), ServiceError> {
    let schema = credential.common().schema.as_ref().await?;
    throw_if_org_id_not_matching_session(schema.organisation.id_ref(), session_provider)
}

pub(crate) fn throw_if_credential_state_not_eq(
    credential: &Credential,
    state: CredentialStateEnum,
) -> Result<(), ServiceError> {
    let current_state = credential.common().state;
    if current_state != state {
        return Err(BusinessLogicError::InvalidCredentialState {
            state: current_state.to_owned(),
        }
        .into());
    }
    Ok(())
}

pub(crate) fn throw_if_proof_state_not_in(
    proof: &Proof,
    valid_states: &[ProofStateEnum],
) -> Result<(), ServiceError> {
    if !valid_states.contains(&proof.state) {
        return Err(BusinessLogicError::InvalidProofState { state: proof.state }.into());
    }
    Ok(())
}

pub(crate) fn throw_if_proof_state_not_eq(
    proof: &Proof,
    state: ProofStateEnum,
) -> Result<(), ServiceError> {
    if proof.state != state {
        return Err(BusinessLogicError::InvalidProofState { state: proof.state }.into());
    }
    Ok(())
}

pub(crate) fn throw_if_endpoint_version_incompatible(
    verification_protocol: &dyn VerificationProtocol,
    endpoint_version: &PresentationDefinitionVersion,
) -> Result<(), ServiceError> {
    if !verification_protocol
        .get_capabilities()
        .supported_presentation_definition
        .contains(endpoint_version)
    {
        return Err(BusinessLogicError::IncompatiblePresentationEndpoint.into());
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum TimestampValidationError {
    #[error(
        "Issued in future: issued at {issued_at}, latest accepted {latest_accepted} (now {now}, leeway {leeway})"
    )]
    IssuedInFuture {
        issued_at: OffsetDateTime,
        latest_accepted: OffsetDateTime,
        now: OffsetDateTime,
        leeway: Duration,
    },
    #[error(
        "Not before in future: not before {not_before}, latest accepted {latest_accepted} (now {now}, leeway {leeway})"
    )]
    NotBeforeInFuture {
        not_before: OffsetDateTime,
        latest_accepted: OffsetDateTime,
        now: OffsetDateTime,
        leeway: Duration,
    },
    #[error(
        "Expired: expired at {expires_at}, earliest accepted {earliest_accepted} (now {now}, leeway {leeway})"
    )]
    Expired {
        expires_at: OffsetDateTime,
        earliest_accepted: OffsetDateTime,
        now: OffsetDateTime,
        leeway: Duration,
    },
}

impl ErrorCodeMixin for TimestampValidationError {
    fn error_code(&self) -> ErrorCode {
        ErrorCode::BR_0521
    }
}

pub(crate) fn validate_issuance_time(
    issued_at: &Option<OffsetDateTime>,
    leeway: Duration,
) -> Result<(), TimestampValidationError> {
    let Some(issued_at) = *issued_at else {
        return Ok(());
    };

    let now = crate::clock::now_utc();
    let latest_accepted = now.add(leeway);
    if issued_at > latest_accepted {
        return Err(TimestampValidationError::IssuedInFuture {
            issued_at,
            latest_accepted,
            now,
            leeway,
        });
    }
    Ok(())
}

pub fn validate_not_before_time(
    not_before: &Option<OffsetDateTime>,
    leeway: Duration,
) -> Result<(), TimestampValidationError> {
    let Some(not_before) = *not_before else {
        return Ok(());
    };

    let now = crate::clock::now_utc();
    let latest_accepted = now.add(leeway);
    if not_before > latest_accepted {
        return Err(TimestampValidationError::NotBeforeInFuture {
            not_before,
            latest_accepted,
            now,
            leeway,
        });
    }
    Ok(())
}

pub fn validate_expiration_time(
    expires_at: &Option<OffsetDateTime>,
    leeway: Duration,
) -> Result<(), TimestampValidationError> {
    let Some(expires_at) = *expires_at else {
        return Ok(());
    };

    let now = crate::clock::now_utc();
    let earliest_accepted = now.sub(leeway);
    if expires_at < earliest_accepted {
        return Err(TimestampValidationError::Expired {
            expires_at,
            earliest_accepted,
            now,
            leeway,
        });
    }
    Ok(())
}

/// Validates the validity period of a received credential
pub(crate) fn validate_credential_validity(
    credential: &DetailCredential,
    leeway: Duration,
) -> Result<(), TimestampValidationError> {
    validate_issuance_time(&credential.issuance_date, leeway)?;
    validate_not_before_time(&credential.valid_from, leeway)?;
    validate_not_before_time(&credential.invalid_before, leeway)?;
    validate_expiration_time(&credential.valid_until, leeway)
}

pub fn validate_audience(audience: &[String], expected: &str) -> Result<(), ServiceError> {
    let contains = audience.iter().any(|s| s.as_str() == expected);
    if !contains {
        return Err(ServiceError::ValidationError(format!(
            "Invalid audience. Expected: {expected}, actual: {audience:?}",
        )));
    }
    Ok(())
}

pub(crate) fn validate_verification_protocol_config_exists(
    config: &CoreConfig,
    protocols: &[VerificationProtocolType],
) -> Result<(), ConfigValidationError> {
    if !config
        .verification_protocol
        .iter()
        .any(|(_, v)| protocols.contains(&v.r#type))
    {
        Err(ConfigValidationError::EntryNotFound(
            "No exchange method with type OPENID4VC".to_string(),
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use assert2::let_assert;
    use similar_asserts::assert_eq;

    use super::*;
    use crate::provider::credential_formatter::model::IdentifierDetails;

    #[test]
    fn test_validate_issuance_time() {
        let leeway = Duration::seconds(5);

        let correctly_issued = validate_issuance_time(&Some(crate::clock::now_utc()), leeway);
        assert!(correctly_issued.is_ok());

        let now_plus_minute = crate::clock::now_utc().add(Duration::seconds(60));
        let issued_in_future = validate_issuance_time(&Some(now_plus_minute), leeway);
        assert!(issued_in_future.is_err());

        let missing_date = validate_issuance_time(&None, leeway);
        assert!(missing_date.is_ok());
    }

    #[test]
    fn test_validate_expiration_time() {
        let leeway = Duration::seconds(5);

        let correctly_issued = validate_expiration_time(&Some(crate::clock::now_utc()), leeway);
        assert!(correctly_issued.is_ok());

        let now_minus_minute = crate::clock::now_utc().sub(Duration::seconds(60));
        let issued_in_future = validate_expiration_time(&Some(now_minus_minute), leeway);
        assert!(issued_in_future.is_err());

        let missing_date = validate_expiration_time(&None, leeway);
        assert!(missing_date.is_ok());
    }

    #[test]
    fn test_validate_not_before_time() {
        let leeway = Duration::seconds(5);

        let correct_not_before = validate_not_before_time(&Some(crate::clock::now_utc()), leeway);
        assert!(correct_not_before.is_ok());

        let now_plus_minute = crate::clock::now_utc().add(Duration::seconds(60));
        let not_before_in_future = validate_not_before_time(&Some(now_plus_minute), leeway);
        assert!(not_before_in_future.is_err());

        let missing_date = validate_not_before_time(&None, leeway);
        assert!(missing_date.is_ok());
    }

    #[test]
    fn test_timestamp_validation_error_details() {
        let leeway = Duration::seconds(5);
        let in_future = crate::clock::now_utc().add(Duration::seconds(60));
        let in_past = crate::clock::now_utc().sub(Duration::seconds(60));

        let err = validate_issuance_time(&Some(in_future), leeway).unwrap_err();
        assert_eq!(err.error_code(), ErrorCode::BR_0521);
        let_assert!(
            TimestampValidationError::IssuedInFuture {
                issued_at,
                latest_accepted,
                now,
                leeway: reported_leeway,
            } = &err
        );
        assert_eq!(*issued_at, in_future);
        assert_eq!(*latest_accepted, *now + leeway);
        assert_eq!(*reported_leeway, leeway);
        assert!(err.to_string().contains(&in_future.to_string()));

        let err = validate_not_before_time(&Some(in_future), leeway).unwrap_err();
        let_assert!(
            TimestampValidationError::NotBeforeInFuture {
                not_before,
                latest_accepted,
                now,
                ..
            } = err
        );
        assert_eq!(not_before, in_future);
        assert_eq!(latest_accepted, now + leeway);

        let err = validate_expiration_time(&Some(in_past), leeway).unwrap_err();
        let_assert!(
            TimestampValidationError::Expired {
                expires_at,
                earliest_accepted,
                now,
                ..
            } = err
        );
        assert_eq!(expires_at, in_past);
        assert_eq!(earliest_accepted, now - leeway);
    }

    fn credential(update: impl FnOnce(&mut DetailCredential)) -> DetailCredential {
        let now = crate::clock::now_utc();
        let mut credential = DetailCredential {
            issuance_date: Some(now),
            valid_from: Some(now),
            valid_until: Some(now + Duration::days(1)),
            update_at: None,
            invalid_before: Some(now),
            issuer: IdentifierDetails::Did("did:issuer:123".parse().unwrap()),
            subject: None,
            claims: Default::default(),
            status: vec![],
        };
        update(&mut credential);
        credential
    }

    #[test]
    fn test_validate_credential_validity() {
        let leeway = Duration::seconds(5);
        let in_future = crate::clock::now_utc() + Duration::minutes(1);
        let in_past = crate::clock::now_utc() - Duration::minutes(1);

        assert!(validate_credential_validity(&credential(|_| {}), leeway).is_ok());

        let_assert!(
            Err(TimestampValidationError::IssuedInFuture { .. }) = validate_credential_validity(
                &credential(|c| c.issuance_date = Some(in_future)),
                leeway
            )
        );
        let_assert!(
            Err(TimestampValidationError::NotBeforeInFuture { not_before, .. }) =
                validate_credential_validity(
                    &credential(|c| c.valid_from = Some(in_future)),
                    leeway
                )
        );
        assert_eq!(not_before, in_future);
        let_assert!(
            Err(TimestampValidationError::NotBeforeInFuture { not_before, .. }) =
                validate_credential_validity(
                    &credential(|c| c.invalid_before = Some(in_future)),
                    leeway
                )
        );
        assert_eq!(not_before, in_future);
        let_assert!(
            Err(TimestampValidationError::Expired { expires_at, .. }) =
                validate_credential_validity(
                    &credential(|c| c.valid_until = Some(in_past)),
                    leeway
                )
        );
        assert_eq!(expires_at, in_past);
    }
}
