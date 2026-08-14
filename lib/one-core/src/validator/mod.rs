use std::ops::{Add, Sub};
use std::sync::Arc;

use shared_types::OrganisationId;
use time::{Duration, OffsetDateTime};

use crate::config::ConfigValidationError;
use crate::config::core_config::{CoreConfig, VerificationProtocolType};
use crate::error::ContextWithErrorCode;
use crate::model::credential::{Credential, CredentialStateEnum};
use crate::model::proof::{Proof, ProofStateEnum};
use crate::proto::session_provider::SessionProvider;
use crate::provider::verification_protocol::VerificationProtocol;
use crate::provider::verification_protocol::dto::PresentationDefinitionVersion;
use crate::repository::organisation_repository::OrganisationRepository;
use crate::service::error::{BusinessLogicError, ServiceError, ValidationError};

pub(crate) mod ecosystem;
pub(crate) mod key_security;
pub(crate) mod permissions;
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
    let schema = credential.schema.as_ref().await?;
    throw_if_org_id_not_matching_session(schema.organisation.id_ref(), session_provider)
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

pub(crate) fn validate_issuance_time(
    issued_at: &Option<OffsetDateTime>,
    leeway: Duration,
) -> Result<(), ServiceError> {
    let Some(issued_at) = issued_at else {
        return Ok(());
    };

    let now = crate::clock::now_utc();
    if *issued_at > now.add(leeway) {
        return Err(ServiceError::ValidationError("Issued in future".to_owned()));
    }
    Ok(())
}

pub fn validate_not_before_time(
    not_before: &Option<OffsetDateTime>,
    leeway: Duration,
) -> Result<(), ServiceError> {
    let Some(not_before) = not_before else {
        return Ok(());
    };

    let now = crate::clock::now_utc();
    if *not_before > now.add(leeway) {
        return Err(ServiceError::ValidationError(
            "Not before in future".to_owned(),
        ));
    }
    Ok(())
}

pub fn validate_expiration_time(
    expires_at: &Option<OffsetDateTime>,
    leeway: Duration,
) -> Result<(), ServiceError> {
    let Some(expires_at) = expires_at else {
        return Ok(());
    };

    let now = crate::clock::now_utc();
    if *expires_at < now.sub(leeway) {
        return Err(ServiceError::ValidationError("Expired".to_owned()));
    }
    Ok(())
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

    use super::*;

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
}
