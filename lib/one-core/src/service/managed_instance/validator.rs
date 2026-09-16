use shared_types::IdentifierId;
use time::Duration;

use super::dto::NoncePayload;
use super::error::ManagedInstanceError;
use crate::error::ContextWithErrorCode;
use crate::model::instance::InstanceRole;
use crate::model::organisation::Organisation;
use crate::proto::jwt::model::DecomposedJwt;
use crate::validator::{
    validate_audience, validate_expiration_time, validate_issuance_time, validate_not_before_time,
};

/// Validates that `provider` is the organisation's configured provider for `role`, dispatching
/// to the wallet- or verifier-specific check since those are tracked as separate org fields.
/// Returns the provider issuer identifier ID
pub(super) fn validate_org_for_role(
    organisation: &Organisation,
    role: InstanceRole,
    provider: &str,
) -> Result<IdentifierId, ManagedInstanceError> {
    match role {
        InstanceRole::Wallet => validate_org_wallet_provider(organisation, provider),
        InstanceRole::Verifier => validate_org_verifier_provider(organisation, provider),
    }
}

pub(crate) fn validate_org_wallet_provider(
    organisation: &Organisation,
    wallet_provider: &str,
) -> Result<IdentifierId, ManagedInstanceError> {
    if organisation.deactivated_at.is_some() {
        return Err(ManagedInstanceError::WalletProviderOrganisationDisabled);
    }
    let Some(org_provider) = &organisation.wallet_provider else {
        return Err(ManagedInstanceError::WalletProviderNotConfigured);
    };
    if org_provider != wallet_provider {
        return Err(ManagedInstanceError::WalletProviderNotConfigured);
    }
    let Some(identifier_id) = organisation.wallet_provider_issuer else {
        return Err(ManagedInstanceError::WalletProviderNotConfigured);
    };
    Ok(identifier_id)
}

pub(crate) fn validate_org_verifier_provider(
    organisation: &Organisation,
    verifier_provider: &str,
) -> Result<IdentifierId, ManagedInstanceError> {
    if organisation.deactivated_at.is_some() {
        return Err(ManagedInstanceError::VerifierProviderOrganisationDisabled);
    }
    let Some(org_provider) = &organisation.verifier_provider else {
        return Err(ManagedInstanceError::VerifierProviderNotConfigured);
    };
    if org_provider != verifier_provider {
        return Err(ManagedInstanceError::VerifierProviderNotConfigured);
    }
    let Some(identifier_id) = organisation.verifier_provider_issuer else {
        return Err(ManagedInstanceError::VerifierProviderNotConfigured);
    };
    Ok(identifier_id)
}

pub(crate) fn validate_proof_payload(
    proof: &DecomposedJwt<NoncePayload>,
    leeway: Duration,
    base_url: Option<&str>,
    nonce: Option<&str>,
) -> Result<(), ManagedInstanceError> {
    validate_issuance_time(&proof.payload.issued_at, leeway)
        .error_while("validating issuance time")?;

    if proof.payload.invalid_before.is_none() {
        return Err(ManagedInstanceError::CouldNotVerifyProof(
            "Missing nbf".to_string(),
        ));
    }
    validate_not_before_time(&proof.payload.invalid_before, leeway)
        .error_while("validating not-before")?;

    if proof.payload.expires_at.is_none() {
        return Err(ManagedInstanceError::CouldNotVerifyProof(
            "Missing ext".to_string(),
        ));
    }
    validate_expiration_time(&proof.payload.expires_at, leeway)
        .error_while("validating expiration")?;

    let Some(audience) = proof.payload.audience.as_ref() else {
        return Err(ManagedInstanceError::CouldNotVerifyProof(
            "Missing aud".to_string(),
        ));
    };
    if let Some(expected_audience) = base_url {
        validate_audience(audience, expected_audience).error_while("validating audience")?;
    }
    if let Some(nonce) = nonce
        && proof
            .payload
            .custom
            .nonce
            .as_ref()
            .is_none_or(|client_nonce| client_nonce != nonce)
    {
        return Err(ManagedInstanceError::CouldNotVerifyProof(
            "Invalid nonce".to_string(),
        ));
    }
    Ok(())
}
