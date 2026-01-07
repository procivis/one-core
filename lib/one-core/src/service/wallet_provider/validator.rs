use shared_types::IdentifierId;

use super::dto::{NoncePayload, WalletProviderParams};
use super::error::WalletProviderError;
use crate::config::ConfigValidationError;
use crate::config::core_config::{CoreConfig, RevocationType};
use crate::model::organisation::Organisation;
use crate::proto::jwt::model::DecomposedJwt;
use crate::service::error::ServiceError;
use crate::validator::{
    validate_audience, validate_expiration_time, validate_issuance_time, validate_not_before_time,
};

pub(crate) fn validate_org_wallet_provider(
    organisation: &Organisation,
    wallet_provider: &str,
) -> Result<IdentifierId, WalletProviderError> {
    if organisation.deactivated_at.is_some() {
        return Err(WalletProviderError::WalletProviderOrganisationDisabled);
    }
    let Some(org_provider) = &organisation.wallet_provider else {
        return Err(WalletProviderError::WalletProviderNotConfigured);
    };
    if org_provider != wallet_provider {
        return Err(WalletProviderError::WalletProviderNotConfigured);
    }
    let Some(identifier_id) = organisation.wallet_provider_issuer else {
        return Err(WalletProviderError::WalletProviderNotConfigured);
    };
    Ok(identifier_id)
}

pub(super) fn validate_revocation_method(
    config: &CoreConfig,
    params: &WalletProviderParams,
) -> Result<(), ConfigValidationError> {
    if let Some(revocation_method) = &params.wallet_unit_attestation.revocation_method {
        let revocation_type = config.revocation.get_fields(revocation_method)?.r#type;
        if revocation_type != RevocationType::TokenStatusList {
            return Err(ConfigValidationError::InvalidType(
                RevocationType::TokenStatusList.to_string(),
                revocation_method.to_string(),
            ));
        }
    } else if params.wallet_unit_attestation.expiration_time > 86400 {
        tracing::warn!(
            "WUA without revocation but expiration longer than one day: {}",
            params.wallet_unit_attestation.expiration_time
        );
    }

    Ok(())
}

pub(super) fn validate_proof_payload(
    proof: &DecomposedJwt<NoncePayload>,
    leeway: u64,
    base_url: Option<&str>,
    nonce: Option<&str>,
) -> Result<(), ServiceError> {
    validate_issuance_time(&proof.payload.issued_at, leeway)?;

    if proof.payload.invalid_before.is_none() {
        return Err(WalletProviderError::CouldNotVerifyProof("Missing nbf".to_string()).into());
    }
    validate_not_before_time(&proof.payload.invalid_before, leeway)?;

    if proof.payload.expires_at.is_none() {
        return Err(WalletProviderError::CouldNotVerifyProof("Missing ext".to_string()).into());
    }
    validate_expiration_time(&proof.payload.expires_at, leeway)?;

    let Some(audience) = proof.payload.audience.as_ref() else {
        return Err(WalletProviderError::CouldNotVerifyProof("Missing aud".to_string()).into());
    };
    if let Some(expected_audience) = base_url {
        validate_audience(audience, expected_audience)?;
    }
    if let Some(nonce) = nonce
        && proof
            .payload
            .custom
            .nonce
            .as_ref()
            .is_none_or(|client_nonce| client_nonce != nonce)
    {
        return Err(WalletProviderError::CouldNotVerifyProof("Invalid nonce".to_string()).into());
    }
    Ok(())
}
