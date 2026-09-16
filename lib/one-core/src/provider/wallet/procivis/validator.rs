use time::Duration;

use super::model::Params;
use crate::config::ConfigValidationError;
use crate::config::core_config::{CoreConfig, RevocationType};
use crate::error::ErrorCodeMixinExt;
use crate::model::wallet_instance_attestation::AttestationType;
use crate::provider::wallet::WalletProviderError;

pub(super) fn validate_params(
    config: &CoreConfig,
    params: &Params,
) -> Result<(), ConfigValidationError> {
    validate_revocation_method(config, params, AttestationType::WalletInstanceAttestation)?;
    validate_revocation_method(config, params, AttestationType::KeyAttestation)?;
    Ok(())
}

fn validate_revocation_method(
    config: &CoreConfig,
    params: &Params,
    attestation_type: AttestationType,
) -> Result<(), ConfigValidationError> {
    let revocation_method = match attestation_type {
        AttestationType::WalletInstanceAttestation => {
            &params.wallet_instance_attestation.revocation_method
        }
        AttestationType::KeyAttestation => &params.wallet_key_attestation.revocation_method,
    };
    let expiration_seconds = match attestation_type {
        AttestationType::WalletInstanceAttestation => {
            params.wallet_instance_attestation.expiration_seconds
        }
        AttestationType::KeyAttestation => params.wallet_key_attestation.expiration_seconds,
    };

    let status_period_seconds = match attestation_type {
        AttestationType::WalletInstanceAttestation => {
            params.wallet_instance_attestation.status_period_seconds
        }
        AttestationType::KeyAttestation => params.wallet_key_attestation.status_period_seconds,
    };

    if let Some(revocation_method) = revocation_method {
        let revocation_type = config.revocation.get_fields(revocation_method)?.r#type;
        if revocation_type != RevocationType::TokenStatusList {
            return Err(ConfigValidationError::InvalidType(
                RevocationType::TokenStatusList.to_string(),
                revocation_method.to_string(),
            ));
        }

        // https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts3-wallet-unit-attestation.md#242-wallet-provider-responsibilities
        if status_period_seconds < Duration::days(31) {
            return Err(WalletProviderError::InvalidConfig(format!(
                "Status period too short: {status_period_seconds}"
            ))
            .error_while(format!("validating provider config: `{attestation_type}`"))
            .into());
        }
    } else if expiration_seconds > Duration::days(1) {
        tracing::warn!(
            "WUA without revocation but expiration longer than one day: {expiration_seconds}",
        );
    }

    Ok(())
}
