use shared_types::IdentifierId;

use super::dto::WalletProviderParams;
use super::error::WalletProviderError;
use crate::config::ConfigValidationError;
use crate::config::core_config::{CoreConfig, RevocationType};
use crate::model::organisation::Organisation;

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
    } else if params.wallet_unit_attestation.lifetime.expiration_time > 86400 {
        tracing::warn!(
            "WUA without revocation but expiration longer than one day: {}",
            params.wallet_unit_attestation.lifetime.expiration_time
        );
    }

    Ok(())
}
