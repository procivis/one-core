use shared_types::IdentifierId;

use crate::model::organisation::Organisation;
use crate::service::error::ServiceError;
use crate::service::ssi_wallet_provider::error::WalletProviderError;

pub(crate) fn validate_audience(
    audience: &[String],
    expected: Option<&str>,
) -> Result<(), ServiceError> {
    let Some(expected) = expected else {
        return Ok(());
    };

    let contains = audience.iter().any(|s| s.as_str() == expected);
    if !contains {
        return Err(ServiceError::ValidationError(format!(
            "{expected} is not intended audience",
        )));
    }
    Ok(())
}

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
