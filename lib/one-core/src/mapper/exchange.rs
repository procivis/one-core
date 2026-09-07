use time::Duration;

use crate::config::ConfigValidationError;
use crate::config::core_config::CoreConfig;
use crate::provider::issuance_protocol::model::OpenID4VCRedirectUriParams;
use crate::provider::issuance_protocol::openid4vci_final1_0::model::OpenID4VCIFinal1Params;

fn get_issuance_params(
    config: &CoreConfig,
    exchange: &str,
) -> Result<OpenID4VCIFinal1Params, ConfigValidationError> {
    config
        .issuance_protocol
        .get_fields(exchange)?
        .deserialize::<OpenID4VCIFinal1Params>()
        .map_err(|source| ConfigValidationError::FieldsDeserialization {
            key: exchange.to_string(),
            source,
        })
}

pub(crate) fn get_issuance_param_pre_authorization_expires_in(
    config: &CoreConfig,
    exchange: &str,
) -> Result<Duration, ConfigValidationError> {
    Ok(get_issuance_params(config, exchange)?.pre_authorized_code_expires_in_seconds)
}

pub(crate) fn get_issuance_param_token_expires_in(
    config: &CoreConfig,
    exchange: &str,
) -> Result<Duration, ConfigValidationError> {
    Ok(get_issuance_params(config, exchange)?.token_expires_in_seconds)
}

pub(crate) fn get_issuance_param_refresh_token_expires_in(
    config: &CoreConfig,
    exchange: &str,
) -> Result<Duration, ConfigValidationError> {
    Ok(get_issuance_params(config, exchange)?.refresh_expires_in_seconds)
}

pub(crate) fn get_issuance_param_redirect_uri(
    config: &CoreConfig,
    protocol: &str,
) -> Result<OpenID4VCRedirectUriParams, ConfigValidationError> {
    Ok(get_issuance_params(config, protocol)?.redirect_uri)
}
