use time::Duration;

use crate::config::ConfigValidationError;
use crate::config::core_config::{CoreConfig, IssuanceProtocolType};
use crate::provider::issuance_protocol::openid4vci_draft13::model::OpenID4VCIDraft13Params;
use crate::provider::issuance_protocol::openid4vci_draft13_swiyu::OpenID4VCISwiyuParams;
use crate::provider::issuance_protocol::openid4vci_final1_0::model::OpenID4VCIFinal1Params;
use crate::service::error::ServiceError;

pub(crate) fn get_exchange_param_pre_authorization_expires_in(
    config: &CoreConfig,
    exchange: &str,
) -> Result<Duration, ServiceError> {
    let fields = config.issuance_protocol.get_fields(exchange)?;
    Ok(match fields.r#type {
        IssuanceProtocolType::OpenId4VciDraft13 => {
            let params = fields
                .deserialize::<OpenID4VCIDraft13Params>()
                .map_err(|source| ConfigValidationError::FieldsDeserialization {
                    key: exchange.to_string(),
                    source,
                })?;
            params.pre_authorized_code_expires_in
        }
        IssuanceProtocolType::OpenId4VciDraft13Swiyu => {
            let params = fields
                .deserialize::<OpenID4VCISwiyuParams>()
                .map_err(|source| ConfigValidationError::FieldsDeserialization {
                    key: exchange.to_string(),
                    source,
                })?;
            params.pre_authorized_code_expires_in
        }
        IssuanceProtocolType::OpenId4VciFinal1_0 => {
            let params = fields
                .deserialize::<OpenID4VCIFinal1Params>()
                .map_err(|source| ConfigValidationError::FieldsDeserialization {
                    key: exchange.to_string(),
                    source,
                })?;
            params.pre_authorized_code_expires_in
        }
    })
}

pub(crate) fn get_exchange_param_token_expires_in(
    config: &CoreConfig,
    exchange: &str,
) -> Result<Duration, ServiceError> {
    let fields = config.issuance_protocol.get_fields(exchange)?;
    Ok(match fields.r#type {
        IssuanceProtocolType::OpenId4VciDraft13 => {
            let params = fields
                .deserialize::<OpenID4VCIDraft13Params>()
                .map_err(|source| ConfigValidationError::FieldsDeserialization {
                    key: exchange.to_string(),
                    source,
                })?;
            params.token_expires_in
        }
        IssuanceProtocolType::OpenId4VciDraft13Swiyu => {
            let params = fields
                .deserialize::<OpenID4VCISwiyuParams>()
                .map_err(|source| ConfigValidationError::FieldsDeserialization {
                    key: exchange.to_string(),
                    source,
                })?;
            params.token_expires_in
        }
        IssuanceProtocolType::OpenId4VciFinal1_0 => {
            let params = fields
                .deserialize::<OpenID4VCIFinal1Params>()
                .map_err(|source| ConfigValidationError::FieldsDeserialization {
                    key: exchange.to_string(),
                    source,
                })?;
            params.token_expires_in
        }
    })
}

pub(crate) fn get_exchange_param_refresh_token_expires_in(
    config: &CoreConfig,
    exchange: &str,
) -> Result<Duration, ServiceError> {
    let fields = config.issuance_protocol.get_fields(exchange)?;
    Ok(match fields.r#type {
        IssuanceProtocolType::OpenId4VciDraft13 => {
            let params = fields
                .deserialize::<OpenID4VCIDraft13Params>()
                .map_err(|source| ConfigValidationError::FieldsDeserialization {
                    key: exchange.to_string(),
                    source,
                })?;
            params.refresh_expires_in
        }
        IssuanceProtocolType::OpenId4VciDraft13Swiyu => {
            let params = fields
                .deserialize::<OpenID4VCISwiyuParams>()
                .map_err(|source| ConfigValidationError::FieldsDeserialization {
                    key: exchange.to_string(),
                    source,
                })?;
            params.refresh_expires_in
        }
        IssuanceProtocolType::OpenId4VciFinal1_0 => {
            let params = fields
                .deserialize::<OpenID4VCIFinal1Params>()
                .map_err(|source| ConfigValidationError::FieldsDeserialization {
                    key: exchange.to_string(),
                    source,
                })?;
            params.refresh_expires_in
        }
    })
}
