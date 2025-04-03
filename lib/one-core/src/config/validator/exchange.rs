use serde::Serialize;

use crate::config::core_config::{ConfigBlock, DidConfig, DidType};
use crate::service::error::{BusinessLogicError, ValidationError};

pub fn validate_exchange_type<T: Serialize + Clone>(
    exchange: &str,
    config: &ConfigBlock<T>,
) -> Result<(), ValidationError> {
    config.get_if_enabled(exchange).map(|_| ()).map_err(|err| {
        ValidationError::InvalidExchangeType {
            value: exchange.into(),
            source: err.into(),
        }
    })
}

pub(crate) fn validate_protocol_did_compatibility(
    capabilities: &[DidType],
    did_method: &str,
    config: &DidConfig,
) -> Result<(), BusinessLogicError> {
    let did_method_type = config
        .get_fields(did_method)
        .map_err(|_| BusinessLogicError::InvalidDidMethod {
            method: did_method.to_string(),
        })?
        .r#type;
    if !capabilities.contains(&did_method_type) {
        return Err(BusinessLogicError::InvalidDidMethod {
            method: did_method.to_string(),
        });
    }
    Ok(())
}
