use serde::Serialize;

use crate::config::core_config::{
    ConfigBlock, DidConfig, DidType, IdentifierConfig, IdentifierType,
};
use crate::model::identifier::Identifier;
use crate::service::error::{BusinessLogicError, ServiceError, ValidationError};

pub fn validate_identifier(
    verifier_identifier: Identifier,
    expected_types: &[IdentifierType],
    config: &IdentifierConfig,
) -> Result<(), ServiceError> {
    let requested_identifier_type = &verifier_identifier.r#type.into();
    config
        .get(requested_identifier_type)
        .filter(|cfg| cfg.enabled.unwrap_or_default())
        .map(|_| ())
        .ok_or(ValidationError::IdentifierTypeDisabled(
            requested_identifier_type.to_string(),
        ))?;
    if !expected_types.contains(requested_identifier_type) {
        return Err(ServiceError::BusinessLogic(
            BusinessLogicError::IncompatibleProofVerificationIdentifier,
        ));
    }
    Ok(())
}

pub fn validate_protocol_type<T: Serialize + Clone>(
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
