use serde::Serialize;
use shared_types::DidMethodId;

use crate::config::core_config::{
    ConfigBlock, ConfigExt, ConfigKey, DidConfig, DidType, IdentifierConfig, IdentifierType,
};
use crate::error::ContextWithErrorCode;
use crate::model::identifier::Identifier;
use crate::service::error::{BusinessLogicError, ServiceError, ValidationError};

pub fn validate_identifier(
    verifier_identifier: Identifier,
    expected_types: &[IdentifierType],
    config: &IdentifierConfig,
) -> Result<(), ServiceError> {
    let requested_identifier_type = &verifier_identifier.data.r#type().into();
    config
        .get(requested_identifier_type)
        .filter(|cfg| cfg.enabled)
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

pub fn validate_protocol_type<K: ConfigKey, T: Serialize + Clone>(
    exchange: &K,
    config: &ConfigBlock<K, T>,
) -> Result<(), ValidationError> {
    config.get_if_enabled(exchange).map(|_| ()).map_err(|err| {
        ValidationError::InvalidExchangeType {
            value: exchange.to_string(),
            source: err.into(),
        }
    })
}

pub(crate) fn validate_protocol_did_compatibility(
    capabilities: &[DidType],
    did_method: &DidMethodId,
    config: &DidConfig,
) -> Result<(), ServiceError> {
    let did_method_type = config
        .get_fields(did_method)
        .error_while("getting did config")?
        .r#type;
    if !capabilities.contains(&did_method_type) {
        return Err(BusinessLogicError::InvalidDidMethod {
            method: did_method.to_owned(),
        }
        .into());
    }
    Ok(())
}
