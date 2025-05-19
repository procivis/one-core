use crate::config::core_config;
use crate::model::did::Did;
use crate::model::identifier::{Identifier, IdentifierType};
use crate::model::key::Key;
use crate::provider::credential_formatter::model::FormatterCapabilities;
use crate::provider::key_algorithm::error::KeyAlgorithmError;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::service::error::{BusinessLogicError, ServiceError};

pub(super) fn validate_holder_capabilities(
    config: &core_config::CoreConfig,
    holder_did: &Did,
    holder_identifier: &Identifier,
    selected_key: &Key,
    capabilities: &FormatterCapabilities,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
) -> Result<(), ServiceError> {
    if !(holder_identifier.r#type == IdentifierType::Did
        && capabilities
            .holder_identifier_types
            .contains(&core_config::IdentifierType::Did))
    {
        return Err(BusinessLogicError::IncompatibleHolderIdentifier.into());
    }

    let did_type = config.did.get_fields(&holder_did.did_method)?.r#type;
    if !capabilities.holder_did_methods.contains(&did_type) {
        return Err(BusinessLogicError::IncompatibleHolderDidMethod.into());
    }

    let key_algorithm = selected_key
        .key_algorithm_type()
        .and_then(|alg| key_algorithm_provider.key_algorithm_from_type(alg))
        .ok_or(KeyAlgorithmError::NotSupported(
            selected_key.key_type.to_owned(),
        ))?;
    if !capabilities
        .holder_key_algorithms
        .contains(&key_algorithm.algorithm_type())
    {
        return Err(BusinessLogicError::IncompatibleHolderKeyAlgorithm.into());
    }

    Ok(())
}
