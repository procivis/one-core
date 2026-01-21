use shared_types::RevocationMethodId;
use strum::Display;

use self::validator::datatype::DatatypeValidationError;
use crate::provider::data_type::model::ValueType;

pub mod validator;

pub mod core_config;

#[cfg(test)]
#[cfg(all(
    feature = "config_yaml",
    feature = "config_json",
    feature = "config_env"
))]
mod test;

#[derive(thiserror::Error, Debug)]
pub enum ConfigError {
    #[error(transparent)]
    Parsing(#[from] ConfigParsingError),
    #[error(transparent)]
    Validation(#[from] ConfigValidationError),
}

#[derive(thiserror::Error, Debug)]
pub enum ConfigParsingError {
    #[error("file error: {0}")]
    File(#[from] std::io::Error),
    #[error("Parsing error: {0}")]
    GeneralParsingError(String),
}

#[derive(Debug)]
pub struct IncompatibleProviderRef {
    pub provider: String,
    pub provider_ref: ProviderReference,
    pub compatible_types: Vec<String>,
}

#[derive(Debug, Display)]
pub enum ProviderReference {
    #[strum(to_string = "revocation method `{0}`")]
    RevocationMethod(RevocationMethodId),
}

#[derive(thiserror::Error, Debug)]
pub enum ConfigValidationError {
    #[error("configuration entry `{0}` is disabled in config")]
    EntryDisabled(String),
    #[error("configuration entry `{0}` is not found in config")]
    EntryNotFound(String),
    #[error("configuration for type `{0}` not found")]
    TypeNotFound(String),
    #[error("fields deserialization for entry: {key}. error: {source}")]
    FieldsDeserialization {
        key: String,
        source: serde_json::Error,
    },
    #[error("entity has invalid type, expected: `{0}`, actual: `{1}`")]
    InvalidType(String, String),
    #[error("provider `{}` is not compatible with {}. Compatible provider types: {:?}", .0.provider, .0.provider_ref, .0.compatible_types)]
    IncompatibleReferencedProvider(Box<IncompatibleProviderRef>),
    #[error("Datatype validation error: `{0}`")]
    DatatypeValidation(#[from] DatatypeValidationError),
    #[error("configuration entry `{key}` specifies URL scheme `{scheme}` that is already in use")]
    DuplicateUrlScheme { key: String, scheme: String },
    #[error("Missing CA certificate for the client id scheme x509_san_dns")]
    MissingX509CaCertificate,
    #[error("Multiple fallback data types configured for value type: `{value_type}`")]
    MultipleFallbackProviders { value_type: ValueType },
}

impl ConfigValidationError {
    pub fn incompatible_provider_ref<T: ToString>(
        provider: String,
        provider_ref: ProviderReference,
        compatible_types: &[T],
    ) -> Self {
        Self::IncompatibleReferencedProvider(Box::new(IncompatibleProviderRef {
            provider,
            provider_ref,
            compatible_types: compatible_types.iter().map(|t| t.to_string()).collect(),
        }))
    }
}
