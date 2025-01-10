use self::validator::datatype::DatatypeValidationError;

pub mod validator;

pub mod core_config;

#[cfg(test)]
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
    #[error("Datatype validation error: `{0}`")]
    DatatypeValidation(#[from] DatatypeValidationError),
    #[error("configuration entry `{key}` specifies URL scheme `{scheme}` that is already in use")]
    DuplicateUrlScheme { key: String, scheme: String },
}
