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
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("yaml error: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("Parsing error: {0}")]
    GeneralParsingError(String),
}

#[derive(thiserror::Error, Debug)]
pub enum ConfigValidationError {
    #[error("invalid configuration key: {0}")]
    InvalidKey(String),
    #[error("configuration key `{0}` is disabled")]
    KeyDisabled(String),
    #[error("configuration key `{0}` not found")]
    KeyNotFound(String),
    #[error("configuration type `{0}` not found")]
    TypeNotFound(String),
    #[error("fields deserialization for key: {key}. error: {source}")]
    FieldsDeserialization {
        key: String,
        source: serde_json::Error,
    },
    #[error("entity has invalid type, expected: `{0}`, actual: `{1}`")]
    InvalidType(String, String),
    #[error("Datatype validation error: `{0}`")]
    DatatypeValidation(#[from] DatatypeValidationError),
}
