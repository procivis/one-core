use thiserror::Error;

pub mod config_provider;
pub mod data_structure;
pub mod validator;

mod json_config_provider;
mod process_config_object;
mod validate_error_param_presence;
mod validate_types;
mod yaml_config_provider;

#[derive(Debug, Error)]
pub enum ConfigParseError {
    #[error("JSON error: `{0}`")]
    JsonError(#[from] serde_json::Error),
    #[error("Invalid type `{1}` on field `{0}`")]
    InvalidType(String, String),
    #[error("Missing error key in params of `{0}`")]
    MissingErrorMessage(String),
    #[error("Missing parameter `{0}` in params of `{1}`")]
    MissingParameter(String, String),
}
