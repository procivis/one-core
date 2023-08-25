use std::sync::Arc;

use thiserror::Error;

use crate::{config::data_structure::CoreConfig, OneCore};

pub mod config_provider;
pub mod data_structure;
pub mod json_config_provider;
pub mod validator;
pub mod yaml_config_provider;

mod process_config_object;
mod validate_error_param_presence;
mod validate_types;

#[derive(Debug, Error)]
pub enum ConfigParseError {
    #[error("JSON error: `{0}`")]
    JsonError(#[from] serde_json::Error),
    #[error("Invalid type `{1}` on field `{0}`")]
    InvalidType(String, String),
    #[error("Missing error key in params of `{0}`")]
    MissingErrorMessage(String),
}

impl OneCore {
    pub async fn get_config(&self) -> Arc<CoreConfig> {
        self.config.clone()
    }
}
