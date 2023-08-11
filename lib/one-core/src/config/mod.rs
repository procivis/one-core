use thiserror::Error;

use crate::{config::data_structure::CoreConfig, OneCore};

pub mod config_provider;
pub mod data_structure;
pub mod json_config_provider;
pub mod yaml_config_provider;

mod process_config_object;
mod validate_types;

#[derive(Debug, Error)]
pub enum ConfigParseError {
    #[error("JSON error: `{0}`")]
    JsonError(serde_json::Error),
    #[error("Invalid type `{1}` on field `{0}`")]
    InvalidType(String, String),
}

impl OneCore {
    pub async fn get_config(&self) -> CoreConfig {
        self.config.to_owned()
    }
}
