use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use shared_types::{DidId, DidValue};
use thiserror::Error;

use crate::config::core_config::{self, DidConfig, KeyAlgorithmConfig};
use crate::config::{ConfigError, ConfigValidationError};
use crate::model::did::Did;
use crate::model::key::Key;
use crate::provider::did_method::key::KeyDidMethod;
use crate::provider::did_method::web::WebDidMethod;
use crate::provider::did_method::x509::X509Method;
use crate::repository::error::DataLayerError;

use super::key_algorithm::provider::KeyAlgorithmProvider;

use self::key::DidKeyParams;

pub mod key;
mod mapper;
pub mod provider;
pub mod web;
pub mod x509;

#[derive(Debug, Error)]
pub enum DidMethodError {
    #[error("Data layer error: `{0}`")]
    DataLayerError(#[from] DataLayerError),
    #[error("Key algorithm not found")]
    KeyAlgorithmNotFound,
    #[error("Could not create: `{0}`")]
    CreationError(String),
    #[error("Could not resolve: `{0}`")]
    ResolutionError(String),
    #[error("Could not create: `{0}`")]
    CouldNotCreate(String),
    #[error("Not supported")]
    NotSupported,
}

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait DidMethod {
    fn get_method(&self) -> String;

    async fn create(
        &self,
        id: &DidId,
        params: &Option<serde_json::Value>,
        key: &Option<Key>,
    ) -> Result<DidValue, DidMethodError>;

    fn check_authorization(&self) -> bool;
    async fn resolve(&self, did: &DidValue) -> Result<Did, DidMethodError>;
    fn update(&self) -> Result<(), DidMethodError>;
    fn can_be_deactivated(&self) -> bool;
}

pub fn did_method_providers_from_config(
    did_config: &DidConfig,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider + Send + Sync>,
    key_algorithm_config: &KeyAlgorithmConfig,
    base_url: Option<String>,
) -> Result<HashMap<String, Arc<dyn DidMethod + Send + Sync>>, ConfigError> {
    let mut providers = HashMap::new();

    for did_type in did_config.as_inner().keys() {
        match did_type {
            core_config::DidType::Key => {
                let method = Arc::new(KeyDidMethod::new(
                    key_algorithm_provider.clone(),
                    key_algorithm_config.clone(),
                    DidKeyParams,
                    "KEY",
                ));

                providers.insert(did_type.to_string(), method as _);
            }
            core_config::DidType::Web => {
                let did_web = WebDidMethod::new(&base_url).map_err(|_| {
                    ConfigError::Validation(ConfigValidationError::KeyNotFound(
                        "Base url".to_string(),
                    ))
                })?;
                let method = Arc::new(did_web);
                providers.insert(did_type.to_string(), method as _);
            }
            core_config::DidType::X509 => {
                let method = Arc::new(X509Method::new());
                providers.insert(did_type.to_string(), method as _);
            }
        }
    }

    Ok(providers)
}
