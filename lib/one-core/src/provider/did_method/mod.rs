use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde::Deserialize;
use shared_types::{DidId, DidValue};
use thiserror::Error;

use crate::config::core_config::{self, DidConfig};
use crate::config::{ConfigError, ConfigValidationError};
use crate::model::key::Key;
use crate::provider::did_method::jwk::JWKDidMethod;
use crate::provider::did_method::key::KeyDidMethod;
use crate::provider::did_method::web::WebDidMethod;
use crate::provider::did_method::x509::X509Method;

use super::key_algorithm::provider::KeyAlgorithmProvider;

use self::dto::DidDocumentDTO;

pub mod common;
pub mod dto;
pub mod jwk;
pub mod key;
pub mod provider;
pub mod web;
pub mod x509;

#[derive(Clone, Default, Deserialize)]
pub struct DidCapabilities {
    pub operations: Vec<String>,
}

#[derive(Debug, Error)]
pub enum DidMethodError {
    #[error("Key algorithm not found")]
    KeyAlgorithmNotFound,
    #[error("Could not resolve: `{0}`")]
    ResolutionError(String),
    #[error("Could not create: `{0}`")]
    CouldNotCreate(String),
    #[error("Not supported")]
    NotSupported,
}

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait DidMethod: Send + Sync {
    fn get_method(&self) -> String;

    async fn create(
        &self,
        id: &DidId,
        params: &Option<serde_json::Value>,
        key: &Option<Key>,
    ) -> Result<DidValue, DidMethodError>;

    fn check_authorization(&self) -> bool;
    async fn resolve(&self, did: &DidValue) -> Result<DidDocumentDTO, DidMethodError>;
    fn update(&self) -> Result<(), DidMethodError>;
    fn can_be_deactivated(&self) -> bool;
    fn get_capabilities(&self) -> DidCapabilities;
}

pub fn did_method_providers_from_config(
    did_config: &DidConfig,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    base_url: Option<String>,
) -> Result<HashMap<String, Arc<dyn DidMethod>>, ConfigError> {
    let mut providers = HashMap::new();

    for did_type in did_config.as_inner().keys() {
        let type_str = did_type.to_string();

        let capabilities = did_config.get_capabilities(&type_str)?;

        match did_type {
            core_config::DidType::Key => {
                let method = Arc::new(KeyDidMethod::new(
                    capabilities,
                    key_algorithm_provider.clone(),
                ));
                providers.insert(type_str, method as _);
            }
            core_config::DidType::Web => {
                let did_web = WebDidMethod::new(&base_url, capabilities).map_err(|_| {
                    ConfigError::Validation(ConfigValidationError::KeyNotFound(
                        "Base url".to_string(),
                    ))
                })?;
                let method = Arc::new(did_web);
                providers.insert(type_str, method as _);
            }
            core_config::DidType::Jwk => {
                let method = Arc::new(JWKDidMethod::new(
                    capabilities,
                    key_algorithm_provider.clone(),
                ));
                providers.insert(type_str, method as _);
            }
            core_config::DidType::X509 => {
                let method = Arc::new(X509Method::new());
                providers.insert(type_str, method as _);
            }
        }
    }

    Ok(providers)
}
