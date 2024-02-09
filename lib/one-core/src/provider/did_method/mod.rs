use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde::Serialize;
use shared_types::{DidId, DidValue};
use thiserror::Error;

use crate::config::core_config::{self, DidConfig};
use crate::config::{ConfigError, ConfigParsingError, ConfigValidationError};
use crate::model::key::Key;
use crate::provider::did_method::jwk::JWKDidMethod;
use crate::provider::did_method::key::KeyDidMethod;
use crate::provider::did_method::web::WebDidMethod;
use crate::provider::did_method::x509::X509Method;

use super::key_algorithm::provider::KeyAlgorithmProvider;

use self::dto::{AmountOfKeys, DidDocumentDTO};
use self::universal::UniversalDidMethod;

pub mod common;
pub mod dto;
pub mod jwk;
pub mod key;
pub mod provider;
pub mod universal;
pub mod web;
pub mod x509;

#[derive(Debug, PartialEq, Eq, Clone, Serialize)]
pub enum Operation {
    RESOLVE,
    CREATE,
    DEACTIVATE,
}

#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DidCapabilities {
    pub operations: Vec<Operation>,
    pub key_algorithms: Vec<String>,
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
    fn validate_keys(&self, keys: AmountOfKeys) -> bool;
}

pub fn did_method_providers_from_config(
    did_config: &mut DidConfig,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    base_url: Option<String>,
) -> Result<HashMap<String, Arc<dyn DidMethod>>, ConfigError> {
    let mut providers: HashMap<String, Arc<dyn DidMethod>> = HashMap::new();

    for (name, field) in did_config.iter() {
        let method = match &field.r#type {
            core_config::DidType::Key => {
                Arc::new(KeyDidMethod::new(key_algorithm_provider.clone())) as _
            }
            core_config::DidType::Web => {
                let params = did_config.get(name)?;
                let did_web = WebDidMethod::new(&base_url, params).map_err(|_| {
                    ConfigError::Validation(ConfigValidationError::KeyNotFound(
                        "Base url".to_string(),
                    ))
                })?;
                Arc::new(did_web) as _
            }
            core_config::DidType::Jwk => {
                Arc::new(JWKDidMethod::new(key_algorithm_provider.clone())) as _
            }
            core_config::DidType::X509 => Arc::new(X509Method::new()) as _,
            core_config::DidType::UNIVERSAL => {
                let params = did_config.get(name)?;
                Arc::new(UniversalDidMethod::new(params)) as _
            }
        };
        providers.insert(name.to_owned(), method);
    }

    for (key, value) in did_config.iter_mut() {
        if let Some(entity) = providers.get(key) {
            let json = serde_json::to_value(entity.get_capabilities())
                .map_err(|e| ConfigError::Parsing(ConfigParsingError::Json(e)))?;
            value.capabilities = Some(json);
        }
    }

    Ok(providers)
}
