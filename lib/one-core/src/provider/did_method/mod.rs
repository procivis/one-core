use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use shared_types::{DidId, DidValue};
use thiserror::Error;

use crate::config::core_config::{self, DidConfig, KeyAlgorithmConfig};
use crate::config::ConfigError;
use crate::model::did::Did;
use crate::model::key::Key;
use crate::provider::did_method::key::KeyDidMethod;
use crate::provider::did_method::web::WebDidMethod;
use crate::provider::did_method::x509::X509Method;
use crate::repository::did_repository::DidRepository;
use crate::repository::error::DataLayerError;
use crate::repository::organisation_repository::OrganisationRepository;
use crate::service::did::dto::CreateDidRequestDTO;

use super::key_algorithm::provider::KeyAlgorithmProvider;

use self::key::DidKeyParams;

pub mod key;
mod mapper;
pub mod provider;
pub mod web;
pub mod x509;

#[derive(Debug, Error)]
pub enum DidMethodError {
    #[error("Did already exists")]
    AlreadyExists,
    #[error("Data layer error: `{0}`")]
    DataLayerError(#[from] DataLayerError),
    #[error("Key algorithm not found")]
    KeyAlgorithmNotFound,
    #[error("Could not resolve: `{0}`")]
    ResolutionError(String),
    #[error("Not supported")]
    NotSupported,
}

#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait DidMethod {
    fn get_method(&self) -> String;

    async fn create(&self, request: CreateDidRequestDTO, key: Key)
        -> Result<DidId, DidMethodError>;

    fn check_authorization(&self) -> bool;
    async fn resolve(&self, did: &DidValue) -> Result<Did, DidMethodError>;
    fn update(&self) -> Result<(), DidMethodError>;
    fn deactivate(&self) -> Result<(), DidMethodError>;
}

pub fn did_method_providers_from_config(
    did_config: &DidConfig,
    did_repository: Arc<dyn DidRepository + Send + Sync>,
    organisation_repository: Arc<dyn OrganisationRepository + Send + Sync>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider + Send + Sync>,
    key_algorithm_config: &KeyAlgorithmConfig,
) -> Result<HashMap<String, Arc<dyn DidMethod + Send + Sync>>, ConfigError> {
    let mut providers = HashMap::new();

    for did_type in did_config.as_inner().keys() {
        match did_type {
            core_config::DidType::Key => {
                let method = Arc::new(KeyDidMethod::new(
                    did_repository.clone(),
                    organisation_repository.clone(),
                    key_algorithm_provider.clone(),
                    key_algorithm_config.clone(),
                    DidKeyParams,
                    "KEY",
                ));

                providers.insert(did_type.to_string(), method as _);
            }
            core_config::DidType::Web => {
                let method = Arc::new(WebDidMethod::new());
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
