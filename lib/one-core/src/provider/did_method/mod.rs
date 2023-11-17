use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use shared_types::{DidId, DidValue};
use thiserror::Error;

use crate::config::{
    data_structure::{DidEntity, DidKeyParams, DidParams, KeyAlgorithmEntity, ParamsEnum},
    ConfigParseError,
};
use crate::model::did::Did;
use crate::model::key::Key;
use crate::provider::did_method::key::KeyDidMethod;
use crate::provider::did_method::web::WebDidMethod;
use crate::provider::did_method::x509::X509Method;
use crate::provider::key_storage::provider::KeyProvider;
use crate::repository::did_repository::DidRepository;
use crate::repository::error::DataLayerError;
use crate::repository::organisation_repository::OrganisationRepository;
use crate::service::did::dto::CreateDidRequestDTO;

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
    #[error("Key storage not found")]
    KeyStorageNotFound,
    #[error("Could not resolve: `{0}`")]
    ResolutionError(String),
    #[error("Not supported")]
    NotSupported,
}

#[async_trait]
pub trait DidMethod {
    fn get_method(&self) -> String;

    async fn load(&self, did_id: &DidId) -> Result<Did, DidMethodError>;
    async fn create(&self, request: CreateDidRequestDTO, key: Key) -> Result<Did, DidMethodError>;

    fn check_authorization(&self) -> bool;
    async fn resolve(&self, did: &DidValue) -> Result<Did, DidMethodError>;
    fn update(&self) -> Result<(), DidMethodError>;
    fn deactivate(&self) -> Result<(), DidMethodError>;
}

pub fn did_method_providers_from_config(
    did_config: &HashMap<String, DidEntity>,
    did_repository: Arc<dyn DidRepository + Send + Sync>,
    organisation_repository: Arc<dyn OrganisationRepository + Send + Sync>,
    key_provider: Arc<dyn KeyProvider + Send + Sync>,
    key_algorithm_config: &HashMap<String, KeyAlgorithmEntity>,
) -> Result<HashMap<String, Arc<dyn DidMethod + Send + Sync>>, ConfigParseError> {
    did_config
        .iter()
        .map(|(name, entity)| {
            storage_from_entity(
                name,
                entity,
                did_repository.clone(),
                organisation_repository.clone(),
                key_provider.clone(),
                key_algorithm_config,
            )
        })
        .collect::<Result<HashMap<String, _>, _>>()
}

fn storage_from_entity(
    name: &String,
    entity: &DidEntity,
    did_repository: Arc<dyn DidRepository + Send + Sync>,
    organisation_repository: Arc<dyn OrganisationRepository + Send + Sync>,
    key_provider: Arc<dyn KeyProvider + Send + Sync>,
    key_algorithm_config: &HashMap<String, KeyAlgorithmEntity>,
) -> Result<(String, Arc<dyn DidMethod + Send + Sync>), ConfigParseError> {
    match entity.r#type.as_str() {
        "X509" => Ok((name.to_owned(), Arc::new(X509Method {}))),
        "WEB" => Ok((name.to_owned(), Arc::new(WebDidMethod {}))),
        "KEY" => {
            let params = match &entity.params {
                None => Ok(DidKeyParams::default()),
                Some(value) => match value {
                    ParamsEnum::Parsed(DidParams::Key(value)) => Ok(value.to_owned()),
                    _ => Err(ConfigParseError::InvalidType(
                        name.to_owned(),
                        String::new(),
                    )),
                },
            }?;
            Ok((
                name.to_owned(),
                Arc::new(KeyDidMethod {
                    did_repository: did_repository.clone(),
                    organisation_repository: organisation_repository.clone(),
                    key_provider: key_provider.clone(),
                    method_key: "KEY".to_string(),
                    params,
                    key_algorithm_config: key_algorithm_config.to_owned(),
                }),
            ))
        }
        _ => Err(ConfigParseError::InvalidType(
            entity.r#type.to_owned(),
            String::new(),
        )),
    }
}

#[cfg(test)]
pub mod mock_did_method;
