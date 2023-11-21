use std::collections::HashMap;
use std::sync::Arc;

use crate::crypto::signer::error::SignerError;
use crate::model::key::Key;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::{
    config::{
        data_structure::{
            KeyStorageEntity, KeyStorageInternalParams, KeyStorageParams, ParamsEnum,
        },
        ConfigParseError,
    },
    provider::{
        key_algorithm::GeneratedKey,
        key_storage::{
            azure_vault::AzureVaultKeyProvider, internal::InternalKeyProvider,
            pkcs11::PKCS11KeyProvider,
        },
    },
    service::error::ServiceError,
};

pub mod azure_vault;
pub mod internal;
pub mod pkcs11;
pub mod provider;

#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub trait KeyStorage {
    async fn generate(&self, key_type: &str) -> Result<GeneratedKey, ServiceError>;
    async fn sign(&self, key: &Key, message: &str) -> Result<Vec<u8>, SignerError>;
}

pub fn key_providers_from_config(
    key_config: &HashMap<String, KeyStorageEntity>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider + Send + Sync>,
) -> Result<HashMap<String, Arc<dyn KeyStorage + Send + Sync>>, ConfigParseError> {
    key_config
        .iter()
        .map(|(name, entity)| storage_from_entity(name, entity, key_algorithm_provider.clone()))
        .collect::<Result<HashMap<String, _>, _>>()
}

fn storage_from_entity(
    name: &String,
    entity: &KeyStorageEntity,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider + Send + Sync>,
) -> Result<(String, Arc<dyn KeyStorage + Send + Sync>), ConfigParseError> {
    match entity.r#type.as_str() {
        "INTERNAL" => {
            let params = match &entity.params {
                None => Ok(KeyStorageInternalParams::default()),
                Some(value) => match value {
                    ParamsEnum::Parsed(KeyStorageParams::Internal(value)) => Ok(value.to_owned()),
                    _ => Err(ConfigParseError::InvalidType(
                        name.to_owned(),
                        String::new(),
                    )),
                },
            }?;
            Ok((
                name.to_owned(),
                Arc::new(InternalKeyProvider {
                    key_algorithm_provider,
                    params,
                }),
            ))
        }
        "AZURE_VAULT" => Ok((name.to_owned(), Arc::new(AzureVaultKeyProvider {}))),
        "PKCS11" => Ok((name.to_owned(), Arc::new(PKCS11KeyProvider {}))),
        _ => Err(ConfigParseError::InvalidType(
            entity.r#type.to_owned(),
            String::new(),
        )),
    }
}
