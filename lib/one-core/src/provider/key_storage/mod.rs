use std::collections::HashMap;
use std::sync::Arc;

use crate::{
    config::{
        data_structure::{
            KeyStorageEntity, KeyStorageInternalParams, KeyStorageParams, ParamsEnum,
        },
        ConfigParseError,
    },
    provider::key_storage::internal::InternalKeyProvider,
    service::error::ServiceError,
};

pub mod internal;
pub mod provider;

pub struct GeneratedKey {
    pub public: Vec<u8>,
    pub private: Vec<u8>,
}

pub trait KeyStorage {
    fn decrypt_private_key(&self, private_key: &[u8]) -> Result<Vec<u8>, ServiceError>;
    fn fingerprint(&self, bytes: &[u8]) -> String;
    fn generate(&self, algorithm: &str) -> Result<GeneratedKey, ServiceError>;
}

pub fn key_providers_from_config(
    key_config: &HashMap<String, KeyStorageEntity>,
) -> Result<HashMap<String, Arc<dyn KeyStorage + Send + Sync>>, ConfigParseError> {
    key_config
        .iter()
        .map(|(name, entity)| storage_from_entity(name, entity))
        .collect::<Result<HashMap<String, _>, _>>()
}

fn storage_from_entity(
    name: &String,
    entity: &KeyStorageEntity,
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
            Ok((name.to_owned(), Arc::new(InternalKeyProvider { params })))
        }
        _ => Err(ConfigParseError::InvalidType(
            entity.r#type.to_owned(),
            String::new(),
        )),
    }
}

#[cfg(test)]
pub mod mock_key_storage;
