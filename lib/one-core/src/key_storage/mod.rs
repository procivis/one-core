use std::collections::HashMap;
use std::sync::Arc;

use crate::{
    config::{
        data_structure::{KeyEntity, KeyHsmAzureParams, KeyInternalParams, KeyParams, ParamsEnum},
        ConfigParseError,
    },
    key_storage::{hsm_azure::HsmAzureKeyProvider, internal::InternalKeyProvider},
    service::error::ServiceError,
};

pub mod hsm_azure;
pub mod internal;
pub mod provider;

pub struct GeneratedKey {
    pub public: String,
    pub private: Vec<u8>,
}

pub trait KeyStorage {
    fn generate(&self, algorithm: &str) -> Result<GeneratedKey, ServiceError>;
}

pub fn key_providers_from_config(
    key_config: &HashMap<String, KeyEntity>,
) -> Result<HashMap<String, Arc<dyn KeyStorage + Send + Sync>>, ConfigParseError> {
    key_config
        .iter()
        .map(|(name, entity)| storage_from_entity(name, entity))
        .collect::<Result<HashMap<String, _>, _>>()
}

fn storage_from_entity(
    name: &String,
    entity: &KeyEntity,
) -> Result<(String, Arc<dyn KeyStorage + Send + Sync>), ConfigParseError> {
    match entity.r#type.as_str() {
        "INTERNAL" => {
            let params = match &entity.params {
                None => Ok(KeyInternalParams::default()),
                Some(value) => match value {
                    ParamsEnum::Parsed(KeyParams::Internal(value)) => Ok(value.to_owned()),
                    _ => Err(ConfigParseError::InvalidType(
                        name.to_owned(),
                        String::new(),
                    )),
                },
            }?;
            Ok((name.to_owned(), Arc::new(InternalKeyProvider { params })))
        }
        "HSM_AZURE" => {
            let params = match &entity.params {
                None => Ok(KeyHsmAzureParams::default()),
                Some(value) => match value {
                    ParamsEnum::Parsed(KeyParams::HsmAzure(value)) => Ok(value.to_owned()),
                    _ => Err(ConfigParseError::InvalidType(
                        name.to_owned(),
                        String::new(),
                    )),
                },
            }?;
            Ok((name.to_owned(), Arc::new(HsmAzureKeyProvider { params })))
        }
        _ => Err(ConfigParseError::InvalidType(
            entity.r#type.to_owned(),
            String::new(),
        )),
    }
}

#[cfg(test)]
pub mod mock_key_storage;
