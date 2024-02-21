use self::helpers::{encode_to_did, extract_jwk, generate_document};
use super::{
    dto::{AmountOfKeys, DidDocumentDTO},
    DidCapabilities, DidMethodError, Operation,
};
use crate::{
    config::core_config::{DidType, Fields, Params},
    provider::did_method::dto::Keys,
};
use crate::{model::key::Key, provider::key_algorithm::provider::KeyAlgorithmProvider};
use async_trait::async_trait;
use serde_json::json;
use shared_types::{DidId, DidValue};
use std::sync::Arc;

mod helpers;

pub struct JWKDidMethod {
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
}

impl JWKDidMethod {
    #[allow(clippy::new_without_default)]
    pub fn new(key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>) -> Self {
        Self {
            key_algorithm_provider,
        }
    }
}

#[async_trait]
impl super::DidMethod for JWKDidMethod {
    fn get_method(&self) -> String {
        "jwk".to_string()
    }

    async fn create(
        &self,
        _id: &DidId,
        _params: &Option<serde_json::Value>,
        keys: &[Key],
    ) -> Result<DidValue, DidMethodError> {
        let key = match keys {
            [key] => key,
            [] => return Err(DidMethodError::CouldNotCreate("Missing key".to_string())),
            _ => return Err(DidMethodError::CouldNotCreate("Too much keys".to_string())),
        };
        let key_algorithm = self
            .key_algorithm_provider
            .get_key_algorithm(&key.key_type)
            .ok_or(DidMethodError::KeyAlgorithmNotFound)?;
        let jwk = key_algorithm
            .bytes_to_jwk(&key.public_key)
            .map_err(|e| DidMethodError::CouldNotCreate(e.to_string()))?;

        encode_to_did(&jwk)
    }

    fn check_authorization(&self) -> bool {
        todo!()
    }

    async fn resolve(&self, did: &DidValue) -> Result<DidDocumentDTO, DidMethodError> {
        let jwk = extract_jwk(did)?;
        Ok(generate_document(did, jwk))
    }

    fn update(&self) -> Result<(), DidMethodError> {
        Err(DidMethodError::NotSupported)
    }

    fn can_be_deactivated(&self) -> bool {
        false
    }

    fn get_capabilities(&self) -> DidCapabilities {
        DidCapabilities {
            operations: vec![Operation::RESOLVE, Operation::CREATE],
            key_algorithms: vec![
                "ES256".to_string(),
                "EDDSA".to_string(),
                "BBS_PLUS".to_string(),
                "DILITHIUM".to_string(),
            ],
        }
    }

    fn validate_keys(&self, keys: AmountOfKeys) -> bool {
        Keys::default().validate_keys(keys)
    }

    fn visit_config_fields(&self, fields: &Fields<DidType>) -> Fields<DidType> {
        Fields {
            capabilities: Some(json!(self.get_capabilities())),
            params: Some(Params {
                public: Some(json!({
                    "keys": Keys::default(),
                })),
                private: None,
            }),
            ..fields.clone()
        }
    }
}

#[cfg(test)]
mod test;
