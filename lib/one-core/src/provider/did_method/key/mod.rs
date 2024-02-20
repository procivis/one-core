mod helpers;

use self::helpers::{decode_did, generate_document};
use super::{
    dto::{DidDocumentDTO, Keys},
    AmountOfKeys, DidCapabilities, DidMethodError, Operation,
};
use crate::{
    config::core_config::{DidType, Fields, Params},
    model::key::Key,
    provider::key_algorithm::provider::KeyAlgorithmProvider,
};
use async_trait::async_trait;
use serde_json::json;
use shared_types::{DidId, DidValue};
use std::sync::Arc;

pub struct KeyDidMethod {
    pub key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
}

impl KeyDidMethod {
    pub fn new(key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>) -> Self {
        Self {
            key_algorithm_provider,
        }
    }
}

#[async_trait]
impl super::DidMethod for KeyDidMethod {
    fn get_method(&self) -> String {
        "key".to_string()
    }

    async fn create(
        &self,
        _id: &DidId,
        _params: &Option<serde_json::Value>,
        key: &Option<Key>,
    ) -> Result<DidValue, DidMethodError> {
        let key = key
            .as_ref()
            .ok_or(DidMethodError::CouldNotCreate("Missing key".to_string()))?;
        let key_algorithm = self
            .key_algorithm_provider
            .get_key_algorithm(&key.key_type)
            .ok_or(DidMethodError::KeyAlgorithmNotFound)?;
        let multibase = key_algorithm
            .get_multibase(&key.public_key)
            .map_err(|e| DidMethodError::ResolutionError(e.to_string()))?;
        // todo(mite): add constructor for this
        let did_value: DidValue = match format!("did:key:{}", multibase).parse() {
            Ok(v) => v,
            Err(err) => match err {},
        };
        Ok(did_value)
    }

    fn check_authorization(&self) -> bool {
        todo!()
    }

    async fn resolve(&self, did_value: &DidValue) -> Result<DidDocumentDTO, DidMethodError> {
        let decoded = decode_did(did_value)?;
        let key_type = match decoded.type_ {
            helpers::DidKeyType::Eddsa => "EDDSA",
            helpers::DidKeyType::Ecdsa => "ES256",
            helpers::DidKeyType::Bbs => "BBS_PLUS",
        };

        let jwk = self
            .key_algorithm_provider
            .get_key_algorithm(key_type)
            .ok_or(DidMethodError::KeyAlgorithmNotFound)?
            .bytes_to_jwk(&decoded.decoded_multibase)
            .map_err(|_| {
                DidMethodError::ResolutionError("Could not create jwk representation".to_string())
            })?;

        generate_document(decoded, did_value, jwk)
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
