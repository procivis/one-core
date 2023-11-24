mod mapper;
mod validator;

use async_trait::async_trait;
use did_key::KeyMaterial;
use shared_types::{DidId, DidValue};
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

use super::DidMethodError;
use crate::{
    config::core_config::KeyAlgorithmConfig,
    model::{
        did::{Did, DidType, KeyRole, RelatedKey},
        key::Key,
    },
    provider::key_algorithm::provider::KeyAlgorithmProvider,
};

use mapper::categorize_did;
use validator::validate_public_key_length;

pub struct KeyDidMethod {
    pub key_algorithm_provider: Arc<dyn KeyAlgorithmProvider + Send + Sync>,
    pub method_key: String,
    pub params: DidKeyParams,
    pub key_algorithm_config: KeyAlgorithmConfig,
}

pub struct DidKeyParams;

impl KeyDidMethod {
    pub fn new(
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider + Send + Sync>,
        key_algorithm_config: KeyAlgorithmConfig,
        params: DidKeyParams,
        method_key: impl Into<String>,
    ) -> Self {
        Self {
            key_algorithm_provider,
            method_key: method_key.into(),
            params,
            key_algorithm_config,
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
            .map_err(|_| DidMethodError::KeyAlgorithmNotFound)?;
        let multibase = key_algorithm.get_multibase(&key.public_key);
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

    async fn resolve(&self, did: &DidValue) -> Result<Did, DidMethodError> {
        let key_type = categorize_did(did)?;

        let resolved = did_key::resolve(did.as_str())
            .map_err(|_| DidMethodError::ResolutionError("Failed to resolve".to_string()))?;

        let public_key = resolved.public_key_bytes();

        validate_public_key_length(&public_key, key_type)?;

        let now = OffsetDateTime::now_utc();
        let key = Key {
            id: Uuid::new_v4(),
            created_date: now,
            last_modified: now,
            public_key,
            name: did.to_string(),
            key_reference: vec![],
            storage_type: "EPHEMERAL".to_string(),
            key_type: "EDDSA".to_string(),
            organisation: None,
        };

        Ok(Did {
            id: Uuid::new_v4().into(),
            created_date: now,
            last_modified: now,
            name: did.to_string(),
            did: did.clone(),
            did_type: DidType::Remote,
            did_method: "KEY".to_string(),
            keys: Some(vec![
                RelatedKey {
                    role: KeyRole::Authentication,
                    key: key.clone(),
                },
                RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: key.clone(),
                },
                RelatedKey {
                    role: KeyRole::CapabilityInvocation,
                    key: key.clone(),
                },
                RelatedKey {
                    role: KeyRole::CapabilityDelegation,
                    key,
                },
                // skipping KeyAgreement (only supported using X25519 converted key)
            ]),
            organisation: None,
            deactivated: false,
        })
    }

    fn update(&self) -> Result<(), DidMethodError> {
        Err(DidMethodError::NotSupported)
    }

    fn can_be_deactivated(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod test;
