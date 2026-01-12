use std::cmp::Reverse;
use std::collections::HashMap;
use std::sync::Arc;

use itertools::Itertools;
use secrecy::SecretSlice;
use serde_json::json;
use standardized_types::jwk::{JwkUse, PublicJwk};

use super::KeyAlgorithm;
use super::bbs::BBS;
use super::ecdsa::Ecdsa;
use super::eddsa::Eddsa;
use super::error::KeyAlgorithmProviderError;
use super::key::KeyHandle;
use super::ml_dsa::MlDsa;
use crate::config::ConfigValidationError;
use crate::config::core_config::{ConfigExt, CoreConfig, KeyAlgorithmConfig, KeyAlgorithmType};

#[derive(Clone)]
pub struct ParsedKey {
    pub algorithm_type: KeyAlgorithmType,
    pub key: KeyHandle,
}

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub trait KeyAlgorithmProvider: Send + Sync {
    fn key_algorithm_from_type(&self, algorithm: KeyAlgorithmType)
    -> Option<Arc<dyn KeyAlgorithm>>;

    fn key_algorithm_from_jose_alg(
        &self,
        jose_alg: &str,
    ) -> Option<(KeyAlgorithmType, Arc<dyn KeyAlgorithm>)>;
    fn key_algorithm_from_cose_alg(
        &self,
        cose_alg: i32,
    ) -> Option<(KeyAlgorithmType, Arc<dyn KeyAlgorithm>)>;

    fn parse_jwk(&self, key: &PublicJwk) -> Result<ParsedKey, KeyAlgorithmProviderError>;
    fn parse_multibase(&self, multibase: &str) -> Result<ParsedKey, KeyAlgorithmProviderError>;
    fn parse_raw(&self, public_key_der: &[u8]) -> Result<ParsedKey, KeyAlgorithmProviderError>;

    fn reconstruct_key(
        &self,
        algorithm: KeyAlgorithmType,
        public_key: &[u8],
        private_key: Option<SecretSlice<u8>>,
        r#use: Option<JwkUse>,
    ) -> Result<KeyHandle, KeyAlgorithmProviderError>;

    fn supported_verification_jose_alg_ids(&self) -> Vec<String>;
    fn ordered_by_holder_priority(&self) -> Vec<(KeyAlgorithmType, Arc<dyn KeyAlgorithm>)>;
}

struct KeyAlgorithmProviderImpl {
    algorithms: HashMap<KeyAlgorithmType, Arc<dyn KeyAlgorithm>>,
    config: KeyAlgorithmConfig,
}

impl KeyAlgorithmProvider for KeyAlgorithmProviderImpl {
    fn key_algorithm_from_type(
        &self,
        algorithm: KeyAlgorithmType,
    ) -> Option<Arc<dyn KeyAlgorithm>> {
        self.algorithms.get(&algorithm).cloned()
    }

    fn key_algorithm_from_jose_alg(
        &self,
        jose_alg: &str,
    ) -> Option<(KeyAlgorithmType, Arc<dyn KeyAlgorithm>)> {
        self.algorithms
            .iter()
            .find(|(_, alg)| {
                alg.verification_jose_alg_ids()
                    .iter()
                    .any(|v| v == jose_alg)
            })
            .map(|(id, alg)| (id.to_owned(), alg.clone()))
    }

    fn key_algorithm_from_cose_alg(
        &self,
        cose_alg: i32,
    ) -> Option<(KeyAlgorithmType, Arc<dyn KeyAlgorithm>)> {
        self.algorithms
            .iter()
            .find(|(_, alg)| alg.cose_alg_id().is_some_and(|alg| alg == cose_alg))
            .map(|(id, alg)| (id.to_owned(), alg.clone()))
    }

    fn parse_jwk(&self, key: &PublicJwk) -> Result<ParsedKey, KeyAlgorithmProviderError> {
        for algorithm in self.algorithms.values() {
            if let Ok(public_key) = algorithm.parse_jwk(key) {
                return Ok(ParsedKey {
                    algorithm_type: algorithm.algorithm_type(),
                    key: public_key,
                });
            }
        }

        Err(KeyAlgorithmProviderError::MissingAlgorithmImplementation(
            "None of the algorithms supports given key".to_string(),
        ))
    }

    fn parse_multibase(&self, multibase: &str) -> Result<ParsedKey, KeyAlgorithmProviderError> {
        for algorithm in self.algorithms.values() {
            if let Ok(public_key) = algorithm.parse_multibase(multibase) {
                return Ok(ParsedKey {
                    algorithm_type: algorithm.algorithm_type(),
                    key: public_key,
                });
            }
        }

        Err(KeyAlgorithmProviderError::MissingAlgorithmImplementation(
            "None of the algorithms supports given key".to_string(),
        ))
    }

    fn parse_raw(&self, public_key_der: &[u8]) -> Result<ParsedKey, KeyAlgorithmProviderError> {
        for algorithm in self.algorithms.values() {
            if let Ok(public_key) = algorithm.parse_raw(public_key_der) {
                return Ok(ParsedKey {
                    algorithm_type: algorithm.algorithm_type(),
                    key: public_key,
                });
            }
        }

        Err(KeyAlgorithmProviderError::MissingAlgorithmImplementation(
            "None of the algorithms supports given key".to_string(),
        ))
    }

    fn reconstruct_key(
        &self,
        algorithm: KeyAlgorithmType,
        public_key: &[u8],
        private_key: Option<SecretSlice<u8>>,
        r#use: Option<JwkUse>,
    ) -> Result<KeyHandle, KeyAlgorithmProviderError> {
        let algorithm = self.key_algorithm_from_type(algorithm).ok_or(
            KeyAlgorithmProviderError::MissingAlgorithmImplementation(algorithm.to_string()),
        )?;
        algorithm
            .reconstruct_key(public_key, private_key, r#use)
            .map_err(KeyAlgorithmProviderError::KeyAlgorithm)
    }

    fn supported_verification_jose_alg_ids(&self) -> Vec<String> {
        self.algorithms
            .values()
            .flat_map(|key_alg| key_alg.verification_jose_alg_ids())
            .collect()
    }

    fn ordered_by_holder_priority(&self) -> Vec<(KeyAlgorithmType, Arc<dyn KeyAlgorithm>)> {
        let get_holder_priority = |r#type: &KeyAlgorithmType| -> u32 {
            self.config
                .get_if_enabled(r#type)
                .ok()
                .map(|v| v.holder_priority)
                .unwrap_or(0)
        };

        self.algorithms
            .iter()
            .sorted_by_key(|(k, _)| Reverse(get_holder_priority(k)))
            .map(|(k, v)| (*k, v.to_owned()))
            .collect()
    }
}

pub(crate) fn key_algorithm_provider_from_config(
    config: &mut CoreConfig,
) -> Result<Arc<dyn KeyAlgorithmProvider>, ConfigValidationError> {
    let mut algorithms: HashMap<KeyAlgorithmType, Arc<dyn KeyAlgorithm>> = HashMap::new();

    for (name, fields) in config.key_algorithm.iter() {
        if !fields.enabled {
            continue;
        }

        let key_algorithm: Arc<dyn KeyAlgorithm> = match name {
            KeyAlgorithmType::Eddsa => Arc::new(Eddsa),
            KeyAlgorithmType::Ecdsa => Arc::new(Ecdsa),
            KeyAlgorithmType::BbsPlus => Arc::new(BBS),
            KeyAlgorithmType::Dilithium => Arc::new(MlDsa),
        };
        algorithms.insert(*name, key_algorithm);
    }

    for (key, value) in config.key_algorithm.iter_mut() {
        if let Some(entity) = algorithms.get(key) {
            value.capabilities = Some(json!(entity.get_capabilities()));
        }
    }

    Ok(Arc::new(KeyAlgorithmProviderImpl {
        algorithms,
        config: config.key_algorithm.to_owned(),
    }))
}
