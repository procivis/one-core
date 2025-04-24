use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use secrecy::SecretSlice;

use super::error::KeyAlgorithmProviderError;
use super::KeyAlgorithm;
use crate::config::core_config::KeyAlgorithmType;
use crate::model::key::PublicKeyJwk;
use crate::provider::key_algorithm::key::KeyHandle;

#[derive(Clone)]
pub struct ParsedKey {
    pub algorithm_id: String,
    pub key: KeyHandle,
}

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub trait KeyAlgorithmProvider: Send + Sync {
    fn key_algorithm_from_type(&self, algorithm: KeyAlgorithmType)
        -> Option<Arc<dyn KeyAlgorithm>>;

    /// This method returns KeyAlgorithm using key_type value (as it's stored in database)
    fn key_algorithm_from_name(&self, algorithm: &str) -> Option<Arc<dyn KeyAlgorithm>>;

    /// This method returns KeyAlgorithm using algorithm id (algorithm_id() method from KeyAlgorithm)
    /// Algorithm id is specified inside tokens which are sent/received when processing VCs
    fn key_algorithm_from_id(&self, algorithm_id: &str) -> Option<Arc<dyn KeyAlgorithm>>;

    fn key_algorithm_from_jose_alg(
        &self,
        jose_alg: &str,
    ) -> Option<(KeyAlgorithmType, Arc<dyn KeyAlgorithm>)>;
    fn key_algorithm_from_cose_alg(
        &self,
        cose_alg: i32,
    ) -> Option<(KeyAlgorithmType, Arc<dyn KeyAlgorithm>)>;

    fn parse_jwk(&self, key: &PublicKeyJwk) -> Result<ParsedKey, KeyAlgorithmProviderError>;
    fn parse_multibase(&self, multibase: &str) -> Result<ParsedKey, KeyAlgorithmProviderError>;
    fn parse_raw(&self, public_key_der: &[u8]) -> Result<ParsedKey, KeyAlgorithmProviderError>;

    fn reconstruct_key(
        &self,
        algorithm: &str,
        public_key: &[u8],
        private_key: Option<SecretSlice<u8>>,
        r#use: Option<String>,
    ) -> Result<KeyHandle, KeyAlgorithmProviderError>;

    fn supported_verification_jose_alg_ids(&self) -> Vec<String>;
}

pub struct KeyAlgorithmProviderImpl {
    algorithms: HashMap<KeyAlgorithmType, Arc<dyn KeyAlgorithm>>,
}

impl KeyAlgorithmProviderImpl {
    pub fn new(algorithms: HashMap<KeyAlgorithmType, Arc<dyn KeyAlgorithm>>) -> Self {
        Self { algorithms }
    }
}

impl KeyAlgorithmProvider for KeyAlgorithmProviderImpl {
    fn key_algorithm_from_type(
        &self,
        algorithm: KeyAlgorithmType,
    ) -> Option<Arc<dyn KeyAlgorithm>> {
        self.algorithms.get(&algorithm).cloned()
    }

    fn key_algorithm_from_name(&self, algorithm: &str) -> Option<Arc<dyn KeyAlgorithm>> {
        KeyAlgorithmType::from_str(algorithm)
            .ok()
            .and_then(|key_type| self.key_algorithm_from_type(key_type))
    }

    fn key_algorithm_from_id(&self, algorithm: &str) -> Option<Arc<dyn KeyAlgorithm>> {
        self.algorithms.iter().find_map(|(_, alg)| {
            if alg.algorithm_id() == algorithm {
                Some(alg.clone())
            } else {
                None
            }
        })
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

    fn parse_jwk(&self, key: &PublicKeyJwk) -> Result<ParsedKey, KeyAlgorithmProviderError> {
        for algorithm in self.algorithms.values() {
            if let Ok(public_key) = algorithm.parse_jwk(key) {
                return Ok(ParsedKey {
                    algorithm_id: algorithm.algorithm_id(),
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
                    algorithm_id: algorithm.algorithm_id(),
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
                    algorithm_id: algorithm.algorithm_id(),
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
        algorithm: &str,
        public_key: &[u8],
        private_key: Option<SecretSlice<u8>>,
        r#use: Option<String>,
    ) -> Result<KeyHandle, KeyAlgorithmProviderError> {
        let algorithm = self.key_algorithm_from_name(algorithm).ok_or(
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
}
