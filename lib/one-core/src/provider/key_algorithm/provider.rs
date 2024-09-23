use std::collections::HashMap;
use std::sync::Arc;

use super::error::KeyAlgorithmProviderError;
use super::model::ParsedPublicKeyJwk;
use super::KeyAlgorithm;
use crate::crypto::{CryptoProvider, Signer};
use crate::model::key::PublicKeyJwk;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub trait KeyAlgorithmProvider: Send + Sync {
    fn get_key_algorithm(&self, algorithm: &str) -> Option<Arc<dyn KeyAlgorithm>>;

    fn get_signer(&self, algorithm: &str) -> Result<Arc<dyn Signer>, KeyAlgorithmProviderError>;

    fn parse_jwk(
        &self,
        key: &PublicKeyJwk,
    ) -> Result<ParsedPublicKeyJwk, KeyAlgorithmProviderError>;
}

pub struct KeyAlgorithmProviderImpl {
    algorithms: HashMap<String, Arc<dyn KeyAlgorithm>>,
    crypto: Arc<dyn CryptoProvider>,
}

impl KeyAlgorithmProviderImpl {
    pub fn new(
        algorithms: HashMap<String, Arc<dyn KeyAlgorithm>>,
        crypto: Arc<dyn CryptoProvider>,
    ) -> Self {
        Self { algorithms, crypto }
    }
}

impl KeyAlgorithmProvider for KeyAlgorithmProviderImpl {
    fn get_key_algorithm(&self, algorithm: &str) -> Option<Arc<dyn KeyAlgorithm>> {
        self.algorithms.get(algorithm).cloned()
    }

    fn get_signer(&self, algorithm: &str) -> Result<Arc<dyn Signer>, KeyAlgorithmProviderError> {
        let key_algorithm = self.get_key_algorithm(algorithm).ok_or(
            KeyAlgorithmProviderError::MissingAlgorithmImplementation(algorithm.to_owned()),
        )?;
        let signer_algorithm = key_algorithm.get_signer_algorithm_id();
        self.crypto
            .get_signer(&signer_algorithm)
            .map_err(|e| KeyAlgorithmProviderError::MissingSignerImplementation(e.to_string()))
    }

    fn parse_jwk(
        &self,
        key: &PublicKeyJwk,
    ) -> Result<ParsedPublicKeyJwk, KeyAlgorithmProviderError> {
        for algorithm in self.algorithms.values() {
            if let Ok(public_key_bytes) = algorithm.jwk_to_bytes(key) {
                return Ok(ParsedPublicKeyJwk {
                    public_key_bytes,
                    signer_algorithm_id: algorithm.get_signer_algorithm_id(),
                });
            }
        }

        Err(KeyAlgorithmProviderError::MissingAlgorithmImplementation(
            "None of the algorithms supports given key".to_string(),
        ))
    }
}
