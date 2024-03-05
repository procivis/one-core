use std::{collections::HashMap, sync::Arc};

use super::KeyAlgorithm;
use crate::{
    crypto::{signer::Signer, CryptoProvider},
    provider::did_method::dto::PublicKeyJwkDTO,
    service::error::{ServiceError, ValidationError},
};

#[cfg_attr(test, mockall::automock)]
pub trait KeyAlgorithmProvider: Send + Sync {
    fn get_key_algorithm(&self, algorithm: &str) -> Option<Arc<dyn KeyAlgorithm>>;

    fn get_signer(&self, algorithm: &str) -> Result<Arc<dyn Signer>, ServiceError>;

    fn parse_jwk(&self, key: &PublicKeyJwkDTO) -> Result<ParsedPublicKeyJwk, ServiceError>;
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

    fn get_signer(&self, algorithm: &str) -> Result<Arc<dyn Signer>, ServiceError> {
        let key_algorithm = self
            .get_key_algorithm(algorithm)
            .ok_or(ValidationError::InvalidKeyAlgorithm(algorithm.to_owned()))?;
        let signer_algorithm = key_algorithm.get_signer_algorithm_id();
        self.crypto
            .get_signer(&signer_algorithm)
            .map_err(|e| ServiceError::MissingAlgorithm(e.to_string()))
    }

    fn parse_jwk(&self, key: &PublicKeyJwkDTO) -> Result<ParsedPublicKeyJwk, ServiceError> {
        for algorithm in self.algorithms.values() {
            if let Ok(public_key_bytes) = algorithm.jwk_to_bytes(key) {
                return Ok(ParsedPublicKeyJwk {
                    public_key_bytes,
                    signer_algorithm_id: algorithm.get_signer_algorithm_id(),
                });
            }
        }

        Err(ServiceError::KeyAlgorithmError(
            "None of the algorithms supports given key".to_string(),
        ))
    }
}

pub struct ParsedPublicKeyJwk {
    pub public_key_bytes: Vec<u8>,
    pub signer_algorithm_id: String,
}
