use std::{collections::HashMap, sync::Arc};

use super::KeyAlgorithm;
use crate::{
    crypto::{signer::Signer, CryptoProvider},
    service::error::ServiceError,
};

#[cfg_attr(test, mockall::automock)]
pub trait KeyAlgorithmProvider {
    fn get_key_algorithm(
        &self,
        algorithm: &str,
    ) -> Result<Arc<dyn KeyAlgorithm + Send + Sync>, ServiceError>;

    fn get_signer(&self, algorithm: &str) -> Result<Arc<dyn Signer + Send + Sync>, ServiceError>;
}

pub struct KeyAlgorithmProviderImpl {
    algorithms: HashMap<String, Arc<dyn KeyAlgorithm + Send + Sync>>,
    crypto: Arc<dyn CryptoProvider + Send + Sync>,
}

impl KeyAlgorithmProviderImpl {
    pub fn new(
        algorithms: HashMap<String, Arc<dyn KeyAlgorithm + Send + Sync>>,
        crypto: Arc<dyn CryptoProvider + Send + Sync>,
    ) -> Self {
        Self { algorithms, crypto }
    }
}

impl KeyAlgorithmProvider for KeyAlgorithmProviderImpl {
    fn get_key_algorithm(
        &self,
        algorithm: &str,
    ) -> Result<Arc<dyn KeyAlgorithm + Send + Sync>, ServiceError> {
        Ok(self
            .algorithms
            .get(algorithm)
            .ok_or(ServiceError::NotFound)?
            .clone())
    }

    fn get_signer(&self, algorithm: &str) -> Result<Arc<dyn Signer + Send + Sync>, ServiceError> {
        let key_algorithm = self.get_key_algorithm(algorithm)?;
        let signer_algorithm = key_algorithm.get_signer_algorithm_id();
        self.crypto
            .get_signer(&signer_algorithm)
            .map_err(|e| ServiceError::MissingAlgorithm(e.to_string()))
    }
}
