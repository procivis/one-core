use std::{collections::HashMap, sync::Arc};

use super::KeyAlgorithm;
use crate::service::error::ServiceError;

#[cfg_attr(test, mockall::automock)]
pub trait KeyAlgorithmProvider {
    fn get_key_algorithm(
        &self,
        algorithm: &str,
    ) -> Result<Arc<dyn KeyAlgorithm + Send + Sync>, ServiceError>;
}

pub struct KeyAlgorithmProviderImpl {
    algorithms: HashMap<String, Arc<dyn KeyAlgorithm + Send + Sync>>,
}

impl KeyAlgorithmProviderImpl {
    pub fn new(algorithms: HashMap<String, Arc<dyn KeyAlgorithm + Send + Sync>>) -> Self {
        Self { algorithms }
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
}
