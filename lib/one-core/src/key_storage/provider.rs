use std::{collections::HashMap, sync::Arc};

use super::KeyStorage;
use crate::service::error::ServiceError;

pub trait KeyProvider {
    fn get_key_storage(
        &self,
        key_provider_id: &str,
    ) -> Result<Arc<dyn KeyStorage + Send + Sync>, ServiceError>;
}

pub struct KeyProviderImpl {
    storages: HashMap<String, Arc<dyn KeyStorage + Send + Sync>>,
}

impl KeyProviderImpl {
    pub fn new(storages: HashMap<String, Arc<dyn KeyStorage + Send + Sync>>) -> Self {
        Self { storages }
    }
}

impl KeyProvider for KeyProviderImpl {
    fn get_key_storage(
        &self,
        format: &str,
    ) -> Result<Arc<dyn KeyStorage + Send + Sync>, ServiceError> {
        Ok(self
            .storages
            .get(format)
            .ok_or(ServiceError::NotFound)?
            .clone())
    }
}
