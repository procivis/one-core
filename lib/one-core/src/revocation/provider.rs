use crate::revocation::RevocationMethod;
use crate::service::error::ServiceError;
use std::{collections::HashMap, sync::Arc};

pub(crate) trait RevocationMethodProvider {
    fn get_revocation_method(
        &self,
        revocation_method_id: &str,
    ) -> Result<Arc<dyn RevocationMethod + Send + Sync>, ServiceError>;
}

pub(crate) struct RevocationMethodProviderImpl {
    revocation_methods: HashMap<String, Arc<dyn RevocationMethod + Send + Sync>>,
}

impl RevocationMethodProviderImpl {
    pub fn new(formatters: Vec<(String, Arc<dyn RevocationMethod + Send + Sync>)>) -> Self {
        Self {
            revocation_methods: formatters.into_iter().collect(),
        }
    }
}

impl RevocationMethodProvider for RevocationMethodProviderImpl {
    fn get_revocation_method(
        &self,
        revocation_method_id: &str,
    ) -> Result<Arc<dyn RevocationMethod + Send + Sync>, ServiceError> {
        Ok(self
            .revocation_methods
            .get(revocation_method_id)
            .ok_or(ServiceError::NotFound)?
            .clone())
    }
}
