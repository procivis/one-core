use crate::provider::revocation::RevocationMethod;
use crate::service::error::ServiceError;
use std::{collections::HashMap, sync::Arc};

#[cfg_attr(test, mockall::automock)]
pub(crate) trait RevocationMethodProvider {
    fn get_revocation_method(
        &self,
        revocation_method_id: &str,
    ) -> Result<Arc<dyn RevocationMethod + Send + Sync>, ServiceError>;

    fn get_revocation_method_by_status_type(
        &self,
        credential_status_type: &str,
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
            .to_owned())
    }

    fn get_revocation_method_by_status_type(
        &self,
        credential_status_type: &str,
    ) -> Result<Arc<dyn RevocationMethod + Send + Sync>, ServiceError> {
        Ok(self
            .revocation_methods
            .values()
            .find(|method| method.get_status_type() == credential_status_type)
            .ok_or(ServiceError::NotFound)?
            .to_owned())
    }
}
