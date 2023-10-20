use super::CredentialFormatter;
use crate::service::error::ServiceError;
use std::{collections::HashMap, sync::Arc};

pub(crate) trait CredentialFormatterProvider {
    fn get_formatter(
        &self,
        formatter_id: &str,
    ) -> Result<Arc<dyn CredentialFormatter + Send + Sync>, ServiceError>;
}

pub(crate) struct CredentialFormatterProviderImpl {
    formatters: HashMap<String, Arc<dyn CredentialFormatter + Send + Sync>>,
}

impl CredentialFormatterProviderImpl {
    pub fn new(formatters: Vec<(String, Arc<dyn CredentialFormatter + Send + Sync>)>) -> Self {
        Self {
            formatters: formatters.into_iter().collect(),
        }
    }
}

impl CredentialFormatterProvider for CredentialFormatterProviderImpl {
    fn get_formatter(
        &self,
        format: &str,
    ) -> Result<Arc<dyn CredentialFormatter + Send + Sync>, ServiceError> {
        Ok(self
            .formatters
            .get(format)
            .ok_or(ServiceError::NotFound)?
            .clone())
    }
}
