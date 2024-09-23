//! Credential format provider.

use std::collections::HashMap;
use std::sync::Arc;

use super::CredentialFormatter;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub trait CredentialFormatterProvider: Send + Sync {
    fn get_formatter(&self, formatter_id: &str) -> Option<Arc<dyn CredentialFormatter>>;
}

pub struct CredentialFormatterProviderImpl {
    formatters: HashMap<String, Arc<dyn CredentialFormatter>>,
}

impl CredentialFormatterProviderImpl {
    pub fn new(formatters: HashMap<String, Arc<dyn CredentialFormatter>>) -> Self {
        Self { formatters }
    }
}

impl CredentialFormatterProvider for CredentialFormatterProviderImpl {
    fn get_formatter(&self, format: &str) -> Option<Arc<dyn CredentialFormatter>> {
        self.formatters.get(format).cloned()
    }
}
