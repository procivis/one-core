//! Credential format provider.

use std::collections::HashMap;
use std::sync::Arc;

use super::CredentialFormatter;
use crate::provider::presentation_formatter::PresentationFormatter;
use crate::provider::presentation_formatter::adapter::PresentationFormatterAdapter;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub trait CredentialFormatterProvider: Send + Sync {
    fn get_credential_formatter(&self, formatter_id: &str) -> Option<Arc<dyn CredentialFormatter>>;
    fn get_presentation_formatter(
        &self,
        formatter_id: &str,
    ) -> Option<Arc<dyn PresentationFormatter>>;
}

pub struct CredentialFormatterProviderImpl {
    credential_formatters: HashMap<String, Arc<dyn CredentialFormatter>>,
    presentation_formatters: HashMap<String, Arc<dyn PresentationFormatter>>,
}

impl CredentialFormatterProviderImpl {
    pub fn new(
        credential_formatters: HashMap<String, Arc<dyn CredentialFormatter>>,
        presentation_formatters: HashMap<String, Arc<dyn PresentationFormatter>>,
    ) -> Self {
        Self {
            credential_formatters,
            presentation_formatters,
        }
    }
}

impl CredentialFormatterProvider for CredentialFormatterProviderImpl {
    fn get_credential_formatter(&self, format: &str) -> Option<Arc<dyn CredentialFormatter>> {
        self.credential_formatters.get(format).cloned()
    }

    fn get_presentation_formatter(&self, format: &str) -> Option<Arc<dyn PresentationFormatter>> {
        self.presentation_formatters
            .get(format)
            .cloned()
            .or_else(|| {
                self.credential_formatters.get(format).map(|f| {
                    Arc::new(PresentationFormatterAdapter::new(f.clone()))
                        as Arc<dyn PresentationFormatter + 'static>
                })
            })
    }
}
