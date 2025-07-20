use std::collections::HashMap;
use std::sync::Arc;

use crate::provider::presentation_formatter::PresentationFormatter;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub trait PresentationFormatterProvider: Send + Sync {
    fn get_presentation_formatter(
        &self,
        formatter_id: &str,
    ) -> Option<Arc<dyn PresentationFormatter>>;
}

pub struct PresentationFormatterProviderImpl {
    presentation_formatters: HashMap<String, Arc<dyn PresentationFormatter>>,
}

impl PresentationFormatterProviderImpl {
    pub fn new(presentation_formatters: HashMap<String, Arc<dyn PresentationFormatter>>) -> Self {
        Self {
            presentation_formatters,
        }
    }
}

impl PresentationFormatterProvider for PresentationFormatterProviderImpl {
    fn get_presentation_formatter(
        &self,
        formatter_id: &str,
    ) -> Option<Arc<dyn PresentationFormatter>> {
        self.presentation_formatters.get(formatter_id).cloned()
    }
}
