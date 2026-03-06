use std::sync::Arc;

use crate::provider::verifier::model::Verifier;
use crate::provider::verifier::provider::VerifierProvider;
use crate::service::error::ServiceError;

pub struct VerifierProviderService {
    verifier_provider: Arc<dyn VerifierProvider>,
}

impl VerifierProviderService {
    pub(crate) fn new(verifier_provider: Arc<dyn VerifierProvider>) -> Self {
        Self { verifier_provider }
    }

    pub fn get_verifier_by_id(&self, id: &str) -> Result<Verifier, ServiceError> {
        self.verifier_provider.get_by_id(id)
    }
}
