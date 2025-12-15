use std::sync::Arc;

use crate::provider::signer::provider::SignerProvider;

pub mod service;

#[derive(Clone)]
pub struct SignatureService {
    signer_provider: Arc<dyn SignerProvider>,
}

impl SignatureService {
    pub(crate) fn new(signer_provider: Arc<dyn SignerProvider>) -> Self {
        Self { signer_provider }
    }
}
