use std::sync::Arc;

use crate::provider::signer::provider::SignerProvider;
use crate::repository::revocation_list_repository::RevocationListRepository;

pub mod dto;
mod error;
mod mapper;
pub mod service;

#[derive(Clone)]
pub struct SignatureService {
    signer_provider: Arc<dyn SignerProvider>,
    revocation_list_repository: Arc<dyn RevocationListRepository>,
}

impl SignatureService {
    pub(crate) fn new(
        signer_provider: Arc<dyn SignerProvider>,
        revocation_list_repository: Arc<dyn RevocationListRepository>,
    ) -> Self {
        Self {
            signer_provider,
            revocation_list_repository,
        }
    }
}
