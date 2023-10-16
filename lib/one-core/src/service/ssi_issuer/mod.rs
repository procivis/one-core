use std::sync::Arc;

use crate::{
    credential_formatter::provider::CredentialFormatterProvider,
    repository::{credential_repository::CredentialRepository, did_repository::DidRepository},
    revocation::provider::RevocationMethodProvider,
};

pub mod dto;
pub mod mapper;
pub mod service;

#[derive(Clone)]
pub struct SSIIssuerService {
    credential_repository: Arc<dyn CredentialRepository + Send + Sync>,
    did_repository: Arc<dyn DidRepository + Send + Sync>,
    formatter_provider: Arc<dyn CredentialFormatterProvider + Send + Sync>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider + Send + Sync>,
}

impl SSIIssuerService {
    pub(crate) fn new(
        credential_repository: Arc<dyn CredentialRepository + Send + Sync>,
        did_repository: Arc<dyn DidRepository + Send + Sync>,
        formatter_provider: Arc<dyn CredentialFormatterProvider + Send + Sync>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider + Send + Sync>,
    ) -> Self {
        Self {
            credential_repository,
            did_repository,
            formatter_provider,
            revocation_method_provider,
        }
    }
}
