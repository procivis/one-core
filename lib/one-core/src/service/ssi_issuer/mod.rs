use crate::{
    credential_formatter::provider::CredentialFormatterProvider,
    repository::{credential_repository::CredentialRepository, did_repository::DidRepository},
};
use std::sync::Arc;

pub mod dto;
pub mod service;

#[derive(Clone)]
pub struct SSIIssuerService {
    credential_repository: Arc<dyn CredentialRepository + Send + Sync>,
    did_repository: Arc<dyn DidRepository + Send + Sync>,
    formatter_provider: Arc<dyn CredentialFormatterProvider + Send + Sync>,
}

impl SSIIssuerService {
    pub(crate) fn new(
        credential_repository: Arc<dyn CredentialRepository + Send + Sync>,
        did_repository: Arc<dyn DidRepository + Send + Sync>,
        formatter_provider: Arc<dyn CredentialFormatterProvider + Send + Sync>,
    ) -> Self {
        Self {
            credential_repository,
            did_repository,
            formatter_provider,
        }
    }
}
