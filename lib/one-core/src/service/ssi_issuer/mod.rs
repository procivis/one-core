use std::sync::Arc;

use crate::{
    config::data_structure::CoreConfig,
    crypto::Crypto,
    provider::{
        credential_formatter::provider::CredentialFormatterProvider,
        key_storage::provider::KeyProvider,
    },
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
    key_provider: Arc<dyn KeyProvider + Send + Sync>,
    formatter_provider: Arc<dyn CredentialFormatterProvider + Send + Sync>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider + Send + Sync>,
    crypto: Crypto,
    config: Arc<CoreConfig>,
}

impl SSIIssuerService {
    pub(crate) fn new(
        credential_repository: Arc<dyn CredentialRepository + Send + Sync>,
        did_repository: Arc<dyn DidRepository + Send + Sync>,
        key_provider: Arc<dyn KeyProvider + Send + Sync>,
        formatter_provider: Arc<dyn CredentialFormatterProvider + Send + Sync>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider + Send + Sync>,
        crypto: Crypto,
        config: Arc<CoreConfig>,
    ) -> Self {
        Self {
            credential_repository,
            did_repository,
            key_provider,
            formatter_provider,
            revocation_method_provider,
            crypto,
            config,
        }
    }
}
