use std::sync::Arc;

use one_crypto::CryptoProvider;
use one_providers::credential_formatter::provider::CredentialFormatterProvider;
use one_providers::did::provider::DidMethodProvider;
use one_providers::key_algorithm::provider::KeyAlgorithmProvider;
use one_providers::key_storage::provider::KeyProvider;
use one_providers::revocation::provider::RevocationMethodProvider;

use crate::config::core_config;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::revocation_list_repository::RevocationListRepository;
use crate::repository::validity_credential_repository::ValidityCredentialRepository;

pub mod dto;
pub mod service;

mod mapper;
mod validator;

#[derive(Clone)]
pub struct RevocationListService {
    core_base_url: Option<String>,
    credential_repository: Arc<dyn CredentialRepository>,
    lvvc_repository: Arc<dyn ValidityCredentialRepository>,
    revocation_list_repository: Arc<dyn RevocationListRepository>,
    crypto_provider: Arc<dyn CryptoProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    config: Arc<core_config::CoreConfig>,
}

impl RevocationListService {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        core_base_url: Option<String>,
        credential_repository: Arc<dyn CredentialRepository>,
        lvvc_repository: Arc<dyn ValidityCredentialRepository>,
        revocation_list_repository: Arc<dyn RevocationListRepository>,
        crypto_provider: Arc<dyn CryptoProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        key_provider: Arc<dyn KeyProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider>,
        config: Arc<core_config::CoreConfig>,
    ) -> Self {
        Self {
            core_base_url,
            credential_repository,
            lvvc_repository,
            revocation_list_repository,
            crypto_provider,
            did_method_provider,
            formatter_provider,
            key_provider,
            key_algorithm_provider,
            revocation_method_provider,
            config,
        }
    }
}

#[cfg(test)]
mod test;
