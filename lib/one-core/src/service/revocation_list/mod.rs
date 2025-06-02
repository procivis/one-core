use std::sync::Arc;

use crate::config::core_config;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::revocation_list_repository::RevocationListRepository;
use crate::repository::validity_credential_repository::ValidityCredentialRepository;
use crate::service::certificate::validator::CertificateValidator;

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
    did_method_provider: Arc<dyn DidMethodProvider>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    config: Arc<core_config::CoreConfig>,
    certificate_validator: Arc<dyn CertificateValidator>,
}

impl RevocationListService {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        core_base_url: Option<String>,
        credential_repository: Arc<dyn CredentialRepository>,
        lvvc_repository: Arc<dyn ValidityCredentialRepository>,
        revocation_list_repository: Arc<dyn RevocationListRepository>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        key_provider: Arc<dyn KeyProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider>,
        config: Arc<core_config::CoreConfig>,
        certificate_validator: Arc<dyn CertificateValidator>,
    ) -> Self {
        Self {
            core_base_url,
            credential_repository,
            lvvc_repository,
            revocation_list_repository,
            did_method_provider,
            formatter_provider,
            key_provider,
            key_algorithm_provider,
            revocation_method_provider,
            certificate_validator,
            config,
        }
    }
}

#[cfg(test)]
mod test;
