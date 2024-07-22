use crate::{
    config::core_config,
    repository::{
        credential_repository::CredentialRepository, did_repository::DidRepository,
        history_repository::HistoryRepository, proof_repository::ProofRepository,
    },
};
use one_providers::key_algorithm::provider::KeyAlgorithmProvider;
use one_providers::revocation::provider::RevocationMethodProvider;
use one_providers::{
    credential_formatter::provider::CredentialFormatterProvider, did::provider::DidMethodProvider,
};
use std::sync::Arc;

pub mod dto;
pub mod service;

mod mapper;
mod validator;

#[cfg(test)]
mod test;

#[allow(unused)]
#[derive(Clone)]
pub struct SSIVerifierService {
    credential_repository: Arc<dyn CredentialRepository>,
    proof_repository: Arc<dyn ProofRepository>,
    did_repository: Arc<dyn DidRepository>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    history_repository: Arc<dyn HistoryRepository>,
    config: Arc<core_config::CoreConfig>,
}

#[allow(clippy::too_many_arguments)]
impl SSIVerifierService {
    pub(crate) fn new(
        credential_repository: Arc<dyn CredentialRepository>,
        proof_repository: Arc<dyn ProofRepository>,
        did_repository: Arc<dyn DidRepository>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        history_repository: Arc<dyn HistoryRepository>,
        config: Arc<core_config::CoreConfig>,
    ) -> Self {
        Self {
            proof_repository,
            did_repository,
            credential_repository,
            formatter_provider,
            did_method_provider,
            revocation_method_provider,
            key_algorithm_provider,
            history_repository,
            config,
        }
    }
}
