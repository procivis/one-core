use std::sync::Arc;

use one_providers::credential_formatter::provider::CredentialFormatterProvider;
use one_providers::key_storage::provider::KeyProvider;
use one_providers::revocation::provider::RevocationMethodProvider;

use crate::config::core_config;
use crate::provider::exchange_protocol::provider::ExchangeProtocolProviderExtra;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::did_repository::DidRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::revocation_list_repository::RevocationListRepository;
use crate::repository::validity_credential_repository::ValidityCredentialRepository;

pub mod dto;
pub mod mapper;
pub mod service;

pub(crate) mod validator;

#[derive(Clone)]
pub struct CredentialService {
    credential_repository: Arc<dyn CredentialRepository>,
    credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    did_repository: Arc<dyn DidRepository>,
    history_repository: Arc<dyn HistoryRepository>,
    interaction_repository: Arc<dyn InteractionRepository>,
    revocation_list_repository: Arc<dyn RevocationListRepository>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    protocol_provider: Arc<dyn ExchangeProtocolProviderExtra>,
    key_provider: Arc<dyn KeyProvider>,
    config: Arc<core_config::CoreConfig>,
    validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
    base_url: Option<String>,
    client: reqwest::Client,
}

impl CredentialService {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        repository: Arc<dyn CredentialRepository>,
        credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
        did_repository: Arc<dyn DidRepository>,
        history_repository: Arc<dyn HistoryRepository>,
        interaction_repository: Arc<dyn InteractionRepository>,
        revocation_list_repository: Arc<dyn RevocationListRepository>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        protocol_provider: Arc<dyn ExchangeProtocolProviderExtra>,
        key_provider: Arc<dyn KeyProvider>,
        config: Arc<core_config::CoreConfig>,
        lvvc_repository: Arc<dyn ValidityCredentialRepository>,
        base_url: Option<String>,
        client: reqwest::Client,
    ) -> Self {
        Self {
            credential_repository: repository,
            credential_schema_repository,
            did_repository,
            history_repository,
            interaction_repository,
            revocation_list_repository,
            revocation_method_provider,
            formatter_provider,
            protocol_provider,
            key_provider,
            config,
            validity_credential_repository: lvvc_repository,
            base_url,
            client,
        }
    }
}

#[cfg(test)]
mod test;
