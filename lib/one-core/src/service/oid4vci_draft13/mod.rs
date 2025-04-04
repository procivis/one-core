use std::sync::Arc;

use crate::config::core_config;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::issuance_protocol::provider::IssuanceProtocolProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::did_repository::DidRepository;
use crate::repository::interaction_repository::InteractionRepository;

pub mod dto;
pub mod mapper;
pub mod service;
pub mod validator;

#[derive(Clone)]
pub struct OID4VCIDraft13Service {
    pub(crate) core_base_url: Option<String>,
    credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    credential_repository: Arc<dyn CredentialRepository>,
    interaction_repository: Arc<dyn InteractionRepository>,
    config: Arc<core_config::CoreConfig>,
    protocol_provider: Arc<dyn IssuanceProtocolProvider>,
    did_repository: Arc<dyn DidRepository>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
}

#[allow(clippy::too_many_arguments)]
impl OID4VCIDraft13Service {
    pub(crate) fn new(
        core_base_url: Option<String>,
        credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
        credential_repository: Arc<dyn CredentialRepository>,
        interaction_repository: Arc<dyn InteractionRepository>,
        config: Arc<core_config::CoreConfig>,
        protocol_provider: Arc<dyn IssuanceProtocolProvider>,
        did_repository: Arc<dyn DidRepository>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    ) -> Self {
        Self {
            core_base_url,
            credential_schema_repository,
            credential_repository,
            interaction_repository,
            config,
            protocol_provider,
            did_repository,
            did_method_provider,
            key_algorithm_provider,
        }
    }
}

#[cfg(test)]
mod test;
