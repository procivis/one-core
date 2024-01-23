use std::sync::Arc;

use crate::{
    config::core_config,
    provider::transport_protocol::provider::TransportProtocolProvider,
    repository::{
        credential_repository::CredentialRepository,
        credential_schema_repository::CredentialSchemaRepository, did_repository::DidRepository,
    },
};

pub mod dto;
mod mapper;
pub mod service;

#[cfg(test)]
mod test;

#[derive(Clone)]
pub struct SSIIssuerService {
    credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    credential_repository: Arc<dyn CredentialRepository>,
    did_repository: Arc<dyn DidRepository>,
    protocol_provider: Arc<dyn TransportProtocolProvider>,
    config: Arc<core_config::CoreConfig>,
    core_base_url: Option<String>,
}

impl SSIIssuerService {
    pub(crate) fn new(
        credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
        credential_repository: Arc<dyn CredentialRepository>,
        did_repository: Arc<dyn DidRepository>,
        protocol_provider: Arc<dyn TransportProtocolProvider>,
        config: Arc<core_config::CoreConfig>,
        core_base_url: Option<String>,
    ) -> Self {
        Self {
            credential_schema_repository,
            credential_repository,
            did_repository,
            protocol_provider,
            config,
            core_base_url,
        }
    }
}
