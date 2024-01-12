use std::sync::Arc;

use crate::{
    config::core_config,
    provider::transport_protocol::provider::TransportProtocolProvider,
    repository::{credential_repository::CredentialRepository, did_repository::DidRepository},
};

pub mod dto;
pub mod service;

#[cfg(test)]
mod test;

#[derive(Clone)]
pub struct SSIIssuerService {
    credential_repository: Arc<dyn CredentialRepository>,
    did_repository: Arc<dyn DidRepository>,
    protocol_provider: Arc<dyn TransportProtocolProvider>,
    config: Arc<core_config::CoreConfig>,
}

impl SSIIssuerService {
    pub(crate) fn new(
        credential_repository: Arc<dyn CredentialRepository>,
        did_repository: Arc<dyn DidRepository>,
        protocol_provider: Arc<dyn TransportProtocolProvider>,
        config: Arc<core_config::CoreConfig>,
    ) -> Self {
        Self {
            credential_repository,
            did_repository,
            protocol_provider,
            config,
        }
    }
}
