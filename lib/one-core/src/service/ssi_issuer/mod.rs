use std::sync::Arc;

use crate::provider::transport_protocol::provider::TransportProtocolProvider;
use crate::repository::{
    credential_repository::CredentialRepository, did_repository::DidRepository,
};

pub mod dto;
pub mod service;

#[cfg(test)]
mod test;

#[derive(Clone)]
pub struct SSIIssuerService {
    credential_repository: Arc<dyn CredentialRepository>,
    did_repository: Arc<dyn DidRepository>,
    protocol_provider: Arc<dyn TransportProtocolProvider + Send + Sync>,
}

impl SSIIssuerService {
    pub(crate) fn new(
        credential_repository: Arc<dyn CredentialRepository>,
        did_repository: Arc<dyn DidRepository>,
        protocol_provider: Arc<dyn TransportProtocolProvider + Send + Sync>,
    ) -> Self {
        Self {
            credential_repository,
            did_repository,
            protocol_provider,
        }
    }
}
