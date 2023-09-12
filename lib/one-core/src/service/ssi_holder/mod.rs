use crate::{
    credential_formatter::provider::CredentialFormatterProvider,
    repository::{
        credential_repository::CredentialRepository,
        credential_schema_repository::CredentialSchemaRepository, did_repository::DidRepository,
        organisation_repository::OrganisationRepository,
    },
    transport_protocol::provider::TransportProtocolProvider,
};
use std::sync::Arc;

pub mod dto;
pub mod service;

mod mapper;

#[derive(Clone)]
pub struct SSIHolderService {
    organisation_repository: Arc<dyn OrganisationRepository + Send + Sync>,
    credential_schema_repository: Arc<dyn CredentialSchemaRepository + Send + Sync>,
    credential_repository: Arc<dyn CredentialRepository + Send + Sync>,
    did_repository: Arc<dyn DidRepository + Send + Sync>,
    formatter_provider: Arc<dyn CredentialFormatterProvider + Send + Sync>,
    protocol_provider: Arc<dyn TransportProtocolProvider + Send + Sync>,
}

impl SSIHolderService {
    pub(crate) fn new(
        organisation_repository: Arc<dyn OrganisationRepository + Send + Sync>,
        credential_schema_repository: Arc<dyn CredentialSchemaRepository + Send + Sync>,
        credential_repository: Arc<dyn CredentialRepository + Send + Sync>,
        did_repository: Arc<dyn DidRepository + Send + Sync>,
        formatter_provider: Arc<dyn CredentialFormatterProvider + Send + Sync>,
        protocol_provider: Arc<dyn TransportProtocolProvider + Send + Sync>,
    ) -> Self {
        Self {
            organisation_repository,
            credential_schema_repository,
            credential_repository,
            did_repository,
            formatter_provider,
            protocol_provider,
        }
    }
}
