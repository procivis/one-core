use crate::config::core_config;
use crate::repository::{
    credential_schema_repository::CredentialSchemaRepository,
    history_repository::HistoryRepository, organisation_repository::OrganisationRepository,
    proof_schema_repository::ProofSchemaRepository,
};
use std::sync::Arc;

pub mod dto;
pub mod service;

mod mapper;
mod validator;

#[derive(Clone)]
pub struct ProofSchemaService {
    proof_schema_repository: Arc<dyn ProofSchemaRepository>,
    credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    organisation_repository: Arc<dyn OrganisationRepository>,
    history_repository: Arc<dyn HistoryRepository>,
    config: Arc<core_config::CoreConfig>,
}

impl ProofSchemaService {
    pub fn new(
        proof_schema_repository: Arc<dyn ProofSchemaRepository>,
        credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
        organisation_repository: Arc<dyn OrganisationRepository>,
        history_repository: Arc<dyn HistoryRepository>,
        config: Arc<core_config::CoreConfig>,
    ) -> Self {
        Self {
            proof_schema_repository,
            organisation_repository,
            history_repository,
            credential_schema_repository,
            config,
        }
    }
}

#[cfg(test)]
mod test;
