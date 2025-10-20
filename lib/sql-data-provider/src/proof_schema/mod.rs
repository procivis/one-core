use std::sync::Arc;

use one_core::repository::claim_schema_repository::ClaimSchemaRepository;
use one_core::repository::credential_schema_repository::CredentialSchemaRepository;
use one_core::repository::organisation_repository::OrganisationRepository;

use crate::transaction_context::TransactionProvider;

mod mapper;
pub mod repository;

pub(crate) struct ProofSchemaProvider {
    pub db: Arc<dyn TransactionProvider>,
    pub claim_schema_repository: Arc<dyn ClaimSchemaRepository>,
    pub organisation_repository: Arc<dyn OrganisationRepository>,
    pub credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
}

#[cfg(test)]
mod test;
