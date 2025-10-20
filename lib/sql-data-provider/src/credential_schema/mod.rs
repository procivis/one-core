use std::sync::Arc;

use one_core::repository::claim_schema_repository::ClaimSchemaRepository;
use one_core::repository::organisation_repository::OrganisationRepository;

use crate::transaction_context::TransactionProvider;

pub mod mapper;
pub mod repository;

pub(crate) struct CredentialSchemaProvider {
    pub db: Arc<dyn TransactionProvider>,
    pub claim_schema_repository: Arc<dyn ClaimSchemaRepository>,
    pub organisation_repository: Arc<dyn OrganisationRepository>,
}

#[cfg(test)]
mod test;
