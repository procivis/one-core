use std::sync::Arc;

use one_core::repository::claim_schema_repository::ClaimSchemaRepository;
use one_core::repository::organisation_repository::OrganisationRepository;

use crate::transaction_context::TransactionManagerImpl;

pub mod mapper;
pub mod repository;

pub(crate) struct CredentialSchemaProvider {
    pub db: TransactionManagerImpl,
    pub claim_schema_repository: Arc<dyn ClaimSchemaRepository>,
    pub organisation_repository: Arc<dyn OrganisationRepository>,
}

#[cfg(test)]
mod test;
