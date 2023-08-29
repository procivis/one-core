pub mod error;

// Old traits. FIXME: Remove one day
pub mod data_provider;

// New traits
pub mod claim_schema_repository;
pub mod did_repository;
pub mod organisation_repository;

use std::sync::Arc;

// Old one
use data_provider::DataProvider;

// New ones
use claim_schema_repository::ClaimSchemaRepository;
use did_repository::DidRepository;
use organisation_repository::OrganisationRepository;

pub trait DataRepository {
    fn get_data_provider(&self) -> Arc<dyn DataProvider + Send + Sync>;
    fn get_organisation_repository(&self) -> Arc<dyn OrganisationRepository + Send + Sync>;
    fn get_did_repository(&self) -> Arc<dyn DidRepository + Send + Sync>;
    fn get_claim_schema_repository(&self) -> Arc<dyn ClaimSchemaRepository + Send + Sync>;
}

#[cfg(test)]
pub mod mock;
