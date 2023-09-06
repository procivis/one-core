pub mod error;

// Old traits. FIXME: Remove one day
pub mod data_provider;

// New traits
pub mod claim_repository;
pub mod claim_schema_repository;
pub mod credential_schema_repository;
pub mod did_repository;
pub mod organisation_repository;
pub mod proof_repository;
pub mod proof_schema_repository;

use std::sync::Arc;

// Old one
use data_provider::DataProvider;

// New ones
use claim_repository::ClaimRepository;
use claim_schema_repository::ClaimSchemaRepository;
use credential_schema_repository::CredentialSchemaRepository;
use did_repository::DidRepository;
use organisation_repository::OrganisationRepository;
use proof_repository::ProofRepository;
use proof_schema_repository::ProofSchemaRepository;

pub trait DataRepository {
    fn get_data_provider(&self) -> Arc<dyn DataProvider + Send + Sync>;
    fn get_organisation_repository(&self) -> Arc<dyn OrganisationRepository + Send + Sync>;
    fn get_did_repository(&self) -> Arc<dyn DidRepository + Send + Sync>;
    fn get_claim_repository(&self) -> Arc<dyn ClaimRepository + Send + Sync>;
    fn get_claim_schema_repository(&self) -> Arc<dyn ClaimSchemaRepository + Send + Sync>;
    fn get_credential_schema_repository(&self)
        -> Arc<dyn CredentialSchemaRepository + Send + Sync>;
    fn get_proof_schema_repository(&self) -> Arc<dyn ProofSchemaRepository + Send + Sync>;
    fn get_proof_repository(&self) -> Arc<dyn ProofRepository + Send + Sync>;
}

#[cfg(any(test, feature = "mock"))]
pub mod mock;
