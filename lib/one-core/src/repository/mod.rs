pub mod error;

// New traits
pub mod claim_repository;
pub mod claim_schema_repository;
pub mod credential_repository;
pub mod credential_schema_repository;
pub mod did_repository;
pub mod interaction_repository;
pub mod key_repository;
pub mod organisation_repository;
pub mod proof_repository;
pub mod proof_schema_repository;
pub mod revocation_list_repository;

use std::sync::Arc;

// New ones
use claim_repository::ClaimRepository;
use claim_schema_repository::ClaimSchemaRepository;
use credential_repository::CredentialRepository;
use credential_schema_repository::CredentialSchemaRepository;
use did_repository::DidRepository;
use key_repository::KeyRepository;
use organisation_repository::OrganisationRepository;
use proof_repository::ProofRepository;
use proof_schema_repository::ProofSchemaRepository;
use revocation_list_repository::RevocationListRepository;

use self::interaction_repository::InteractionRepository;

pub trait DataRepository {
    fn get_organisation_repository(&self) -> Arc<dyn OrganisationRepository + Send + Sync>;
    fn get_did_repository(&self) -> Arc<dyn DidRepository + Send + Sync>;
    fn get_claim_repository(&self) -> Arc<dyn ClaimRepository + Send + Sync>;
    fn get_claim_schema_repository(&self) -> Arc<dyn ClaimSchemaRepository + Send + Sync>;
    fn get_credential_repository(&self) -> Arc<dyn CredentialRepository + Send + Sync>;
    fn get_credential_schema_repository(&self)
        -> Arc<dyn CredentialSchemaRepository + Send + Sync>;
    fn get_key_repository(&self) -> Arc<dyn KeyRepository + Send + Sync>;
    fn get_proof_schema_repository(&self) -> Arc<dyn ProofSchemaRepository + Send + Sync>;
    fn get_proof_repository(&self) -> Arc<dyn ProofRepository + Send + Sync>;
    fn get_interaction_repository(&self) -> Arc<dyn InteractionRepository + Send + Sync>;
    fn get_revocation_list_repository(&self) -> Arc<dyn RevocationListRepository + Send + Sync>;
}

#[cfg(any(test, feature = "mock"))]
pub mod mock;
