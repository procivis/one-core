pub mod error;

// New traits
pub mod backup_repository;
pub mod claim_repository;
pub mod claim_schema_repository;
pub mod credential_repository;
pub mod credential_schema_repository;
pub mod did_repository;
pub mod history_repository;
pub mod interaction_repository;
pub mod key_repository;
pub mod lvvc_repository;
pub mod organisation_repository;
pub mod proof_repository;
pub mod proof_schema_repository;
pub mod revocation_list_repository;

use std::sync::Arc;

// New ones
use backup_repository::BackupRepository;
use claim_repository::ClaimRepository;
use claim_schema_repository::ClaimSchemaRepository;
use credential_repository::CredentialRepository;
use credential_schema_repository::CredentialSchemaRepository;
use did_repository::DidRepository;
use history_repository::HistoryRepository;
use interaction_repository::InteractionRepository;
use key_repository::KeyRepository;
use lvvc_repository::LvvcRepository;
use organisation_repository::OrganisationRepository;
use proof_repository::ProofRepository;
use proof_schema_repository::ProofSchemaRepository;
use revocation_list_repository::RevocationListRepository;

pub trait DataRepository {
    fn get_organisation_repository(&self) -> Arc<dyn OrganisationRepository>;
    fn get_did_repository(&self) -> Arc<dyn DidRepository>;
    fn get_claim_repository(&self) -> Arc<dyn ClaimRepository>;
    fn get_claim_schema_repository(&self) -> Arc<dyn ClaimSchemaRepository>;
    fn get_credential_repository(&self) -> Arc<dyn CredentialRepository>;
    fn get_credential_schema_repository(&self) -> Arc<dyn CredentialSchemaRepository>;
    fn get_history_repository(&self) -> Arc<dyn HistoryRepository>;
    fn get_key_repository(&self) -> Arc<dyn KeyRepository>;
    fn get_proof_schema_repository(&self) -> Arc<dyn ProofSchemaRepository>;
    fn get_proof_repository(&self) -> Arc<dyn ProofRepository>;
    fn get_interaction_repository(&self) -> Arc<dyn InteractionRepository>;
    fn get_revocation_list_repository(&self) -> Arc<dyn RevocationListRepository>;
    fn get_lvvc_repository(&self) -> Arc<dyn LvvcRepository>;
    fn get_backup_repository(&self) -> Arc<dyn BackupRepository>;
}

#[cfg(any(test, feature = "mock"))]
pub mod mock;
