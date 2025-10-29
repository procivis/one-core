pub mod error;

// New traits
pub mod backup_repository;
pub mod blob_repository;
pub mod certificate_repository;
pub mod claim_repository;
pub mod claim_schema_repository;
pub mod credential_repository;
pub mod credential_schema_repository;
pub mod did_repository;
pub mod history_repository;
pub mod holder_wallet_unit_repository;
pub mod identifier_repository;
pub mod interaction_repository;
pub mod key_repository;
pub mod organisation_repository;
pub mod proof_repository;
pub mod proof_schema_repository;
pub mod remote_entity_cache_repository;
pub mod revocation_list_repository;
pub mod trust_anchor_repository;
pub mod trust_entity_repository;
pub mod validity_credential_repository;
pub mod wallet_unit_attestation_repository;
pub mod wallet_unit_attested_key_repository;
pub mod wallet_unit_repository;

use std::sync::Arc;

// New ones
use backup_repository::BackupRepository;
use blob_repository::BlobRepository;
use certificate_repository::CertificateRepository;
use claim_repository::ClaimRepository;
use claim_schema_repository::ClaimSchemaRepository;
use credential_repository::CredentialRepository;
use credential_schema_repository::CredentialSchemaRepository;
use did_repository::DidRepository;
use history_repository::HistoryRepository;
use holder_wallet_unit_repository::HolderWalletUnitRepository;
use identifier_repository::IdentifierRepository;
use interaction_repository::InteractionRepository;
use key_repository::KeyRepository;
use organisation_repository::OrganisationRepository;
use proof_repository::ProofRepository;
use proof_schema_repository::ProofSchemaRepository;
use remote_entity_cache_repository::RemoteEntityCacheRepository;
use revocation_list_repository::RevocationListRepository;
use trust_anchor_repository::TrustAnchorRepository;
use trust_entity_repository::TrustEntityRepository;
use validity_credential_repository::ValidityCredentialRepository;
use wallet_unit_attestation_repository::WalletUnitAttestationRepository;
use wallet_unit_repository::WalletUnitRepository;

use crate::proto::transaction_manager::TransactionManager;

pub trait DataRepository: Send + Sync {
    fn get_organisation_repository(&self) -> Arc<dyn OrganisationRepository>;
    fn get_did_repository(&self) -> Arc<dyn DidRepository>;
    fn get_certificate_repository(&self) -> Arc<dyn CertificateRepository>;
    fn get_claim_repository(&self) -> Arc<dyn ClaimRepository>;
    fn get_claim_schema_repository(&self) -> Arc<dyn ClaimSchemaRepository>;
    fn get_credential_repository(&self) -> Arc<dyn CredentialRepository>;
    fn get_credential_schema_repository(&self) -> Arc<dyn CredentialSchemaRepository>;
    fn get_history_repository(&self) -> Arc<dyn HistoryRepository>;
    fn get_identifier_repository(&self) -> Arc<dyn IdentifierRepository>;
    fn get_interaction_repository(&self) -> Arc<dyn InteractionRepository>;
    fn get_key_repository(&self) -> Arc<dyn KeyRepository>;
    fn get_proof_schema_repository(&self) -> Arc<dyn ProofSchemaRepository>;
    fn get_proof_repository(&self) -> Arc<dyn ProofRepository>;
    fn get_remote_entity_cache_repository(&self) -> Arc<dyn RemoteEntityCacheRepository>;
    fn get_revocation_list_repository(&self) -> Arc<dyn RevocationListRepository>;
    fn get_validity_credential_repository(&self) -> Arc<dyn ValidityCredentialRepository>;
    fn get_backup_repository(&self) -> Arc<dyn BackupRepository>;
    fn get_trust_anchor_repository(&self) -> Arc<dyn TrustAnchorRepository>;
    fn get_trust_entity_repository(&self) -> Arc<dyn TrustEntityRepository>;
    fn get_blob_repository(&self) -> Arc<dyn BlobRepository>;
    fn get_wallet_unit_repository(&self) -> Arc<dyn WalletUnitRepository>;

    fn get_holder_wallet_unit_repository(&self) -> Arc<dyn HolderWalletUnitRepository>;
    fn get_wallet_unit_attestation_repository(&self) -> Arc<dyn WalletUnitAttestationRepository>;

    fn get_tx_manager(&self) -> Arc<dyn TransactionManager>;
}
