pub mod error;

// New traits
pub mod backup_repository;
pub mod blob_repository;
pub mod certificate_repository;
pub mod claim_repository;
pub mod claim_schema_repository;
pub mod credential_repository;
pub mod credential_schema_format_repository;
pub mod credential_schema_repository;
pub mod did_repository;
pub mod history_repository;
pub mod identifier_repository;
pub mod identifier_trust_information_repository;
pub mod instance_repository;
pub mod interaction_repository;
pub mod key_repository;
pub mod localized_text_repository;
pub mod managed_instance_attestation_repository;
pub mod managed_instance_repository;
pub mod notification_repository;
pub mod organisation_repository;
pub mod proof_repository;
pub mod proof_schema_repository;
pub mod remote_entity_cache_repository;
pub mod revocation_list_repository;
pub mod trust_collection_repository;
pub mod trust_entry_repository;
pub mod trust_list_publication_repository;
pub mod trust_list_subscription_repository;
pub mod wallet_attestation_repository;

use std::sync::Arc;

// New ones
use backup_repository::BackupRepository;
use blob_repository::BlobRepository;
use certificate_repository::CertificateRepository;
use claim_repository::ClaimRepository;
use claim_schema_repository::ClaimSchemaRepository;
use credential_repository::CredentialRepository;
use credential_schema_format_repository::CredentialSchemaFormatRepository;
use credential_schema_repository::CredentialSchemaRepository;
use did_repository::DidRepository;
use history_repository::HistoryRepository;
use identifier_repository::IdentifierRepository;
use identifier_trust_information_repository::IdentifierTrustInformationRepository;
use instance_repository::InstanceRepository;
use interaction_repository::InteractionRepository;
use key_repository::KeyRepository;
use managed_instance_attestation_repository::ManagedInstanceAttestationRepository;
use managed_instance_repository::ManagedInstanceRepository;
use notification_repository::NotificationRepository;
use organisation_repository::OrganisationRepository;
use proof_repository::ProofRepository;
use proof_schema_repository::ProofSchemaRepository;
use remote_entity_cache_repository::RemoteEntityCacheRepository;
use revocation_list_repository::RevocationListRepository;
use trust_collection_repository::TrustCollectionRepository;
use trust_entry_repository::TrustEntryRepository;
use trust_list_publication_repository::TrustListPublicationRepository;
use trust_list_subscription_repository::TrustListSubscriptionRepository;
use wallet_attestation_repository::WalletAttestationRepository;

use crate::proto::transaction_manager::TransactionManager;
use crate::repository::localized_text_repository::LocalizedTextRepository;

pub trait DataRepository: Send + Sync {
    fn get_organisation_repository(&self) -> Arc<dyn OrganisationRepository>;
    fn get_did_repository(&self) -> Arc<dyn DidRepository>;
    fn get_certificate_repository(&self) -> Arc<dyn CertificateRepository>;
    fn get_claim_repository(&self) -> Arc<dyn ClaimRepository>;
    fn get_claim_schema_repository(&self) -> Arc<dyn ClaimSchemaRepository>;
    fn get_credential_repository(&self) -> Arc<dyn CredentialRepository>;
    fn get_credential_schema_repository(&self) -> Arc<dyn CredentialSchemaRepository>;
    fn get_credential_schema_format_repository(&self) -> Arc<dyn CredentialSchemaFormatRepository>;
    fn get_history_repository(&self) -> Arc<dyn HistoryRepository>;
    fn get_identifier_repository(&self) -> Arc<dyn IdentifierRepository>;
    fn get_identifier_trust_information_repository(
        &self,
    ) -> Arc<dyn IdentifierTrustInformationRepository>;
    fn get_interaction_repository(&self) -> Arc<dyn InteractionRepository>;
    fn get_key_repository(&self) -> Arc<dyn KeyRepository>;
    fn get_proof_schema_repository(&self) -> Arc<dyn ProofSchemaRepository>;
    fn get_proof_repository(&self) -> Arc<dyn ProofRepository>;
    fn get_remote_entity_cache_repository(&self) -> Arc<dyn RemoteEntityCacheRepository>;
    fn get_revocation_list_repository(&self) -> Arc<dyn RevocationListRepository>;
    fn get_backup_repository(&self) -> Arc<dyn BackupRepository>;
    fn get_trust_collection_repository(&self) -> Arc<dyn TrustCollectionRepository>;
    fn get_trust_entry_repository(&self) -> Arc<dyn TrustEntryRepository>;
    fn get_trust_list_publication_repository(&self) -> Arc<dyn TrustListPublicationRepository>;
    fn get_trust_list_subscription_repository(&self) -> Arc<dyn TrustListSubscriptionRepository>;
    fn get_blob_repository(&self) -> Arc<dyn BlobRepository>;
    fn get_managed_instance_repository(&self) -> Arc<dyn ManagedInstanceRepository>;
    fn get_notification_repository(&self) -> Arc<dyn NotificationRepository>;
    fn get_instance_repository(&self) -> Arc<dyn InstanceRepository>;
    fn get_wallet_attestation_repository(&self) -> Arc<dyn WalletAttestationRepository>;
    fn get_managed_instance_attestation_repository(
        &self,
    ) -> Arc<dyn ManagedInstanceAttestationRepository>;
    fn get_localized_text_repository(&self) -> Arc<dyn LocalizedTextRepository>;
    fn get_tx_manager(&self) -> Arc<dyn TransactionManager>;
}
