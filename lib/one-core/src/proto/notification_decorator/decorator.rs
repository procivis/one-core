use std::sync::Arc;

use super::credential::CredentialNotificationDecorator;
use super::proof::ProofNotificationDecorator;
use crate::config::core_config::CoreConfig;
use crate::proto::notification_scheduler::NotificationScheduler;
use crate::proto::transaction_manager::TransactionManager;
use crate::repository::DataRepository;
use crate::repository::backup_repository::BackupRepository;
use crate::repository::blob_repository::BlobRepository;
use crate::repository::certificate_repository::CertificateRepository;
use crate::repository::claim_repository::ClaimRepository;
use crate::repository::claim_schema_repository::ClaimSchemaRepository;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::did_repository::DidRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::holder_wallet_unit_repository::HolderWalletUnitRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::key_repository::KeyRepository;
use crate::repository::notification_repository::NotificationRepository;
use crate::repository::organisation_repository::OrganisationRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::repository::proof_schema_repository::ProofSchemaRepository;
use crate::repository::remote_entity_cache_repository::RemoteEntityCacheRepository;
use crate::repository::revocation_list_repository::RevocationListRepository;
use crate::repository::trust_anchor_repository::TrustAnchorRepository;
use crate::repository::trust_collection_repository::TrustCollectionRepository;
use crate::repository::trust_entity_repository::TrustEntityRepository;
use crate::repository::trust_entry_repository::TrustEntryRepository;
use crate::repository::trust_list_publication_repository::TrustListPublicationRepository;
use crate::repository::trust_list_subscription_repository::TrustListSubscriptionRepository;
use crate::repository::validity_credential_repository::ValidityCredentialRepository;
use crate::repository::verifier_instance_repository::VerifierInstanceRepository;
use crate::repository::wallet_unit_attestation_repository::WalletUnitAttestationRepository;
use crate::repository::wallet_unit_attested_key_repository::WalletUnitAttestedKeyRepository;
use crate::repository::wallet_unit_repository::WalletUnitRepository;

struct DecoratedDataProvider {
    // for non-decorated repositories
    data_provider: Arc<dyn DataRepository>,

    // decorated repositories
    credential_repository: Arc<dyn CredentialRepository>,
    proof_repository: Arc<dyn ProofRepository>,
}

impl DataRepository for DecoratedDataProvider {
    // decorated

    fn get_credential_repository(&self) -> Arc<dyn CredentialRepository> {
        self.credential_repository.clone()
    }
    fn get_proof_repository(&self) -> Arc<dyn ProofRepository> {
        self.proof_repository.clone()
    }

    // non-decorated
    fn get_organisation_repository(&self) -> Arc<dyn OrganisationRepository> {
        self.data_provider.get_organisation_repository()
    }
    fn get_did_repository(&self) -> Arc<dyn DidRepository> {
        self.data_provider.get_did_repository()
    }
    fn get_certificate_repository(&self) -> Arc<dyn CertificateRepository> {
        self.data_provider.get_certificate_repository()
    }
    fn get_credential_schema_repository(&self) -> Arc<dyn CredentialSchemaRepository> {
        self.data_provider.get_credential_schema_repository()
    }
    fn get_identifier_repository(&self) -> Arc<dyn IdentifierRepository> {
        self.data_provider.get_identifier_repository()
    }
    fn get_key_repository(&self) -> Arc<dyn KeyRepository> {
        self.data_provider.get_key_repository()
    }
    fn get_proof_schema_repository(&self) -> Arc<dyn ProofSchemaRepository> {
        self.data_provider.get_proof_schema_repository()
    }
    fn get_trust_entity_repository(&self) -> Arc<dyn TrustEntityRepository> {
        self.data_provider.get_trust_entity_repository()
    }
    fn get_claim_repository(&self) -> Arc<dyn ClaimRepository> {
        self.data_provider.get_claim_repository()
    }
    fn get_claim_schema_repository(&self) -> Arc<dyn ClaimSchemaRepository> {
        self.data_provider.get_claim_schema_repository()
    }
    fn get_history_repository(&self) -> Arc<dyn HistoryRepository> {
        self.data_provider.get_history_repository()
    }
    fn get_interaction_repository(&self) -> Arc<dyn InteractionRepository> {
        self.data_provider.get_interaction_repository()
    }
    fn get_remote_entity_cache_repository(&self) -> Arc<dyn RemoteEntityCacheRepository> {
        self.data_provider.get_remote_entity_cache_repository()
    }
    fn get_revocation_list_repository(&self) -> Arc<dyn RevocationListRepository> {
        self.data_provider.get_revocation_list_repository()
    }
    fn get_validity_credential_repository(&self) -> Arc<dyn ValidityCredentialRepository> {
        self.data_provider.get_validity_credential_repository()
    }
    fn get_backup_repository(&self) -> Arc<dyn BackupRepository> {
        self.data_provider.get_backup_repository()
    }
    fn get_trust_anchor_repository(&self) -> Arc<dyn TrustAnchorRepository> {
        self.data_provider.get_trust_anchor_repository()
    }
    fn get_trust_entry_repository(&self) -> Arc<dyn TrustEntryRepository> {
        self.data_provider.get_trust_entry_repository()
    }
    fn get_trust_list_publication_repository(&self) -> Arc<dyn TrustListPublicationRepository> {
        self.data_provider.get_trust_list_publication_repository()
    }
    fn get_blob_repository(&self) -> Arc<dyn BlobRepository> {
        self.data_provider.get_blob_repository()
    }
    fn get_wallet_unit_repository(&self) -> Arc<dyn WalletUnitRepository> {
        self.data_provider.get_wallet_unit_repository()
    }
    fn get_notification_repository(&self) -> Arc<dyn NotificationRepository> {
        self.data_provider.get_notification_repository()
    }
    fn get_holder_wallet_unit_repository(&self) -> Arc<dyn HolderWalletUnitRepository> {
        self.data_provider.get_holder_wallet_unit_repository()
    }
    fn get_verifier_instance_repository(&self) -> Arc<dyn VerifierInstanceRepository> {
        self.data_provider.get_verifier_instance_repository()
    }
    fn get_wallet_unit_attestation_repository(&self) -> Arc<dyn WalletUnitAttestationRepository> {
        self.data_provider.get_wallet_unit_attestation_repository()
    }
    fn get_wallet_unit_attested_key_repository(&self) -> Arc<dyn WalletUnitAttestedKeyRepository> {
        self.data_provider.get_wallet_unit_attested_key_repository()
    }
    fn get_trust_collection_repository(&self) -> Arc<dyn TrustCollectionRepository> {
        self.data_provider.get_trust_collection_repository()
    }

    fn get_trust_list_subscription_repository(&self) -> Arc<dyn TrustListSubscriptionRepository> {
        self.data_provider.get_trust_list_subscription_repository()
    }

    fn get_tx_manager(&self) -> Arc<dyn TransactionManager> {
        self.data_provider.get_tx_manager()
    }
}

pub(crate) fn decorate_data_provider(
    data_provider: Arc<dyn DataRepository>,
    notification_scheduler: Arc<dyn NotificationScheduler>,
    config: Arc<CoreConfig>,
) -> Arc<dyn DataRepository> {
    let credential_repository = Arc::new(CredentialNotificationDecorator {
        inner: data_provider.get_credential_repository(),
        notification_scheduler: notification_scheduler.clone(),
        config: config.clone(),
    });

    let proof_repository = Arc::new(ProofNotificationDecorator {
        inner: data_provider.get_proof_repository(),
        notification_scheduler: notification_scheduler.clone(),
        config,
    });

    Arc::new(DecoratedDataProvider {
        data_provider,
        credential_repository,
        proof_repository,
    })
}
