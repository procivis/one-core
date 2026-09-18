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
use crate::repository::credential_schema_format_repository::CredentialSchemaFormatRepository;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::did_repository::DidRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::identifier_trust_information_repository::IdentifierTrustInformationRepository;
use crate::repository::instance_repository::InstanceRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::key_repository::KeyRepository;
use crate::repository::localized_text_repository::LocalizedTextRepository;
use crate::repository::managed_instance_attestation_repository::ManagedInstanceAttestationRepository;
use crate::repository::managed_instance_repository::ManagedInstanceRepository;
use crate::repository::notification_repository::NotificationRepository;
use crate::repository::organisation_repository::OrganisationRepository;
use crate::repository::proof_repository::ProofRepository;
use crate::repository::proof_schema_repository::ProofSchemaRepository;
use crate::repository::remote_entity_cache_repository::RemoteEntityCacheRepository;
use crate::repository::revocation_list_repository::RevocationListRepository;
use crate::repository::trust_collection_repository::TrustCollectionRepository;
use crate::repository::trust_entry_repository::TrustEntryRepository;
use crate::repository::trust_list_publication_repository::TrustListPublicationRepository;
use crate::repository::trust_list_subscription_repository::TrustListSubscriptionRepository;
use crate::repository::wallet_attestation_repository::WalletAttestationRepository;

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
    fn get_credential_schema_format_repository(&self) -> Arc<dyn CredentialSchemaFormatRepository> {
        self.data_provider.get_credential_schema_format_repository()
    }
    fn get_identifier_repository(&self) -> Arc<dyn IdentifierRepository> {
        self.data_provider.get_identifier_repository()
    }
    fn get_identifier_trust_information_repository(
        &self,
    ) -> Arc<dyn IdentifierTrustInformationRepository> {
        self.data_provider
            .get_identifier_trust_information_repository()
    }
    fn get_key_repository(&self) -> Arc<dyn KeyRepository> {
        self.data_provider.get_key_repository()
    }
    fn get_proof_schema_repository(&self) -> Arc<dyn ProofSchemaRepository> {
        self.data_provider.get_proof_schema_repository()
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
    fn get_backup_repository(&self) -> Arc<dyn BackupRepository> {
        self.data_provider.get_backup_repository()
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
    fn get_managed_instance_repository(&self) -> Arc<dyn ManagedInstanceRepository> {
        self.data_provider.get_managed_instance_repository()
    }
    fn get_notification_repository(&self) -> Arc<dyn NotificationRepository> {
        self.data_provider.get_notification_repository()
    }
    fn get_instance_repository(&self) -> Arc<dyn InstanceRepository> {
        self.data_provider.get_instance_repository()
    }
    fn get_wallet_attestation_repository(&self) -> Arc<dyn WalletAttestationRepository> {
        self.data_provider.get_wallet_attestation_repository()
    }
    fn get_managed_instance_attestation_repository(
        &self,
    ) -> Arc<dyn ManagedInstanceAttestationRepository> {
        self.data_provider
            .get_managed_instance_attestation_repository()
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

    fn get_localized_text_repository(&self) -> Arc<dyn LocalizedTextRepository> {
        self.data_provider.get_localized_text_repository()
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
