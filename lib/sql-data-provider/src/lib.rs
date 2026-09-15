use std::sync::Arc;

use backup::BackupProvider;
use certificate::CertificateProvider;
use claim::ClaimProvider;
use claim_schema::ClaimSchemaProvider;
use did::DidProvider;
use identifier::IdentifierProvider;
use interaction::InteractionProvider;
use managed_instance::ManagedInstanceProvider;
use migration::runner::run_migrations;
use one_core::proto::transaction_manager::TransactionManager;
use one_core::repository::DataRepository;
use one_core::repository::backup_repository::BackupRepository;
use one_core::repository::blob_repository::BlobRepository;
use one_core::repository::certificate_repository::CertificateRepository;
use one_core::repository::claim_repository::ClaimRepository;
use one_core::repository::claim_schema_repository::ClaimSchemaRepository;
use one_core::repository::credential_repository::CredentialRepository;
use one_core::repository::credential_schema_format_repository::CredentialSchemaFormatRepository;
use one_core::repository::credential_schema_repository::CredentialSchemaRepository;
use one_core::repository::did_repository::DidRepository;
use one_core::repository::history_repository::HistoryRepository;
use one_core::repository::identifier_repository::IdentifierRepository;
use one_core::repository::identifier_trust_information_repository::IdentifierTrustInformationRepository;
use one_core::repository::instance_repository::InstanceRepository;
use one_core::repository::interaction_repository::InteractionRepository;
use one_core::repository::key_repository::KeyRepository;
use one_core::repository::localized_text_repository::LocalizedTextRepository;
use one_core::repository::managed_instance_attestation_repository::ManagedInstanceAttestationRepository;
use one_core::repository::managed_instance_repository::ManagedInstanceRepository;
use one_core::repository::notification_repository::NotificationRepository;
use one_core::repository::organisation_repository::OrganisationRepository;
use one_core::repository::proof_repository::ProofRepository;
use one_core::repository::proof_schema_repository::ProofSchemaRepository;
use one_core::repository::remote_entity_cache_repository::RemoteEntityCacheRepository;
use one_core::repository::revocation_list_repository::RevocationListRepository;
use one_core::repository::trust_collection_repository::TrustCollectionRepository;
use one_core::repository::trust_entry_repository::TrustEntryRepository;
use one_core::repository::trust_list_publication_repository::TrustListPublicationRepository;
use one_core::repository::trust_list_subscription_repository::TrustListSubscriptionRepository;
use one_core::repository::wallet_instance_attestation_repository::WalletInstanceAttestationRepository;
use organisation::OrganisationProvider;
use proof::ProofProvider;
use proof_schema::ProofSchemaProvider;
use sea_orm::{ConnectOptions, DatabaseConnection, DbErr};
use trust_collection::TrustCollectionProvider;
use trust_entry::TrustEntryProvider;
use trust_list_publication::TrustListPublicationProvider;
use trust_list_subscription::TrustListSubscriptionProvider;

use crate::blob::BlobProvider;
use crate::credential::CredentialProvider;
use crate::credential_schema::CredentialSchemaProvider;
use crate::credential_schema_format::CredentialSchemaFormatProvider;
use crate::history::HistoryProvider;
use crate::identifier_trust_information::IdentifierTrustInformationProvider;
use crate::instance::InstanceProvider;
use crate::key::KeyProvider;
use crate::localized_text::LocalizedTextProvider;
use crate::managed_instance_attestation::ManagedInstanceAttestationProvider;
use crate::notification::NotificationProvider;
use crate::remote_entity_cache::RemoteEntityCacheProvider;
use crate::revocation_list::RevocationListProvider;
use crate::transaction_context::TransactionManagerImpl;
use crate::wallet_instance_attestation::WalletInstanceAttestationProvider;

mod common;
mod entity;
mod mapper;

mod list_query_generic;

// New implementations
pub mod backup;
pub mod certificate;
pub mod claim;
pub mod claim_schema;
pub mod credential;
pub mod credential_schema;
pub mod credential_schema_format;
pub mod did;
pub mod history;
pub mod identifier;
pub mod interaction;
pub mod key;
pub mod managed_instance;
pub mod notification;
pub mod organisation;
pub mod proof;
pub mod proof_schema;
pub mod remote_entity_cache;
pub mod revocation_list;
pub mod trust_collection;
pub mod trust_entry;
pub mod trust_list_publication;
pub mod trust_list_subscription;

// Re-exporting the DatabaseConnection to avoid unnecessary dependency on sea_orm in cases where we only need the DB connection
pub type DbConn = DatabaseConnection;

#[derive(Clone)]
pub struct DataLayer {
    // Used for tests for now
    #[allow(dead_code)]
    db: DatabaseConnection,
    transaction_manager: TransactionManagerImpl,
    organisation_repository: Arc<dyn OrganisationRepository>,
    did_repository: Arc<dyn DidRepository>,
    claim_repository: Arc<dyn ClaimRepository>,
    claim_schema_repository: Arc<dyn ClaimSchemaRepository>,
    credential_repository: Arc<dyn CredentialRepository>,
    credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    credential_schema_format_repository: Arc<dyn CredentialSchemaFormatRepository>,
    history_repository: Arc<dyn HistoryRepository>,
    identifier_repository: Arc<dyn IdentifierRepository>,
    identifier_trust_information_repository: Arc<dyn IdentifierTrustInformationRepository>,
    certificate_repository: Arc<dyn CertificateRepository>,
    key_repository: Arc<dyn KeyRepository>,
    json_ld_context_repository: Arc<dyn RemoteEntityCacheRepository>,
    proof_schema_repository: Arc<dyn ProofSchemaRepository>,
    proof_repository: Arc<dyn ProofRepository>,
    interaction_repository: Arc<dyn InteractionRepository>,
    revocation_list_repository: Arc<dyn RevocationListRepository>,
    backup_repository: Arc<dyn BackupRepository>,
    trust_collection_repository: Arc<dyn TrustCollectionRepository>,
    trust_entry_repository: Arc<dyn TrustEntryRepository>,
    trust_list_publication_repository: Arc<dyn TrustListPublicationRepository>,
    trust_list_subscription_repository: Arc<dyn TrustListSubscriptionRepository>,
    blob_repository: Arc<dyn BlobRepository>,
    notification_repository: Arc<dyn NotificationRepository>,
    wallet_instance_repository: Arc<dyn ManagedInstanceRepository>,
    holder_wallet_instance_repository: Arc<dyn InstanceRepository>,
    wallet_instance_attestation_repository: Arc<dyn WalletInstanceAttestationRepository>,
    managed_instance_attestation_repository: Arc<dyn ManagedInstanceAttestationRepository>,
    #[allow(dead_code)]
    localized_text_repository: Arc<dyn LocalizedTextRepository>,
}

impl DataLayer {
    pub fn build(db: DbConn, exportable_storages: Vec<String>) -> Self {
        let transaction_manager = TransactionManagerImpl::new(db.clone());
        let history_repository = Arc::new(HistoryProvider {
            db: transaction_manager.clone(),
        });
        let localized_text_repository = Arc::new(LocalizedTextProvider {
            db: transaction_manager.clone(),
        });

        let identifier_trust_information_repository =
            Arc::new(IdentifierTrustInformationProvider {
                db: transaction_manager.clone(),
            });

        let claim_schema_repository = Arc::new(ClaimSchemaProvider {
            db: transaction_manager.clone(),
        });

        let claim_repository = Arc::new(ClaimProvider {
            db: transaction_manager.clone(),
            claim_schema_repository: claim_schema_repository.clone(),
        });

        let organisation_repository = Arc::new(OrganisationProvider {
            db: transaction_manager.clone(),
        });

        let interaction_repository = Arc::new(InteractionProvider {
            db: transaction_manager.clone(),
            organisation_repository: organisation_repository.clone(),
        });

        let credential_schema_repository = Arc::new(CredentialSchemaProvider {
            db: transaction_manager.clone(),
            organisation_repository: organisation_repository.clone(),
            localized_text_repository: localized_text_repository.clone(),
        });

        let credential_schema_format_repository = Arc::new(CredentialSchemaFormatProvider {
            db: transaction_manager.clone(),
        });

        let key_repository = Arc::new(KeyProvider {
            db: transaction_manager.clone(),
            organisation_repository: organisation_repository.clone(),
        });

        let json_ld_context_repository = Arc::new(RemoteEntityCacheProvider {
            db: transaction_manager.clone(),
        });

        let did_repository = Arc::new(DidProvider {
            db: transaction_manager.clone(),
            key_repository: key_repository.clone(),
            organisation_repository: organisation_repository.clone(),
        });

        let certificate_repository = Arc::new(CertificateProvider {
            db: transaction_manager.clone(),
            key_repository: key_repository.clone(),
            organisation_repository: organisation_repository.clone(),
        });

        let identifier_repository = Arc::new(IdentifierProvider {
            db: transaction_manager.clone(),
            organisation_repository: organisation_repository.clone(),
            did_repository: did_repository.clone(),
            key_repository: key_repository.clone(),
            certificate_repository: certificate_repository.clone(),
            trust_information_repository: identifier_trust_information_repository.clone(),
            localized_text_repository: localized_text_repository.clone(),
        });

        let proof_schema_repository = Arc::new(ProofSchemaProvider {
            db: transaction_manager.clone(),
            claim_schema_repository: claim_schema_repository.clone(),
            organisation_repository: organisation_repository.clone(),
            credential_schema_repository: credential_schema_repository.clone(),
        });

        let revocation_list_repository = Arc::new(RevocationListProvider {
            db: transaction_manager.clone(),
            identifier_repository: identifier_repository.clone(),
            certificate_repository: certificate_repository.clone(),
        });

        let trust_collection_repository = Arc::new(TrustCollectionProvider {
            db: transaction_manager.clone(),
            organisation_repository: organisation_repository.clone(),
        });

        let trust_list_publication_repository = Arc::new(TrustListPublicationProvider {
            db: transaction_manager.clone(),
            organisation_repository: organisation_repository.clone(),
            identifier_repository: identifier_repository.clone(),
            key_repository: key_repository.clone(),
            certificate_repository: certificate_repository.clone(),
        });

        let trust_entry_repository = Arc::new(TrustEntryProvider {
            db: transaction_manager.clone(),
            trust_list_publication_repository: trust_list_publication_repository.clone(),
            identifier_repository: identifier_repository.clone(),
            did_repository: did_repository.clone(),
            key_repository: key_repository.clone(),
            certificate_repository: certificate_repository.clone(),
            organisation_repository: organisation_repository.clone(),
            trust_information_repository: identifier_trust_information_repository.clone(),
            localized_text_repository: localized_text_repository.clone(),
        });

        let trust_list_subscription_repository = Arc::new(TrustListSubscriptionProvider {
            db: transaction_manager.clone(),
            trust_collection_repository: trust_collection_repository.clone(),
        });

        let credential_repository = Arc::new(CredentialProvider {
            db: transaction_manager.clone(),
            credential_schema_repository: credential_schema_repository.clone(),
            claim_repository: claim_repository.clone(),
            identifier_repository: identifier_repository.clone(),
            did_repository: did_repository.clone(),
            interaction_repository: interaction_repository.clone(),
            certificate_repository: certificate_repository.clone(),
            key_repository: key_repository.clone(),
            organisation_repository: organisation_repository.clone(),
            trust_information_repository: identifier_trust_information_repository.clone(),
        });

        let proof_repository = Arc::new(ProofProvider {
            db: transaction_manager.clone(),
            claim_repository: claim_repository.clone(),
            credential_repository: credential_repository.clone(),
            proof_schema_repository: proof_schema_repository.clone(),
            identifier_repository: identifier_repository.clone(),
            did_repository: did_repository.clone(),
            certificate_repository: certificate_repository.clone(),
            interaction_repository: interaction_repository.clone(),
            key_repository: key_repository.clone(),
            organisation_repository: organisation_repository.clone(),
            trust_information_repository: identifier_trust_information_repository.clone(),
            localized_text_repository: localized_text_repository.clone(),
        });

        let backup_repository = Arc::new(BackupProvider::new(
            transaction_manager.clone(),
            credential_repository.clone(),
            exportable_storages,
            organisation_repository.clone(),
            did_repository.clone(),
            key_repository.clone(),
            certificate_repository.clone(),
            identifier_trust_information_repository.clone(),
            localized_text_repository.clone(),
        ));

        let blob_repository = Arc::new(BlobProvider {
            db: transaction_manager.clone(),
        });

        let notification_repository = Arc::new(NotificationProvider {
            db: transaction_manager.clone(),
        });

        let managed_instance_attestation_repository =
            Arc::new(ManagedInstanceAttestationProvider {
                db: transaction_manager.clone(),
                revocation_list_repository: revocation_list_repository.clone(),
            });

        let wallet_instance_repository = Arc::new(ManagedInstanceProvider {
            db: transaction_manager.clone(),
            organisation_repository: organisation_repository.clone(),
            managed_instance_attestation_repository: managed_instance_attestation_repository
                .clone(),
        });

        let wallet_instance_attestation_repository = Arc::new(WalletInstanceAttestationProvider {
            db: transaction_manager.clone(),
            key_repository: key_repository.clone(),
        });

        let holder_wallet_instance_repository = Arc::new(InstanceProvider {
            db: transaction_manager.clone(),
            organisation_repository: organisation_repository.clone(),
            key_repository: key_repository.clone(),
            wallet_unit_attestation_repository: wallet_instance_attestation_repository.clone(),
        });

        Self {
            transaction_manager,
            organisation_repository,
            credential_repository,
            credential_schema_repository,
            credential_schema_format_repository,
            key_repository,
            json_ld_context_repository,
            history_repository,
            proof_schema_repository,
            proof_repository,
            claim_schema_repository,
            claim_repository,
            did_repository,
            db,
            interaction_repository,
            revocation_list_repository,
            backup_repository,
            trust_collection_repository,
            trust_entry_repository,
            trust_list_publication_repository,
            trust_list_subscription_repository,
            identifier_repository,
            identifier_trust_information_repository,
            certificate_repository,
            blob_repository,
            notification_repository,
            wallet_instance_repository,
            holder_wallet_instance_repository,
            wallet_instance_attestation_repository,
            managed_instance_attestation_repository,
            localized_text_repository,
        }
    }
}

#[async_trait::async_trait]
impl DataRepository for DataLayer {
    fn get_organisation_repository(&self) -> Arc<dyn OrganisationRepository> {
        self.organisation_repository.clone()
    }
    fn get_did_repository(&self) -> Arc<dyn DidRepository> {
        self.did_repository.clone()
    }
    fn get_certificate_repository(&self) -> Arc<dyn CertificateRepository> {
        self.certificate_repository.clone()
    }
    fn get_claim_repository(&self) -> Arc<dyn ClaimRepository> {
        self.claim_repository.clone()
    }
    fn get_claim_schema_repository(&self) -> Arc<dyn ClaimSchemaRepository> {
        self.claim_schema_repository.clone()
    }
    fn get_credential_repository(&self) -> Arc<dyn CredentialRepository> {
        self.credential_repository.clone()
    }
    fn get_credential_schema_repository(&self) -> Arc<dyn CredentialSchemaRepository> {
        self.credential_schema_repository.clone()
    }
    fn get_credential_schema_format_repository(&self) -> Arc<dyn CredentialSchemaFormatRepository> {
        self.credential_schema_format_repository.clone()
    }
    fn get_history_repository(&self) -> Arc<dyn HistoryRepository> {
        self.history_repository.clone()
    }
    fn get_identifier_repository(&self) -> Arc<dyn IdentifierRepository> {
        self.identifier_repository.clone()
    }
    fn get_identifier_trust_information_repository(
        &self,
    ) -> Arc<dyn IdentifierTrustInformationRepository> {
        self.identifier_trust_information_repository.clone()
    }
    fn get_remote_entity_cache_repository(&self) -> Arc<dyn RemoteEntityCacheRepository> {
        self.json_ld_context_repository.clone()
    }
    fn get_key_repository(&self) -> Arc<dyn KeyRepository> {
        self.key_repository.clone()
    }
    fn get_proof_schema_repository(&self) -> Arc<dyn ProofSchemaRepository> {
        self.proof_schema_repository.clone()
    }
    fn get_proof_repository(&self) -> Arc<dyn ProofRepository> {
        self.proof_repository.clone()
    }
    fn get_interaction_repository(&self) -> Arc<dyn InteractionRepository> {
        self.interaction_repository.clone()
    }
    fn get_revocation_list_repository(&self) -> Arc<dyn RevocationListRepository> {
        self.revocation_list_repository.clone()
    }
    fn get_backup_repository(&self) -> Arc<dyn BackupRepository> {
        self.backup_repository.clone()
    }
    fn get_trust_collection_repository(&self) -> Arc<dyn TrustCollectionRepository> {
        self.trust_collection_repository.clone()
    }
    fn get_trust_entry_repository(&self) -> Arc<dyn TrustEntryRepository> {
        self.trust_entry_repository.clone()
    }
    fn get_trust_list_publication_repository(&self) -> Arc<dyn TrustListPublicationRepository> {
        self.trust_list_publication_repository.clone()
    }
    fn get_trust_list_subscription_repository(&self) -> Arc<dyn TrustListSubscriptionRepository> {
        self.trust_list_subscription_repository.clone()
    }
    fn get_blob_repository(&self) -> Arc<dyn BlobRepository> {
        self.blob_repository.clone()
    }
    fn get_notification_repository(&self) -> Arc<dyn NotificationRepository> {
        self.notification_repository.clone()
    }

    fn get_managed_instance_repository(&self) -> Arc<dyn ManagedInstanceRepository> {
        self.wallet_instance_repository.clone()
    }

    fn get_wallet_instance_attestation_repository(
        &self,
    ) -> Arc<dyn WalletInstanceAttestationRepository> {
        self.wallet_instance_attestation_repository.clone()
    }

    fn get_managed_instance_attestation_repository(
        &self,
    ) -> Arc<dyn ManagedInstanceAttestationRepository> {
        self.managed_instance_attestation_repository.clone()
    }

    fn get_tx_manager(&self) -> Arc<dyn TransactionManager> {
        Arc::new(self.transaction_manager.clone())
    }

    fn get_instance_repository(&self) -> Arc<dyn InstanceRepository> {
        self.holder_wallet_instance_repository.clone()
    }

    fn get_localized_text_repository(&self) -> Arc<dyn LocalizedTextRepository> {
        self.localized_text_repository.clone()
    }
}

/// Connects to the database and runs the pending migrations (until we externalize them)
pub async fn db_conn(
    database_url: impl Into<ConnectOptions>,
    with_migration: bool,
) -> Result<DatabaseConnection, DbErr> {
    let db = sea_orm::Database::connect(database_url).await?;

    if with_migration {
        run_migrations(&db).await?;
    }

    Ok(db)
}

mod blob;
mod identifier_trust_information;
mod instance;
mod localized_text;
mod managed_instance_attestation;
#[cfg(any(test, feature = "test_utils"))]
pub mod test_utilities;
mod transaction_context;
mod wallet_instance_attestation;
