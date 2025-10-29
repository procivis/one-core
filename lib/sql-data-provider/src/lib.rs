use std::sync::Arc;

use backup::BackupProvider;
use certificate::CertificateProvider;
use claim::ClaimProvider;
use claim_schema::ClaimSchemaProvider;
use did::DidProvider;
use identifier::IdentifierProvider;
use interaction::InteractionProvider;
use migration::runner::run_migrations;
use one_core::proto::transaction_manager::TransactionManager;
use one_core::repository::DataRepository;
use one_core::repository::backup_repository::BackupRepository;
use one_core::repository::blob_repository::BlobRepository;
use one_core::repository::certificate_repository::CertificateRepository;
use one_core::repository::claim_repository::ClaimRepository;
use one_core::repository::claim_schema_repository::ClaimSchemaRepository;
use one_core::repository::credential_repository::CredentialRepository;
use one_core::repository::credential_schema_repository::CredentialSchemaRepository;
use one_core::repository::did_repository::DidRepository;
use one_core::repository::history_repository::HistoryRepository;
use one_core::repository::holder_wallet_unit_repository::HolderWalletUnitRepository;
use one_core::repository::identifier_repository::IdentifierRepository;
use one_core::repository::interaction_repository::InteractionRepository;
use one_core::repository::key_repository::KeyRepository;
use one_core::repository::organisation_repository::OrganisationRepository;
use one_core::repository::proof_repository::ProofRepository;
use one_core::repository::proof_schema_repository::ProofSchemaRepository;
use one_core::repository::remote_entity_cache_repository::RemoteEntityCacheRepository;
use one_core::repository::revocation_list_repository::RevocationListRepository;
use one_core::repository::trust_anchor_repository::TrustAnchorRepository;
use one_core::repository::trust_entity_repository::TrustEntityRepository;
use one_core::repository::validity_credential_repository::ValidityCredentialRepository;
use one_core::repository::wallet_unit_attestation_repository::WalletUnitAttestationRepository;
use one_core::repository::wallet_unit_attested_key_repository::WalletUnitAttestedKeyRepository;
use one_core::repository::wallet_unit_repository::WalletUnitRepository;
use organisation::OrganisationProvider;
use proof::ProofProvider;
use proof_schema::ProofSchemaProvider;
use sea_orm::{ConnectOptions, DatabaseConnection, DbErr};
use trust_anchor::TrustAnchorProvider;
use trust_entity::TrustEntityProvider;
use validity_credential::ValidityCredentialProvider;
use wallet_unit::WalletUnitProvider;

use crate::blob::BlobProvider;
use crate::credential::CredentialProvider;
use crate::credential_schema::CredentialSchemaProvider;
use crate::history::HistoryProvider;
use crate::holder_wallet_unit::HolderWalletUnitProvider;
use crate::key::KeyProvider;
use crate::remote_entity_cache::RemoteEntityCacheProvider;
use crate::revocation_list::RevocationListProvider;
use crate::transaction_context::TransactionManagerImpl;
use crate::wallet_unit_attestation::WalletUnitAttestationProvider;
use crate::wallet_unit_attested_key::WalletUnitAttestedKeyProvider;

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
pub mod did;
pub mod history;
pub mod identifier;
pub mod interaction;
pub mod key;
pub mod organisation;
pub mod proof;
pub mod proof_schema;
pub mod remote_entity_cache;
pub mod revocation_list;
pub mod trust_anchor;
pub mod trust_entity;
pub mod validity_credential;
pub mod wallet_unit;

// Re-exporting the DatabaseConnection to avoid unnecessary dependency on sea_orm in cases where we only need the DB connection
pub type DbConn = DatabaseConnection;

#[derive(Clone)]
pub struct DataLayer {
    // Used for tests for now
    #[allow(unused)]
    db: DatabaseConnection,
    transaction_manager: Arc<dyn TransactionManager>,
    organisation_repository: Arc<dyn OrganisationRepository>,
    did_repository: Arc<dyn DidRepository>,
    claim_repository: Arc<dyn ClaimRepository>,
    claim_schema_repository: Arc<dyn ClaimSchemaRepository>,
    credential_repository: Arc<dyn CredentialRepository>,
    credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    history_repository: Arc<dyn HistoryRepository>,
    identifier_repository: Arc<dyn IdentifierRepository>,
    certificate_repository: Arc<dyn CertificateRepository>,
    key_repository: Arc<dyn KeyRepository>,
    json_ld_context_repository: Arc<dyn RemoteEntityCacheRepository>,
    proof_schema_repository: Arc<dyn ProofSchemaRepository>,
    proof_repository: Arc<dyn ProofRepository>,
    interaction_repository: Arc<dyn InteractionRepository>,
    revocation_list_repository: Arc<dyn RevocationListRepository>,
    lvvc_repository: Arc<dyn ValidityCredentialRepository>,
    backup_repository: Arc<dyn BackupRepository>,
    trust_anchor_repository: Arc<dyn TrustAnchorRepository>,
    trust_entity_repository: Arc<dyn TrustEntityRepository>,
    blob_repository: Arc<dyn BlobRepository>,
    wallet_unit_repository: Arc<dyn WalletUnitRepository>,
    holder_wallet_unit_repository: Arc<dyn HolderWalletUnitRepository>,
    wallet_unit_attestation_repository: Arc<dyn WalletUnitAttestationRepository>,
    #[allow(unused)]
    wallet_unit_attested_key_repository: Arc<dyn WalletUnitAttestedKeyRepository>,
}

impl DataLayer {
    pub fn build(db: DbConn, exportable_storages: Vec<String>) -> Self {
        let transaction_manager = Arc::new(TransactionManagerImpl::new(db.clone()));
        let history_repository = Arc::new(HistoryProvider {
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
            claim_schema_repository: claim_schema_repository.clone(),
            organisation_repository: organisation_repository.clone(),
        });

        let key_repository = Arc::new(KeyProvider {
            db: transaction_manager.clone(),
            organisation_repository: organisation_repository.clone(),
        });

        let json_ld_context_repository = Arc::new(RemoteEntityCacheProvider {
            db: transaction_manager.clone(),
        });

        let did_repository = Arc::new(DidProvider {
            key_repository: key_repository.clone(),
            organisation_repository: organisation_repository.clone(),
            db: transaction_manager.clone(),
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
        });

        let trust_anchor_repository = Arc::new(TrustAnchorProvider {
            db: transaction_manager.clone(),
        });

        let trust_entity_repository = Arc::new(TrustEntityProvider {
            db: transaction_manager.clone(),
            trust_anchor_repository: trust_anchor_repository.clone(),
            organisation_repository: organisation_repository.clone(),
        });

        let credential_repository = Arc::new(CredentialProvider {
            db: transaction_manager.clone(),
            credential_schema_repository: credential_schema_repository.clone(),
            claim_repository: claim_repository.clone(),
            identifier_repository: identifier_repository.clone(),
            interaction_repository: interaction_repository.clone(),
            revocation_list_repository: revocation_list_repository.clone(),
            certificate_repository: certificate_repository.clone(),
            key_repository: key_repository.clone(),
        });

        let proof_repository = Arc::new(ProofProvider {
            db: transaction_manager.clone(),
            claim_repository: claim_repository.clone(),
            credential_repository: credential_repository.clone(),
            proof_schema_repository: proof_schema_repository.clone(),
            identifier_repository: identifier_repository.clone(),
            certificate_repository: certificate_repository.clone(),
            interaction_repository: interaction_repository.clone(),
            key_repository: key_repository.clone(),
        });

        let lvvc_repository =
            Arc::new(ValidityCredentialProvider::new(transaction_manager.clone()));
        let backup_repository = Arc::new(BackupProvider::new(
            transaction_manager.clone(),
            exportable_storages,
        ));

        let blob_repository = Arc::new(BlobProvider::new(transaction_manager.clone()));

        let wallet_unit_attested_key_repository = Arc::new(WalletUnitAttestedKeyProvider {
            db: transaction_manager.clone(),
            revocation_list_repository: revocation_list_repository.clone(),
        });

        let wallet_unit_repository = Arc::new(WalletUnitProvider {
            db: transaction_manager.clone(),
            tx_manager: transaction_manager.clone(),
            organisation_repository: organisation_repository.clone(),
            wallet_unit_attested_key_repository: wallet_unit_attested_key_repository.clone(),
        });

        let wallet_unit_attestation_repository = Arc::new(WalletUnitAttestationProvider {
            db: transaction_manager.clone(),
            key_repository: key_repository.clone(),
        });

        let holder_wallet_unit_repository = Arc::new(HolderWalletUnitProvider {
            db: transaction_manager.clone(),
            tx_manager: transaction_manager.clone(),
            organisation_repository: organisation_repository.clone(),
            key_repository: key_repository.clone(),
            wallet_unit_attestation_repository: wallet_unit_attestation_repository.clone(),
        });

        Self {
            transaction_manager,
            organisation_repository,
            credential_repository,
            credential_schema_repository,
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
            lvvc_repository,
            backup_repository,
            trust_anchor_repository,
            trust_entity_repository,
            identifier_repository,
            certificate_repository,
            blob_repository,
            wallet_unit_repository,
            holder_wallet_unit_repository,
            wallet_unit_attestation_repository,
            wallet_unit_attested_key_repository,
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
    fn get_history_repository(&self) -> Arc<dyn HistoryRepository> {
        self.history_repository.clone()
    }
    fn get_identifier_repository(&self) -> Arc<dyn IdentifierRepository> {
        self.identifier_repository.clone()
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
    fn get_validity_credential_repository(&self) -> Arc<dyn ValidityCredentialRepository> {
        self.lvvc_repository.clone()
    }
    fn get_backup_repository(&self) -> Arc<dyn BackupRepository> {
        self.backup_repository.clone()
    }
    fn get_trust_anchor_repository(&self) -> Arc<dyn TrustAnchorRepository> {
        self.trust_anchor_repository.clone()
    }
    fn get_trust_entity_repository(&self) -> Arc<dyn TrustEntityRepository> {
        self.trust_entity_repository.clone()
    }

    fn get_blob_repository(&self) -> Arc<dyn BlobRepository> {
        self.blob_repository.clone()
    }

    fn get_wallet_unit_repository(&self) -> Arc<dyn WalletUnitRepository> {
        self.wallet_unit_repository.clone()
    }

    fn get_wallet_unit_attestation_repository(&self) -> Arc<dyn WalletUnitAttestationRepository> {
        self.wallet_unit_attestation_repository.clone()
    }

    fn get_tx_manager(&self) -> Arc<dyn TransactionManager> {
        self.transaction_manager.clone()
    }

    fn get_holder_wallet_unit_repository(&self) -> Arc<dyn HolderWalletUnitRepository> {
        self.holder_wallet_unit_repository.clone()
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
mod holder_wallet_unit;
#[cfg(any(test, feature = "test_utils"))]
pub mod test_utilities;
mod transaction_context;
mod wallet_unit_attestation;
mod wallet_unit_attested_key;
