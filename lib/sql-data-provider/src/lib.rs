use std::sync::Arc;

use backup::BackupProvider;
use certificate::CertificateProvider;
use certificate::history::CertificateHistoryDecorator;
use claim::ClaimProvider;
use claim_schema::ClaimSchemaProvider;
use credential::history::CredentialHistoryDecorator;
use credential_schema::history::CredentialSchemaHistoryDecorator;
use did::DidProvider;
use did::history::DidHistoryDecorator;
use identifier::IdentifierProvider;
use identifier::history::IdentifierHistoryDecorator;
use interaction::InteractionProvider;
use key::history::KeyHistoryDecorator;
use migration::runner::run_migrations;
use one_core::repository::DataRepository;
use one_core::repository::backup_repository::BackupRepository;
use one_core::repository::certificate_repository::CertificateRepository;
use one_core::repository::claim_repository::ClaimRepository;
use one_core::repository::claim_schema_repository::ClaimSchemaRepository;
use one_core::repository::credential_repository::CredentialRepository;
use one_core::repository::credential_schema_repository::CredentialSchemaRepository;
use one_core::repository::did_repository::DidRepository;
use one_core::repository::history_repository::HistoryRepository;
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
use organisation::OrganisationProvider;
use organisation::history::OrganisationHistoryDecorator;
use proof::ProofProvider;
use proof::history::ProofHistoryDecorator;
use proof_schema::ProofSchemaProvider;
use proof_schema::history::ProofSchemaHistoryDecorator;
use sea_orm::{ConnectOptions, DatabaseConnection, DbErr};
use trust_anchor::TrustAnchorProvider;
use trust_entity::TrustEntityProvider;
use trust_entity::history::TrustEntityHistoryDecorator;
use validity_credential::ValidityCredentialProvider;

use crate::credential::CredentialProvider;
use crate::credential_schema::CredentialSchemaProvider;
use crate::history::HistoryProvider;
use crate::key::KeyProvider;
use crate::remote_entity_cache::RemoteEntityCacheProvider;
use crate::revocation_list::RevocationListProvider;

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

// Re-exporting the DatabaseConnection to avoid unnecessary dependency on sea_orm in cases where we only need the DB connection
pub type DbConn = DatabaseConnection;

#[derive(Clone)]
pub struct DataLayer {
    // Used for tests for now
    #[allow(unused)]
    db: DatabaseConnection,
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
}

impl DataLayer {
    pub fn build(db: DbConn, exportable_storages: Vec<String>) -> Self {
        let history_repository = Arc::new(HistoryProvider { db: db.clone() });

        let claim_schema_repository = Arc::new(ClaimSchemaProvider { db: db.clone() });

        let claim_repository = Arc::new(ClaimProvider {
            db: db.clone(),
            claim_schema_repository: claim_schema_repository.clone(),
        });

        let organisation_repository = Arc::new(OrganisationProvider { db: db.clone() });
        let organisation_repository = Arc::new(OrganisationHistoryDecorator {
            inner: organisation_repository,
            history_repository: history_repository.clone(),
        });

        let interaction_repository = Arc::new(InteractionProvider {
            db: db.clone(),
            organisation_repository: organisation_repository.clone(),
        });

        let credential_schema_repository = Arc::new(CredentialSchemaProvider {
            db: db.clone(),
            claim_schema_repository: claim_schema_repository.clone(),
            organisation_repository: organisation_repository.clone(),
        });

        let credential_schema_repository = Arc::new(CredentialSchemaHistoryDecorator {
            history_repository: history_repository.clone(),
            inner: credential_schema_repository,
        });

        let key_repository = Arc::new(KeyProvider {
            db: db.clone(),
            organisation_repository: organisation_repository.clone(),
        });

        let key_repository = Arc::new(KeyHistoryDecorator {
            inner: key_repository,
            history_repository: history_repository.clone(),
        });

        let json_ld_context_repository = Arc::new(RemoteEntityCacheProvider { db: db.clone() });

        let did_repository = Arc::new(DidProvider {
            key_repository: key_repository.clone(),
            organisation_repository: organisation_repository.clone(),
            db: db.clone(),
        });

        let did_repository = Arc::new(DidHistoryDecorator {
            inner: did_repository,
            history_repository: history_repository.clone(),
        });

        let certificate_repository = Arc::new(CertificateProvider {
            db: db.clone(),
            key_repository: key_repository.clone(),
            organisation_repository: organisation_repository.clone(),
        });

        let certificate_repository = Arc::new(CertificateHistoryDecorator {
            inner: certificate_repository,
            history_repository: history_repository.clone(),
            db: db.clone(),
        });

        let identifier_repository = Arc::new(IdentifierProvider {
            db: db.clone(),
            organisation_repository: organisation_repository.clone(),
            did_repository: did_repository.clone(),
            key_repository: key_repository.clone(),
            certificate_repository: certificate_repository.clone(),
        });

        let identifier_repository = Arc::new(IdentifierHistoryDecorator {
            inner: identifier_repository,
            history_repository: history_repository.clone(),
        });

        let proof_schema_repository = Arc::new(ProofSchemaProvider {
            db: db.clone(),
            claim_schema_repository: claim_schema_repository.clone(),
            organisation_repository: organisation_repository.clone(),
            credential_schema_repository: credential_schema_repository.clone(),
        });

        let proof_schema_repository = Arc::new(ProofSchemaHistoryDecorator {
            inner: proof_schema_repository,
            history_repository: history_repository.clone(),
        });

        let revocation_list_repository = Arc::new(RevocationListProvider {
            db: db.clone(),
            identifier_repository: identifier_repository.clone(),
        });

        let trust_anchor_repository = Arc::new(TrustAnchorProvider { db: db.clone() });

        let trust_entity_repository = Arc::new(TrustEntityProvider {
            db: db.clone(),
            trust_anchor_repository: trust_anchor_repository.clone(),
            organisation_repository: organisation_repository.clone(),
        });
        let trust_entity_repository = Arc::new(TrustEntityHistoryDecorator {
            inner: trust_entity_repository,
            history_repository: history_repository.clone(),
        });

        let credential_repository = Arc::new(CredentialProvider {
            db: db.clone(),
            credential_schema_repository: credential_schema_repository.clone(),
            claim_repository: claim_repository.clone(),
            identifier_repository: identifier_repository.clone(),
            interaction_repository: interaction_repository.clone(),
            revocation_list_repository: revocation_list_repository.clone(),
            certificate_repository: certificate_repository.clone(),
            key_repository: key_repository.clone(),
        });

        let credential_repository = Arc::new(CredentialHistoryDecorator {
            inner: credential_repository,
            history_repository: history_repository.clone(),
        });

        let proof_repository = Arc::new(ProofProvider {
            db: db.clone(),
            claim_repository: claim_repository.clone(),
            credential_repository: credential_repository.clone(),
            proof_schema_repository: proof_schema_repository.clone(),
            identifier_repository: identifier_repository.clone(),
            certificate_repository: certificate_repository.clone(),
            interaction_repository: interaction_repository.clone(),
            key_repository: key_repository.clone(),
        });

        let proof_repository = Arc::new(ProofHistoryDecorator {
            history_repository: history_repository.clone(),
            inner: proof_repository,
        });

        let lvvc_repository = Arc::new(ValidityCredentialProvider::new(db.clone()));
        let backup_repository = Arc::new(BackupProvider::new(db.clone(), exportable_storages));

        Self {
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

#[cfg(any(test, feature = "test_utils"))]
pub mod test_utilities;
