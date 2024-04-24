use std::sync::Arc;

use backup::BackupProvider;
use claim::ClaimProvider;
use claim_schema::ClaimSchemaProvider;
use did::DidProvider;
use interaction::InteractionProvider;
use lvvc::LvvcProvider;
use migration::{Migrator, MigratorTrait};
use one_core::repository::backup_repository::BackupRepository;
use one_core::repository::json_ld_context_repository::JsonLdContextRepository;
use one_core::repository::lvvc_repository::LvvcRepository;
use one_core::repository::{
    claim_repository::ClaimRepository, claim_schema_repository::ClaimSchemaRepository,
    credential_repository::CredentialRepository,
    credential_schema_repository::CredentialSchemaRepository, did_repository::DidRepository,
    history_repository::HistoryRepository, interaction_repository::InteractionRepository,
    key_repository::KeyRepository, organisation_repository::OrganisationRepository,
    proof_repository::ProofRepository, proof_schema_repository::ProofSchemaRepository,
    revocation_list_repository::RevocationListRepository, DataRepository,
};
use organisation::OrganisationProvider;
use proof::ProofProvider;
use proof_schema::ProofSchemaProvider;
use sea_orm::{ConnectOptions, DatabaseConnection, DbErr};

use crate::credential::CredentialProvider;
use crate::credential_schema::CredentialSchemaProvider;
use crate::history::HistoryProvider;
use crate::json_ld_context::JsonLdContextProvider;
use crate::key::KeyProvider;
use crate::revocation_list::RevocationListProvider;

mod common;
mod entity;
mod mapper;

mod list_query;
mod list_query_generic;

// New implementations
pub mod backup;
pub mod claim;
pub mod claim_schema;
pub mod credential;
pub mod credential_schema;
pub mod did;
pub mod history;
pub mod interaction;
pub mod json_ld_context;
pub mod key;
pub mod lvvc;
pub mod organisation;
pub mod proof;
pub mod proof_schema;
pub mod revocation_list;

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
    key_repository: Arc<dyn KeyRepository>,
    json_ld_context_repository: Arc<dyn JsonLdContextRepository>,
    proof_schema_repository: Arc<dyn ProofSchemaRepository>,
    proof_repository: Arc<dyn ProofRepository>,
    interaction_repository: Arc<dyn InteractionRepository>,
    revocation_list_repository: Arc<dyn RevocationListRepository>,
    lvvc_repository: Arc<dyn LvvcRepository>,
    backup_repository: Arc<dyn BackupRepository>,
}

impl DataLayer {
    pub fn build(db: DbConn, exportable_storages: Vec<String>) -> Self {
        let interaction_repository = Arc::new(InteractionProvider { db: db.clone() });

        let claim_schema_repository = Arc::new(ClaimSchemaProvider { db: db.clone() });

        let claim_repository = Arc::new(ClaimProvider {
            db: db.clone(),
            claim_schema_repository: claim_schema_repository.clone(),
        });

        let organisation_repository = Arc::new(OrganisationProvider { db: db.clone() });

        let credential_schema_repository = Arc::new(CredentialSchemaProvider {
            db: db.clone(),
            claim_schema_repository: claim_schema_repository.clone(),
            organisation_repository: organisation_repository.clone(),
        });

        let key_repository = Arc::new(KeyProvider {
            db: db.clone(),
            organisation_repository: organisation_repository.clone(),
        });

        let json_ld_context_repository = Arc::new(JsonLdContextProvider { db: db.clone() });

        let history_repository = Arc::new(HistoryProvider { db: db.clone() });

        let did_repository = Arc::new(DidProvider {
            key_repository: key_repository.clone(),
            organisation_repository: organisation_repository.clone(),
            db: db.clone(),
        });

        let proof_schema_repository = Arc::new(ProofSchemaProvider {
            db: db.clone(),
            claim_schema_repository: claim_schema_repository.clone(),
            organisation_repository: organisation_repository.clone(),
            credential_schema_repository: credential_schema_repository.clone(),
        });

        let revocation_list_repository = Arc::new(RevocationListProvider {
            db: db.clone(),
            did_repository: did_repository.clone(),
        });

        let credential_repository = Arc::new(CredentialProvider {
            db: db.clone(),
            credential_schema_repository: credential_schema_repository.clone(),
            claim_repository: claim_repository.clone(),
            did_repository: did_repository.clone(),
            interaction_repository: interaction_repository.clone(),
            revocation_list_repository: revocation_list_repository.clone(),
            key_repository: key_repository.clone(),
        });

        let proof_repository = Arc::new(ProofProvider {
            db: db.clone(),
            claim_repository: claim_repository.clone(),
            credential_repository: credential_repository.clone(),
            proof_schema_repository: proof_schema_repository.clone(),
            did_repository: did_repository.clone(),
            interaction_repository: interaction_repository.clone(),
            key_repository: key_repository.clone(),
        });

        let lvvc_repository = Arc::new(LvvcProvider::new(db.clone()));
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
    fn get_json_ld_context_repository(&self) -> Arc<dyn JsonLdContextRepository> {
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
    fn get_lvvc_repository(&self) -> Arc<dyn LvvcRepository> {
        self.lvvc_repository.clone()
    }
    fn get_backup_repository(&self) -> Arc<dyn BackupRepository> {
        self.backup_repository.clone()
    }
}

/// Connects to the database and runs the pending migrations (until we externalize them)
pub async fn db_conn(
    database_url: impl Into<ConnectOptions>,
    with_migration: bool,
) -> Result<DatabaseConnection, DbErr> {
    let db = sea_orm::Database::connect(database_url).await?;

    if with_migration {
        Migrator::up(&db, None).await?;
    }

    Ok(db)
}

#[cfg(any(test, feature = "test_utils"))]
pub mod test_utilities;
