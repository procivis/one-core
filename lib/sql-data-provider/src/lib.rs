use crate::credential::CredentialProvider;
use crate::credential_schema::CredentialSchemaProvider;
use claim::ClaimProvider;
use claim_schema::ClaimSchemaProvider;
use did::DidProvider;
use interaction::InteractionProvider;
use migration::{Migrator, MigratorTrait};
use one_core::repository::{
    claim_repository::ClaimRepository, claim_schema_repository::ClaimSchemaRepository,
    credential_repository::CredentialRepository,
    credential_schema_repository::CredentialSchemaRepository, did_repository::DidRepository,
    interaction_repository::InteractionRepository, organisation_repository::OrganisationRepository,
    proof_repository::ProofRepository, proof_schema_repository::ProofSchemaRepository,
    DataRepository,
};
use organisation::OrganisationProvider;
use proof::ProofProvider;
use proof_schema::ProofSchemaProvider;
use sea_orm::DatabaseConnection;

use std::sync::Arc;

mod common;
mod data_model;
mod entity;

mod list_query;

// New implementations
pub mod claim;
pub mod claim_schema;
pub mod credential;
pub mod credential_schema;
pub mod did;
pub mod interaction;
pub mod organisation;
pub mod proof;
pub mod proof_schema;

mod error_mapper;

#[derive(Clone)]
pub struct DataLayer {
    // Used for tests for now
    #[allow(unused)]
    db: DatabaseConnection,
    organisation_repository: Arc<dyn OrganisationRepository + Send + Sync>,
    did_repository: Arc<dyn DidRepository + Send + Sync>,
    claim_repository: Arc<dyn ClaimRepository + Send + Sync>,
    claim_schema_repository: Arc<dyn ClaimSchemaRepository + Send + Sync>,
    credential_repository: Arc<dyn CredentialRepository + Send + Sync>,
    credential_schema_repository: Arc<dyn CredentialSchemaRepository + Send + Sync>,
    proof_schema_repository: Arc<dyn ProofSchemaRepository + Send + Sync>,
    proof_repository: Arc<dyn ProofRepository + Send + Sync>,
    interaction_repository: Arc<dyn InteractionRepository + Send + Sync>,
}

impl DataLayer {
    pub async fn create(database_url: &str) -> Self {
        let db = sea_orm::Database::connect(database_url)
            .await
            .expect("Database Connected");

        Migrator::up(&db, None).await.unwrap();

        let interaction_repository = Arc::new(InteractionProvider { db: db.clone() });
        let did_repository = Arc::new(DidProvider { db: db.clone() });
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
        let proof_schema_repository = Arc::new(ProofSchemaProvider {
            db: db.clone(),
            claim_schema_repository: claim_schema_repository.clone(),
            organisation_repository: organisation_repository.clone(),
            credential_schema_repository: credential_schema_repository.clone(),
        });
        let proof_repository = Arc::new(ProofProvider {
            db: db.clone(),
            claim_repository: claim_repository.clone(),
            proof_schema_repository: proof_schema_repository.clone(),
            did_repository: did_repository.clone(),
            interaction_repository: interaction_repository.clone(),
        });
        let credential_repository = Arc::new(CredentialProvider {
            db: db.clone(),
            credential_schema_repository: credential_schema_repository.clone(),
            claim_repository: claim_repository.clone(),
            did_repository: did_repository.clone(),
        });

        Self {
            organisation_repository,
            credential_repository,
            credential_schema_repository,
            proof_schema_repository,
            proof_repository,
            claim_schema_repository,
            claim_repository,
            did_repository,
            db,
            interaction_repository,
        }
    }
}

#[async_trait::async_trait]
impl DataRepository for DataLayer {
    fn get_organisation_repository(&self) -> Arc<dyn OrganisationRepository + Send + Sync> {
        self.organisation_repository.clone()
    }
    fn get_did_repository(&self) -> Arc<dyn DidRepository + Send + Sync> {
        self.did_repository.clone()
    }
    fn get_claim_repository(&self) -> Arc<dyn ClaimRepository + Send + Sync> {
        self.claim_repository.clone()
    }
    fn get_claim_schema_repository(&self) -> Arc<dyn ClaimSchemaRepository + Send + Sync> {
        self.claim_schema_repository.clone()
    }
    fn get_credential_repository(&self) -> Arc<dyn CredentialRepository + Send + Sync> {
        self.credential_repository.clone()
    }
    fn get_credential_schema_repository(
        &self,
    ) -> Arc<dyn CredentialSchemaRepository + Send + Sync> {
        self.credential_schema_repository.clone()
    }
    fn get_proof_schema_repository(&self) -> Arc<dyn ProofSchemaRepository + Send + Sync> {
        self.proof_schema_repository.clone()
    }
    fn get_proof_repository(&self) -> Arc<dyn ProofRepository + Send + Sync> {
        self.proof_repository.clone()
    }
    fn get_interaction_repository(&self) -> Arc<dyn InteractionRepository + Send + Sync> {
        self.interaction_repository.clone()
    }
}

#[cfg(test)]
pub(crate) mod test_utilities;
