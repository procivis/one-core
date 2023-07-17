use migration::{Migrator, MigratorTrait};
use sea_orm::DatabaseConnection;

pub mod common;
mod common_queries;
pub mod create_credential;
pub mod create_credential_schema;
pub mod create_organisation;
pub mod create_proof_schema;
pub mod data_model;
pub mod delete_credential_schema;
pub mod delete_proof_schema;
pub mod get_credential_details;
pub mod get_credential_schema_details;
pub mod get_credential_schemas;
pub mod get_did;
pub mod get_dids;
pub mod get_organisation_details;
pub mod get_organisations;
pub mod get_proof_schema_details;
pub mod get_proof_schemas;
pub mod share_credential;

pub mod list_query;

pub(super) mod entities;

#[derive(Debug, PartialEq, Eq)]
pub enum DataLayerError {
    GeneralRuntimeError(String),
    AlreadyExists,
    IncorrectParameters,
    RecordNotFound,
    RecordNotUpdated,
    Other,
}

#[derive(Clone)]
pub struct DataLayer {
    db: DatabaseConnection,
}

impl DataLayer {
    pub async fn create(database_url: &str) -> Self {
        let db = sea_orm::Database::connect(database_url)
            .await
            .expect("Database Connected");

        Migrator::up(&db, None).await.unwrap();

        Self { db }
    }
}

#[cfg(test)]
mod test_utilities;
