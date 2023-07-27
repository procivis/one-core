use migration::{Migrator, MigratorTrait};
use sea_orm::DatabaseConnection;
use thiserror::Error;

pub mod common;
mod common_queries;
pub mod create_credential;
pub mod create_credential_schema;
pub mod create_did;
pub mod create_organisation;
pub mod create_proof_schema;
pub mod data_model;
pub mod delete_credential_schema;
pub mod delete_proof_schema;
pub mod get_credential_details;
pub mod get_credential_schema_details;
pub mod get_credential_schemas;
pub mod get_credentials;
pub mod get_did;
pub mod get_dids;
pub mod get_organisation_details;
pub mod get_organisations;
pub mod get_proof_schema_details;
pub mod get_proof_schemas;
pub mod reject_proof_request;
pub mod share_credential;
pub mod update_credential;

pub mod list_query;

pub(super) mod entities;

#[derive(Debug, PartialEq, Eq, Error)]
pub enum DataLayerError {
    #[error("General Data Layer error `{0}`")]
    GeneralRuntimeError(String),
    #[error("Already exists")]
    AlreadyExists,
    #[error("Wrong parameters")]
    IncorrectParameters,
    #[error("Record not found")]
    RecordNotFound,
    #[error("Record not updated")]
    RecordNotUpdated,
    #[error("Other Data Layer error")]
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
