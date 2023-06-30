use migration::{Migrator, MigratorTrait, SQLiteMigrator};
use sea_orm::DatabaseConnection;

pub mod common;
pub mod create_credential_schema;
pub mod create_organisation;
pub mod create_proof_schema;
pub mod data_model;
pub mod delete_credential_schema;
pub mod delete_proof_schema;
pub mod get_credential_schema_details;
pub mod get_credential_schemas;
pub mod get_organisation_details;
pub mod get_organisations;
pub mod get_proof_schema_details;
pub mod get_proof_schemas;

pub mod list_query;

pub(super) mod entities;

#[derive(Debug, PartialEq, Eq)]
pub enum DataLayerError {
    GeneralRuntimeError(String),
    AlreadyExists,
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
        let is_sqlite = database_url.starts_with("sqlite:");

        let db = sea_orm::Database::connect(database_url).await.unwrap();

        if is_sqlite {
            SQLiteMigrator::up(&db, None).await.unwrap();
        } else {
            Migrator::up(&db, None).await.unwrap();
        }

        Self { db }
    }
}

#[cfg(test)]
mod test_utilities;
