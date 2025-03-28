use sea_orm::{EnumIter, Iterable, Statement};
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            backend @ sea_orm::DatabaseBackend::MySql => {
                let enum_values: Vec<String> = UpdatedHistoryAction::iter()
                    .map(|action| action.to_string())
                    .collect();

                let values = format!("'{}'", enum_values.join("', '"));

                let query = format!(
                    r#"ALTER TABLE history CHANGE COLUMN action action ENUM({}) NOT NULL;"#,
                    values
                );

                let change_stmt = Statement::from_string(backend, &query);

                manager.get_connection().execute(change_stmt).await?;
            }
            sea_orm::DatabaseBackend::Postgres | sea_orm::DatabaseBackend::Sqlite => {}
        }
        Ok(())
    }
}

#[derive(Iden, EnumIter)]
pub enum UpdatedHistoryAction {
    #[iden = "ACCEPTED"]
    Accepted,
    #[iden = "CREATED"]
    Created,
    #[iden = "DEACTIVATED"]
    Deactivated,
    #[iden = "DELETED"]
    Deleted,
    #[iden = "ERRORED"]
    Errored,
    #[iden = "ISSUED"]
    Issued,
    #[iden = "OFFERED"]
    Offered,
    #[iden = "REJECTED"]
    Rejected,
    #[iden = "REQUESTED"]
    Requested,
    #[iden = "REVOKED"]
    Revoked,
    #[iden = "PENDING"]
    Pending,
    #[iden = "SUSPENDED"]
    Suspended,
    #[iden = "RESTORED"]
    Restored,
    #[iden = "SHARED"]
    Shared,
    #[iden = "IMPORTED"]
    Imported,
    #[iden = "CLAIMS_REMOVED"]
    ClaimsRemoved,
    #[iden = "ACTIVATED"]
    Activated,
    #[iden = "WITHDRAWN"]
    Withdrawn,
    #[iden = "REMOVED"]
    Removed,
    #[iden = "RETRACTED"]
    Retracted,
    #[iden = "UPDATED"]
    Updated,
    #[iden = "CSR_GENERATED"]
    CsrGenerated,
}
