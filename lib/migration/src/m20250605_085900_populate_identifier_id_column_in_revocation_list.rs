use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DbBackend::Postgres => {}
            DbBackend::Sqlite => {
                manager
                    .get_connection()
                    .execute_unprepared(
                        r#"
                    UPDATE revocation_list
                    SET issuer_identifier_id = identifier.id
                    FROM identifier
                    WHERE revocation_list.issuer_did_id = identifier.did_id;
                    "#,
                    )
                    .await?;
            }
            DbBackend::MySql => {
                manager
                    .get_connection()
                    .execute_unprepared(
                        r#"
                    UPDATE revocation_list, identifier
                    SET revocation_list.issuer_identifier_id = identifier.id
                    WHERE revocation_list.issuer_did_id = identifier.did_id;
                    "#,
                    )
                    .await?;
            }
        }
        Ok(())
    }
}
