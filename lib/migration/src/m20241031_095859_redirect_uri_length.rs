use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == sea_orm::DatabaseBackend::Postgres {
            // Skip because it is not supported. If support for Postgres is added in the future
            // the schema can be setup in its entirety in a new, later migration.
            return Ok(());
        }
        manager
            .alter_table(
                Table::alter()
                    .table(Credential::Table)
                    .add_column(ColumnDef::new(Credential::RedirectUriTemp).string())
                    .to_owned(),
            )
            .await?;

        let credential_query = format!(
            "UPDATE {} SET {} = {}",
            Credential::Table.to_string(),
            Credential::RedirectUriTemp.to_string(),
            Credential::RedirectUri.to_string(),
        );

        manager
            .get_connection()
            .execute_unprepared(&credential_query)
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Credential::Table)
                    .drop_column(Credential::RedirectUri)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Credential::Table)
                    .add_column(
                        ColumnDef::new(Credential::RedirectUri)
                            .string_len(500)
                            .string(),
                    )
                    .to_owned(),
            )
            .await?;

        let credential_query = format!(
            "UPDATE {} SET {} = {}",
            Credential::Table.to_string(),
            Credential::RedirectUri.to_string(),
            Credential::RedirectUriTemp.to_string(),
        );

        manager
            .get_connection()
            .execute_unprepared(&credential_query)
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Credential::Table)
                    .drop_column(Credential::RedirectUriTemp)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(Iden)]
pub enum Credential {
    Table,
    RedirectUri,
    RedirectUriTemp,
}
