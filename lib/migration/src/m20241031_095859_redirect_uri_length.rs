use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
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
