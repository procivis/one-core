use sea_orm_migration::prelude::*;

use crate::m20240424_124450_add_json_ld_context::JsonLdContext;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .rename_table(
                Table::rename()
                    .table(JsonLdContext::Table, RemoteEntityCache::Table)
                    .to_owned(),
            )
            .await?;

        // Separate operations - SQLite does not support multiple alter operations
        manager
            .alter_table(
                Table::alter()
                    .table(RemoteEntityCache::Table)
                    .add_column_if_not_exists(
                        ColumnDef::new(RemoteEntityCache::Type)
                            .enumeration(
                                RemoteEntityCache::Table,
                                [
                                    RemoteEntityType::DidDocument,
                                    RemoteEntityType::JsonLdContext,
                                    RemoteEntityType::StatusListCredential,
                                ],
                            )
                            .not_null()
                            .default("JSON_LD_CONTEXT"),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(RemoteEntityCache::Table)
                    .rename_column(JsonLdContext::Url, RemoteEntityCache::Key)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(RemoteEntityCache::Table)
                    .rename_column(JsonLdContext::Context, RemoteEntityCache::Value)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, _: &SchemaManager) -> Result<(), DbErr> {
        Err(DbErr::Migration("One way migration".to_owned()))
    }
}

#[derive(Iden)]
pub enum RemoteEntityCache {
    Table,
    Key,
    Value,
    Type,
}

#[derive(Iden)]
pub enum RemoteEntityType {
    #[iden = "DID_DOCUMENT"]
    DidDocument,
    #[iden = "JSON_LD_CONTEXT"]
    JsonLdContext,
    #[iden = "STATUSLIST_CREDENTIAL"]
    StatusListCredential,
}
