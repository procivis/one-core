use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

pub const UNIQUE_INTERACTION_NONCE_ID_INDEX: &str = "index-Interaction-NonceId-Unique";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == DbBackend::Postgres {
            return Ok(());
        }

        manager
            .alter_table(
                Table::alter()
                    .table(Interaction::Table)
                    .add_column(ColumnDef::new(Interaction::NonceId).char_len(36).null())
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name(UNIQUE_INTERACTION_NONCE_ID_INDEX)
                    .unique()
                    .table(Interaction::Table)
                    .col(Interaction::NonceId)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum Interaction {
    Table,
    NonceId,
}
