use sea_orm_migration::prelude::*;

use crate::datatype::ColumnDefExt;
use crate::m20240110_000001_initial::Organisation;
use crate::m20240130_105023_add_history::History;
use crate::m20250820_084021_wallet_unit_table::UNIQUE_WALLET_UNIT_PUBLIC_KEY_INDEX;

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
        // Delete existing wallet unit history
        manager
            .exec_stmt(
                Query::delete()
                    .from_table(History::Table)
                    .and_where(Expr::col(History::EntityType).eq("WALLET_UNIT"))
                    .to_owned(),
            )
            .await?;
        // Drope entire table
        manager
            .drop_table(Table::drop().table(WalletUnit::Table).to_owned())
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(WalletUnit::Table)
                    .col(
                        ColumnDef::new(WalletUnit::Id)
                            .char_len(36)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(WalletUnit::OrganisationId)
                            .char_len(36)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(WalletUnit::CreatedDate)
                            .datetime_millisecond_precision(manager)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(WalletUnit::LastModified)
                            .datetime_millisecond_precision(manager)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(WalletUnit::LastIssuance)
                            .datetime_millisecond_precision(manager)
                            .null(),
                    )
                    .col(ColumnDef::new(WalletUnit::Name).string().not_null())
                    .col(ColumnDef::new(WalletUnit::Os).string().not_null())
                    .col(ColumnDef::new(WalletUnit::Status).string().not_null())
                    .col(ColumnDef::new(WalletUnit::Nonce).string().null())
                    .col(ColumnDef::new(WalletUnit::PublicKey).string().null())
                    .col(
                        ColumnDef::new(WalletUnit::WalletProviderType)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(WalletUnit::WalletProviderName)
                            .string()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-WalletUnit-OrganisationId")
                            .from_tbl(WalletUnit::Table)
                            .from_col(WalletUnit::OrganisationId)
                            .to_tbl(Organisation::Table)
                            .to_col(Organisation::Id),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name(UNIQUE_WALLET_UNIT_PUBLIC_KEY_INDEX)
                    .table(WalletUnit::Table)
                    .col(WalletUnit::PublicKey)
                    .unique()
                    .to_owned(),
            )
            .await
    }
}

#[derive(Iden)]
pub enum WalletUnit {
    Table,
    Id,
    OrganisationId,
    CreatedDate,
    LastModified,
    LastIssuance,
    Name,
    Os,
    Status,
    Nonce,
    PublicKey,
    WalletProviderType,
    WalletProviderName,
}
