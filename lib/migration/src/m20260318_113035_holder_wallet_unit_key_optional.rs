use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::string;

use crate::datatype::{timestamp, uuid_char, uuid_char_null};
use crate::m20240110_000001_initial::{Key, Organisation};
use crate::m20251029_144801_add_holder_wallet_unit::HolderWalletUnit;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DbBackend::Postgres => {}
            DbBackend::MySql => {
                manager
                    .alter_table(
                        Table::alter()
                            .table(HolderWalletUnit::Table)
                            .modify_column(uuid_char_null(HolderWalletUnit::AuthenticationKeyId))
                            .to_owned(),
                    )
                    .await?;
            }
            DbBackend::Sqlite => sqlite_migration(manager).await?,
        }
        Ok(())
    }
}

#[derive(Iden)]
enum HolderWalletUnitNew {
    Table,
}

async fn sqlite_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let db = manager.get_connection();

    db.execute_unprepared("PRAGMA defer_foreign_keys = ON;")
        .await?;

    // Create new table with the correct columns
    manager
        .create_table(
            Table::create()
                .table(HolderWalletUnitNew::Table)
                .col(uuid_char(HolderWalletUnit::Id).primary_key())
                .col(timestamp(HolderWalletUnit::CreatedDate, manager))
                .col(timestamp(HolderWalletUnit::LastModified, manager))
                .col(string(HolderWalletUnit::WalletProviderName))
                .col(string(HolderWalletUnit::WalletProviderType))
                .col(string(HolderWalletUnit::WalletProviderUrl))
                .col(uuid_char(HolderWalletUnit::OrganisationId))
                .col(uuid_char_null(HolderWalletUnit::AuthenticationKeyId))
                .col(uuid_char(HolderWalletUnit::ProviderWalletUnitId))
                .col(string(HolderWalletUnit::Status))
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-HolderWalletUnit-Organisation")
                        .from_tbl(HolderWalletUnitNew::Table)
                        .from_col(HolderWalletUnit::OrganisationId)
                        .to_tbl(Organisation::Table)
                        .to_col(Organisation::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-HolderWalletUnitAuthKey-Key")
                        .from_tbl(HolderWalletUnitNew::Table)
                        .from_col(HolderWalletUnit::AuthenticationKeyId)
                        .to_tbl(Key::Table)
                        .to_col(Key::Id),
                )
                .to_owned(),
        )
        .await?;

    // Copy data from old table to new table
    let copied_columns = vec![
        HolderWalletUnit::Id,
        HolderWalletUnit::OrganisationId,
        HolderWalletUnit::AuthenticationKeyId,
        HolderWalletUnit::CreatedDate,
        HolderWalletUnit::LastModified,
        HolderWalletUnit::ProviderWalletUnitId,
        HolderWalletUnit::WalletProviderUrl,
        HolderWalletUnit::WalletProviderType,
        HolderWalletUnit::WalletProviderName,
        HolderWalletUnit::Status,
    ];
    manager
        .exec_stmt(
            Query::insert()
                .into_table(HolderWalletUnitNew::Table)
                .columns(copied_columns.to_vec())
                .select_from(
                    Query::select()
                        .from(HolderWalletUnit::Table)
                        .columns(copied_columns)
                        .to_owned(),
                )
                .map_err(|e| DbErr::Migration(e.to_string()))?
                .to_owned(),
        )
        .await?;

    // Drop old table & rename new table
    manager
        .drop_table(Table::drop().table(HolderWalletUnit::Table).to_owned())
        .await?;

    manager
        .rename_table(
            Table::rename()
                .table(HolderWalletUnitNew::Table, HolderWalletUnit::Table)
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .unique()
                .name("index-HolderWalletUnit-AuthenticationKey-Unique")
                .table(HolderWalletUnit::Table)
                .col(HolderWalletUnit::AuthenticationKeyId)
                .to_owned(),
        )
        .await?;

    db.execute_unprepared("PRAGMA defer_foreign_keys = OFF;")
        .await?;

    Ok(())
}
