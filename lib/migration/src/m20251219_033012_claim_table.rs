use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{boolean, string};

use crate::datatype::{ColumnDefExt, timestamp, uuid_char};
use crate::m20240110_000001_initial::Credential;
use crate::m20240611_110000_introduce_path_and_array::{Claim, ClaimSchema};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DatabaseBackend::Postgres => {}
            DatabaseBackend::MySql => {
                // remove default values
                manager
                    .alter_table(
                        Table::alter()
                            .table(Claim::Table)
                            .modify_column(
                                ColumnDef::new(ClaimNew::SelectivelyDisclosable)
                                    .boolean()
                                    .not_null(),
                            )
                            .modify_column(ColumnDef::new(Claim::Path).string().not_null())
                            .to_owned(),
                    )
                    .await?;
            }
            DatabaseBackend::Sqlite => sqlite_migration(manager).await?,
        };

        Ok(())
    }
}

#[derive(Clone, Iden)]
enum ClaimNew {
    Table,
    Id,
    ClaimSchemaId,
    CredentialId,
    Value,
    CreatedDate,
    LastModified,
    Path,
    SelectivelyDisclosable,
}

async fn sqlite_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let db = manager.get_connection();

    db.execute_unprepared("PRAGMA defer_foreign_keys = ON;")
        .await?;

    // Create new table with the correct columns
    manager
        .create_table(
            Table::create()
                .table(ClaimNew::Table)
                .col(uuid_char(ClaimNew::Id).primary_key())
                .col(timestamp(ClaimNew::CreatedDate, manager))
                .col(timestamp(ClaimNew::LastModified, manager))
                .col(uuid_char(ClaimNew::ClaimSchemaId))
                .col(uuid_char(ClaimNew::CredentialId))
                .col(ColumnDef::new(ClaimNew::Value).large_blob(manager).null())
                .col(string(ClaimNew::Path))
                .col(boolean(ClaimNew::SelectivelyDisclosable))
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-Claim-ClaimSchemaId")
                        .from_tbl(ClaimNew::Table)
                        .from_col(ClaimNew::ClaimSchemaId)
                        .to_tbl(ClaimSchema::Table)
                        .to_col(ClaimSchema::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-Claim-CredentialId")
                        .from_tbl(ClaimNew::Table)
                        .from_col(ClaimNew::CredentialId)
                        .to_tbl(Credential::Table)
                        .to_col(Credential::Id),
                )
                .to_owned(),
        )
        .await?;

    // Copy data from old table to new table
    let copied_columns = vec![
        ClaimNew::Id,
        ClaimNew::CreatedDate,
        ClaimNew::LastModified,
        ClaimNew::ClaimSchemaId,
        ClaimNew::CredentialId,
        ClaimNew::Value,
        ClaimNew::Path,
        ClaimNew::SelectivelyDisclosable,
    ];
    manager
        .exec_stmt(
            Query::insert()
                .into_table(ClaimNew::Table)
                .columns(copied_columns.to_vec())
                .select_from(
                    Query::select()
                        .from(Claim::Table)
                        .columns(copied_columns)
                        .to_owned(),
                )
                .map_err(|e| DbErr::Migration(e.to_string()))?
                .to_owned(),
        )
        .await?;

    // Drop old table & rename new table
    manager
        .drop_table(Table::drop().table(Claim::Table).to_owned())
        .await?;

    manager
        .rename_table(
            Table::rename()
                .table(ClaimNew::Table, Claim::Table)
                .to_owned(),
        )
        .await?;

    db.execute_unprepared("PRAGMA defer_foreign_keys = OFF;")
        .await?;

    Ok(())
}
