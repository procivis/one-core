use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::*;

use crate::datatype::{timestamp, uuid_char, uuid_char_null};

#[derive(DeriveMigrationName)]
pub struct Migration;

const UNIQUE_REVOCATION_LIST_INDEX_INDEX: &str = "index-RevocationList-Index-Unique";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DbBackend::Postgres => {
                // Unsupported
            }
            DbBackend::MySql => up_mysql(manager).await?,
            DbBackend::Sqlite => up_sqlite(manager).await?,
        }
        Ok(())
    }
}

async fn up_sqlite(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let statement = Table::alter()
        .table(RevocationListEntry::Table)
        .add_column(string_null(RevocationListEntry::Status))
        .to_owned();
    manager.alter_table(statement).await?;

    manager
        .alter_table(
            Table::alter()
                .table(RevocationListEntry::Table)
                .add_column(string_null(RevocationListEntry::Type))
                .to_owned(),
        )
        .await?;

    manager.get_connection().execute_unprepared(
        r#"
            UPDATE revocation_list_entry
            SET
                status = (SELECT
                    CASE
                        WHEN credential.id IS NOT NULL AND credential.state = 'SUSPENDED' THEN 'SUSPENDED'
                        WHEN credential.id IS NOT NULL AND credential.state IN ('REVOKED', 'REJECTED', 'ERROR') THEN 'REVOKED'
                        WHEN wallet_unit.id IS NOT NULL AND wallet_unit.status IN ('REVOKED', 'ERROR') THEN 'REVOKED'
                        ELSE 'ACTIVE'
                    END
                FROM revocation_list_entry
                    LEFT JOIN credential ON revocation_list_entry.credential_id = credential.id
                    LEFT JOIN wallet_unit_attested_key On revocation_list_entry.id = wallet_unit_attested_key.revocation_list_entry_id
                    LEFT JOIN wallet_unit ON wallet_unit_attested_key.wallet_unit_id = wallet_unit.id),
                type = (SELECT CASE
                    WHEN credential.id IS NOT NULL THEN 'CREDENTIAL'
                    WHEN wallet_unit.id IS NOT NULL THEN 'WUA'
                END FROM revocation_list_entry
                    LEFT JOIN credential ON revocation_list_entry.credential_id = credential.id
                    LEFT JOIN wallet_unit_attested_key On revocation_list_entry.id = wallet_unit_attested_key.revocation_list_entry_id
                    LEFT JOIN wallet_unit ON wallet_unit_attested_key.wallet_unit_id = wallet_unit.id)
            "#
    ).await?;

    manager
        .create_table(
            Table::create()
                .table(RevocationListEntryTemp::Table)
                .col(uuid_char(RevocationListEntry::Id).primary_key())
                .col(timestamp(RevocationListEntry::CreatedDate, manager))
                .col(uuid_char(RevocationListEntry::RevocationListId))
                .col(unsigned(RevocationListEntry::Index))
                .col(uuid_char_null(RevocationListEntry::CredentialId))
                .col(string(RevocationListEntry::Status))
                .col(string(RevocationListEntry::Type))
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name("fk-RevocationListEntry-RevocationListId")
                        .from_tbl(RevocationListEntry::Table)
                        .from_col(RevocationListEntry::RevocationListId)
                        .to_tbl(RevocationList::Table)
                        .to_col(RevocationList::Id),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name("fk-RevocationListEntry-CredentialId")
                        .from_tbl(RevocationListEntry::Table)
                        .from_col(RevocationListEntry::CredentialId)
                        .to_tbl(Credential::Table)
                        .to_col(Credential::Id),
                )
                .to_owned(),
        )
        .await?;

    let copied_columns = vec![
        RevocationListEntry::Id,
        RevocationListEntry::CreatedDate,
        RevocationListEntry::RevocationListId,
        RevocationListEntry::Index,
        RevocationListEntry::CredentialId,
        RevocationListEntry::Status,
        RevocationListEntry::Type,
    ];

    manager
        .exec_stmt(
            Query::insert()
                .into_table(RevocationListEntryTemp::Table)
                .columns(copied_columns.to_vec())
                .select_from(
                    Query::select()
                        .from(RevocationListEntry::Table)
                        .columns(copied_columns)
                        .to_owned(),
                )
                .map_err(|e| DbErr::Migration(e.to_string()))?
                .to_owned(),
        )
        .await?;

    // Disable foreign keys for SQLite
    manager
        .get_connection()
        .execute_unprepared("PRAGMA defer_foreign_keys = ON;")
        .await?;

    // Drop old table
    manager
        .drop_table(Table::drop().table(RevocationListEntry::Table).to_owned())
        .await?;

    // Rename new table to original name
    manager
        .rename_table(
            Table::rename()
                .table(RevocationListEntryTemp::Table, RevocationListEntry::Table)
                .to_owned(),
        )
        .await?;

    // Re-enable foreign keys for SQLite
    manager
        .get_connection()
        .execute_unprepared("PRAGMA defer_foreign_keys = OFF;")
        .await?;

    // Recreate indexes
    manager
        .create_index(
            Index::create()
                .name(UNIQUE_REVOCATION_LIST_INDEX_INDEX)
                .unique()
                .table(RevocationListEntry::Table)
                .col(RevocationListEntry::RevocationListId)
                .col(RevocationListEntry::Index)
                .to_owned(),
        )
        .await?;

    Ok(())
}

async fn up_mysql(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .alter_table(
            Table::alter()
                .table(RevocationListEntry::Table)
                .add_column(string_null(RevocationListEntry::Status))
                .add_column(string_null(RevocationListEntry::Type))
                .to_owned(),
        )
        .await?;

    manager.get_connection().execute_unprepared(
        r#"
            UPDATE revocation_list_entry
                LEFT JOIN credential ON revocation_list_entry.credential_id = credential.id
                LEFT JOIN wallet_unit_attested_key On revocation_list_entry.id = wallet_unit_attested_key.revocation_list_entry_id
                LEFT JOIN wallet_unit ON wallet_unit_attested_key.wallet_unit_id = wallet_unit.id
            SET
                revocation_list_entry.status = CASE
                    WHEN credential.id IS NOT NULL AND credential.state = 'SUSPENDED' THEN 'SUSPENDED'
                    WHEN credential.id IS NOT NULL AND credential.state IN ('REVOKED', 'REJECTED', 'ERROR') THEN 'REVOKED'
                    WHEN wallet_unit.id IS NOT NULL AND wallet_unit.status IN ('REVOKED', 'ERROR') THEN 'REVOKED'
                    ELSE 'ACTIVE'
                END,
                revocation_list_entry.type = CASE
                    WHEN credential.id IS NOT NULL THEN 'CREDENTIAL'
                    WHEN wallet_unit.id IS NOT NULL THEN 'WUA'
                END
            "#
    ).await?;

    manager
        .alter_table(
            Table::alter()
                .table(RevocationListEntry::Table)
                .modify_column(string(RevocationListEntry::Status))
                .modify_column(string(RevocationListEntry::Type))
                .to_owned(),
        )
        .await?;
    Ok(())
}

#[derive(DeriveIden, Clone)]
enum RevocationListEntry {
    Table,
    Id,
    CreatedDate,
    RevocationListId,
    Index,
    CredentialId,
    Status,
    Type,
}

#[derive(DeriveIden)]
enum RevocationListEntryTemp {
    Table,
}

#[derive(DeriveIden)]
enum RevocationList {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum Credential {
    Table,
    Id,
}
