use sea_orm::{ConnectionTrait, FromQueryResult};
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{boolean, string, string_len, text_null};
use sea_orm_migration_sqlite::{SchemaManagerExt, TableExt};
use sha2::{Digest, Sha256};

use crate::datatype::{timestamp, timestamp_null, uuid_char};
use crate::foreign_key::{disable_foreign_key_checks, enable_foreign_key_checks};
use crate::nullable_unique_idx::{NullableIdxOpts, add_nullable_unique_idx};
use crate::supported_db_type::{SupportedDbType, WithSupportedDbType};

#[derive(DeriveMigrationName)]
pub struct Migration;

const INDEX_NAME: &str = "index-Did-Did-OrganisationId-DeletedAt-Unique";
const PAGE_SIZE: u64 = 1000;

/// Moves the unique index of the DID from the DID itself to its SHA-256.
///
/// A DID can be longer than an index key. MariaDB then builds a `USING HASH` unique index, and
/// its duplicate check deadlocks concurrent inserts.
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let db_type = manager.supported_db_type();
        manager
            .alter_table(
                Table::alter()
                    .table(Did::Table)
                    .add_column_if_not_exists(string_len(Did::DidHash, 64).default(""))
                    .to_owned(),
            )
            .await?;
        let drop_index = match db_type {
            SupportedDbType::MySql => {
                format!("ALTER TABLE did DROP INDEX IF EXISTS `{INDEX_NAME}`")
            }
            _ => format!("DROP INDEX IF EXISTS \"{INDEX_NAME}\""),
        };
        db.execute_unprepared(&drop_index).await?;

        if db_type == SupportedDbType::Sqlite {
            up_sqlite(manager).await?;
        } else {
            db.execute_unprepared(&format!(
                "ALTER TABLE {table} ALTER COLUMN {column} DROP DEFAULT",
                table = Did::Table.to_string(),
                column = Did::DidHash.to_string(),
            ))
            .await?;
        }

        match db_type {
            SupportedDbType::MySql => {
                db.execute_unprepared(
                    "UPDATE did SET did_hash = SHA2(CONVERT(did USING utf8mb4), 256) WHERE did_hash = ''",
                )
                .await?;
            }
            SupportedDbType::Postgres => {
                db.execute_unprepared(
                    "UPDATE did SET did_hash = encode(sha256(convert_to(did, 'UTF8')), 'hex') WHERE did_hash = ''",
                )
                .await?;
            }
            SupportedDbType::Sqlite => backfill_rows(db).await?,
        }

        add_nullable_unique_idx(
            Did::Table,
            Did::DeletedAt,
            INDEX_NAME,
            NullableIdxOpts {
                non_nullable_columns: vec![Did::DidHash, Did::OrganisationId],
                ..Default::default()
            },
            manager,
        )
        .await
    }
}

fn did_hash(did: &str) -> String {
    hex::encode(Sha256::digest(did))
}

#[derive(FromQueryResult)]
struct DidRow {
    id: String,
    did: String,
}

async fn backfill_rows(db: &impl ConnectionTrait) -> Result<(), DbErr> {
    let mut cursor: Option<String> = None;
    loop {
        let mut query = Query::select();
        query
            .columns([Did::Id, Did::Did])
            .from(Did::Table)
            .order_by(Did::Id, Order::Asc)
            .limit(PAGE_SIZE);
        if let Some(id) = &cursor {
            query.and_where(Expr::col(Did::Id).gt(id));
        }
        let rows = DidRow::find_by_statement(db.get_database_backend().build(&query))
            .all(db)
            .await?;
        let Some(last) = rows.last() else {
            return Ok(());
        };
        cursor = Some(last.id.clone());
        for row in &rows {
            db.execute(
                Query::update()
                    .table(Did::Table)
                    .value(Did::DidHash, did_hash(&row.did))
                    .and_where(Expr::col(Did::Id).eq(&row.id)),
            )
            .await?;
        }
    }
}

async fn up_sqlite(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    disable_foreign_key_checks(manager).await?;

    manager
        .recreate_table(
            Table::recreate()
                .table(Did::Table)
                .modify_column(uuid_char(Did::Id).primary_key())
                .modify_column(timestamp(Did::CreatedDate, manager))
                .modify_column(timestamp(Did::LastModified, manager))
                .modify_column(timestamp_null(Did::DeletedAt, manager))
                .modify_column(string_len(Did::Did, 4000))
                .modify_column(string_len(Did::DidHash, 64))
                .modify_column(string(Did::Name))
                .modify_column(string(Did::Type))
                .modify_column(string(Did::Method))
                .modify_column(boolean(Did::Deactivated))
                .modify_column(text_null(Did::Log))
                .modify_column(uuid_char(Did::OrganisationId))
                .to_owned(),
        )
        .await?;

    enable_foreign_key_checks(manager).await
}

#[derive(Clone, DeriveIden)]
#[allow(clippy::enum_variant_names)]
enum Did {
    Table,
    Id,
    CreatedDate,
    LastModified,
    DeletedAt,
    Did,
    DidHash,
    Name,
    Type,
    Method,
    Deactivated,
    Log,
    OrganisationId,
}
