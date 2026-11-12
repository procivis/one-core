use sea_orm::{ConnectionTrait, FromQueryResult};
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{string, string_len, string_null, text};
use sea_orm_migration_sqlite::{SchemaManagerExt, TableExt};
use sha2::{Digest, Sha256};

use crate::datatype::{timestamp, timestamp_null, uuid_char};
use crate::nullable_unique_idx::{NullableIdxOpts, add_nullable_unique_idx};
use crate::supported_db_type::{SupportedDbType, WithSupportedDbType};

#[derive(DeriveMigrationName)]
pub struct Migration;

const INDEX_NAME: &str = "index-TrustListSubscription-Reference-Col-DeactivatedAt-Unique";
const PAGE_SIZE: u64 = 1000;

/// Moves the unique index of the subscription reference from the reference itself to its SHA-256.
///
/// A reference can be longer than an index key. MariaDB then builds a `USING HASH` unique index,
/// and its duplicate check deadlocks concurrent inserts.
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let db_type = manager.supported_db_type();
        manager
            .alter_table(
                Table::alter()
                    .table(TrustListSubscription::Table)
                    .add_column_if_not_exists(
                        string_len(TrustListSubscription::ReferenceHash, 64).default(""),
                    )
                    .to_owned(),
            )
            .await?;
        let drop_index = match db_type {
            SupportedDbType::MySql => {
                format!("ALTER TABLE trust_list_subscription DROP INDEX IF EXISTS `{INDEX_NAME}`")
            }
            _ => format!("DROP INDEX IF EXISTS \"{INDEX_NAME}\""),
        };
        db.execute_unprepared(&drop_index).await?;

        if db_type == SupportedDbType::Sqlite {
            up_sqlite(manager).await?;
        } else {
            db.execute_unprepared(&format!(
                "ALTER TABLE {table} ALTER COLUMN {column} DROP DEFAULT",
                table = TrustListSubscription::Table.to_string(),
                column = TrustListSubscription::ReferenceHash.to_string(),
            ))
            .await?;
        }

        match db_type {
            SupportedDbType::MySql => {
                db.execute_unprepared(
                    "UPDATE trust_list_subscription SET reference_hash = SHA2(CONVERT(reference USING utf8mb4), 256) WHERE reference_hash = ''",
                )
                .await?;
            }
            SupportedDbType::Postgres => {
                db.execute_unprepared(
                    "UPDATE trust_list_subscription SET reference_hash = encode(sha256(convert_to(reference, 'UTF8')), 'hex') WHERE reference_hash = ''",
                )
                .await?;
            }
            SupportedDbType::Sqlite => backfill_rows(db).await?,
        }

        add_nullable_unique_idx(
            TrustListSubscription::Table,
            TrustListSubscription::DeactivatedAt,
            INDEX_NAME,
            NullableIdxOpts {
                non_nullable_columns: vec![
                    TrustListSubscription::ReferenceHash,
                    TrustListSubscription::TrustCollectionId,
                ],
                null_value: Some("not_deactivated"),
                ..Default::default()
            },
            manager,
        )
        .await
    }
}

fn reference_hash(reference: &str) -> String {
    hex::encode(Sha256::digest(reference))
}

#[derive(FromQueryResult)]
struct Row {
    id: String,
    reference: String,
}

async fn backfill_rows(db: &impl ConnectionTrait) -> Result<(), DbErr> {
    let mut cursor: Option<String> = None;
    loop {
        let mut query = Query::select();
        query
            .columns([TrustListSubscription::Id, TrustListSubscription::Reference])
            .from(TrustListSubscription::Table)
            .order_by(TrustListSubscription::Id, Order::Asc)
            .limit(PAGE_SIZE);
        if let Some(id) = &cursor {
            query.and_where(Expr::col(TrustListSubscription::Id).gt(id));
        }
        let rows = Row::find_by_statement(db.get_database_backend().build(&query))
            .all(db)
            .await?;
        let Some(last) = rows.last() else {
            return Ok(());
        };
        cursor = Some(last.id.clone());
        for row in &rows {
            db.execute(
                Query::update()
                    .table(TrustListSubscription::Table)
                    .value(
                        TrustListSubscription::ReferenceHash,
                        reference_hash(&row.reference),
                    )
                    .and_where(Expr::col(TrustListSubscription::Id).eq(&row.id)),
            )
            .await?;
        }
    }
}

async fn up_sqlite(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let db = manager.get_connection();
    db.execute_unprepared("PRAGMA defer_foreign_keys = ON;")
        .await?;

    manager
        .recreate_table(
            Table::recreate()
                .table(TrustListSubscription::Table)
                .modify_column(uuid_char(TrustListSubscription::Id).primary_key())
                .modify_column(timestamp(TrustListSubscription::CreatedDate, manager))
                .modify_column(timestamp(TrustListSubscription::LastModified, manager))
                .modify_column(timestamp_null(
                    TrustListSubscription::DeactivatedAt,
                    manager,
                ))
                .modify_column(string_null(TrustListSubscription::Role))
                .modify_column(string(TrustListSubscription::Type))
                .modify_column(string(TrustListSubscription::State))
                .modify_column(string(TrustListSubscription::Name))
                .modify_column(text(TrustListSubscription::Reference))
                .modify_column(string_len(TrustListSubscription::ReferenceHash, 64))
                .modify_column(uuid_char(TrustListSubscription::TrustCollectionId))
                .to_owned(),
        )
        .await?;

    db.execute_unprepared("PRAGMA defer_foreign_keys = OFF;")
        .await
        .map(|_| ())
}

#[derive(Clone, DeriveIden)]
enum TrustListSubscription {
    Table,
    Id,
    CreatedDate,
    LastModified,
    DeactivatedAt,
    Name,
    Role,
    Type,
    State,
    Reference,
    ReferenceHash,
    TrustCollectionId,
}
