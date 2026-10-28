use sea_orm::{ConnectionTrait, FromQueryResult};
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{string, string_len, string_null, text};
use sha2::{Digest, Sha256};

use crate::datatype::{timestamp, timestamp_null, uuid_char};
use crate::migrations::m20260417_150300_initial::TrustCollection;
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
        .create_table(
            Table::create()
                .table(TrustListSubscriptionNew::Table)
                .col(uuid_char(TrustListSubscription::Id).primary_key())
                .col(timestamp(TrustListSubscription::CreatedDate, manager))
                .col(timestamp(TrustListSubscription::LastModified, manager))
                .col(timestamp_null(
                    TrustListSubscription::DeactivatedAt,
                    manager,
                ))
                .col(string_null(TrustListSubscription::Role))
                .col(string(TrustListSubscription::Type))
                .col(string(TrustListSubscription::State))
                .col(string(TrustListSubscription::Name))
                .col(text(TrustListSubscription::Reference))
                .col(string_len(TrustListSubscription::ReferenceHash, 64))
                .col(uuid_char(TrustListSubscription::TrustCollectionId))
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name("fk-TrustListSubscription-TrustCollectionId")
                        .from_tbl(TrustListSubscriptionNew::Table)
                        .from_col(TrustListSubscription::TrustCollectionId)
                        .to_tbl(TrustCollection::Table)
                        .to_col(TrustCollection::Id),
                )
                .to_owned(),
        )
        .await?;

    let copied_columns = vec![
        TrustListSubscription::Id,
        TrustListSubscription::CreatedDate,
        TrustListSubscription::LastModified,
        TrustListSubscription::DeactivatedAt,
        TrustListSubscription::Role,
        TrustListSubscription::Type,
        TrustListSubscription::State,
        TrustListSubscription::Name,
        TrustListSubscription::Reference,
        TrustListSubscription::ReferenceHash,
        TrustListSubscription::TrustCollectionId,
    ];
    manager
        .exec_stmt(
            Query::insert()
                .into_table(TrustListSubscriptionNew::Table)
                .columns(copied_columns.clone())
                .select_from(
                    Query::select()
                        .columns(copied_columns)
                        .from(TrustListSubscription::Table)
                        .to_owned(),
                )
                .map_err(|e| DbErr::Migration(e.to_string()))?
                .to_owned(),
        )
        .await?;

    manager
        .drop_table(Table::drop().table(TrustListSubscription::Table).to_owned())
        .await?;
    manager
        .rename_table(
            Table::rename()
                .table(
                    TrustListSubscriptionNew::Table,
                    TrustListSubscription::Table,
                )
                .to_owned(),
        )
        .await?;

    add_nullable_unique_idx(
        TrustListSubscription::Table,
        TrustListSubscription::DeactivatedAt,
        "index-TrustListSubscription-Name-Col-DeactivatedAt-Unique",
        NullableIdxOpts {
            non_nullable_columns: vec![
                TrustListSubscription::Name,
                TrustListSubscription::TrustCollectionId,
            ],
            null_value: Some("not_deactivated"),
            ..Default::default()
        },
        manager,
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

#[derive(DeriveIden)]
enum TrustListSubscriptionNew {
    Table,
}
