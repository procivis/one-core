use sea_orm::{ConnectionTrait, FromQueryResult};
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{boolean, string, string_len, string_len_null};
use sha2::{Digest, Sha256};

use crate::datatype::{large_blob, large_blob_null, timestamp, timestamp_null, uuid_char};
use crate::foreign_key::{disable_foreign_key_checks, enable_foreign_key_checks};
use crate::migrations::m20260417_150300_initial::Organisation;
use crate::nullable_unique_idx::{NullableIdxOpts, add_nullable_unique_idx};
use crate::supported_db_type::{SupportedDbType, WithSupportedDbType};

#[derive(DeriveMigrationName)]
pub struct Migration;

const FK_KEY_ORGANISATION: &str = "fk-Key-OrganisationId";
const INDEX_UNIQUE_KEY_NAME_ORGANISATION_DELETED_AT: &str =
    "index_Key_Name-OrganisationId-DeletedAt_Unique";
const INDEX_KEY_CREATED_DATE: &str = "index-Key-CreatedDate";
const INDEX_UNIQUE_KEY_ORGANISATION_PUBLIC_KEY_HASH_DELETED_AT: &str =
    "index-Key-OrganisationId-PublicKeyHash-DeletedAt-Unique";
const INDEX_KEY_ORGANISATION_ID_CREATED_DATE_ID_DELETED_AT: &str =
    "index-Key-OrganisationId-CreatedDate-Id-DeletedAt";
const PAGE_SIZE: u64 = 1000;

/// Adds the SHA-256 of the public key and makes it unique per organisation.
///
/// Looking up a key by its public key (a BLOB) scanned the whole table, and nothing prevented
/// the same public key from being stored twice in an organisation.
/// Also adds an index for listing the keys of an organisation (default order: newest first), so
/// a page can walk the index and stop at the limit, and the count is an index-only scan.
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let db_type = manager.supported_db_type();

        // Before any schema change: MariaDB commits DDL implicitly, a later failure would leave
        // a NOT NULL column behind that the running (previous) version does not fill.
        check_no_duplicates(db, db_type).await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Key::Table)
                    .add_column_if_not_exists(string_len_null(Key::PublicKeyHash, 64))
                    .to_owned(),
            )
            .await?;

        match db_type {
            SupportedDbType::MySql => {
                db.execute_unprepared(
                    "UPDATE `key` SET public_key_hash = SHA2(public_key, 256) WHERE public_key_hash IS NULL",
                )
                .await?;
            }
            SupportedDbType::Postgres => {
                db.execute_unprepared(
                    "UPDATE key SET public_key_hash = encode(sha256(public_key), 'hex') WHERE public_key_hash IS NULL",
                )
                .await?;
            }
            SupportedDbType::Sqlite => backfill_rows(db).await?,
        }

        if db_type == SupportedDbType::Sqlite {
            disable_foreign_key_checks(manager).await?;
            make_hash_not_null_sqlite(manager).await?;
            enable_foreign_key_checks(manager).await?;
        } else {
            manager
                .alter_table(
                    Table::alter()
                        .table(Key::Table)
                        .modify_column(string_len(Key::PublicKeyHash, 64))
                        .to_owned(),
                )
                .await?;
        }

        add_nullable_unique_idx(
            Key::Table,
            Key::DeletedAt,
            INDEX_UNIQUE_KEY_ORGANISATION_PUBLIC_KEY_HASH_DELETED_AT,
            NullableIdxOpts {
                non_nullable_columns: vec![Key::OrganisationId, Key::PublicKeyHash],
                ..Default::default()
            },
            manager,
        )
        .await?;

        manager
            .create_index(
                Index::create()
                    .name(INDEX_KEY_ORGANISATION_ID_CREATED_DATE_ID_DELETED_AT)
                    .table(Key::Table)
                    .col(Key::OrganisationId)
                    .col(Key::CreatedDate)
                    .col(Key::Id)
                    .col(Key::DeletedAt)
                    .to_owned(),
            )
            .await
    }
}

fn public_key_hash(public_key: &[u8]) -> String {
    hex::encode(Sha256::digest(public_key))
}

#[derive(FromQueryResult)]
struct KeyRow {
    id: String,
    public_key: Vec<u8>,
}

async fn backfill_rows(db: &impl ConnectionTrait) -> Result<(), DbErr> {
    let mut cursor: Option<String> = None;
    loop {
        let mut query = Query::select();
        query
            .columns([Key::Id, Key::PublicKey])
            .from(Key::Table)
            .order_by(Key::Id, Order::Asc)
            .limit(PAGE_SIZE);
        if let Some(id) = &cursor {
            query.and_where(Expr::col(Key::Id).gt(id));
        }
        let rows = KeyRow::find_by_statement(db.get_database_backend().build(&query))
            .all(db)
            .await?;
        let Some(last) = rows.last() else {
            return Ok(());
        };
        cursor = Some(last.id.clone());
        for row in &rows {
            db.execute(
                Query::update()
                    .table(Key::Table)
                    .value(Key::PublicKeyHash, public_key_hash(&row.public_key))
                    .and_where(Expr::col(Key::Id).eq(&row.id)),
            )
            .await?;
        }
    }
}

#[derive(FromQueryResult)]
struct DuplicateCount {
    count: i64,
}

/// Fails with a readable error instead of a unique constraint violation, as duplicates cannot be
/// resolved automatically (keys are referenced by identifiers, credentials, ...).
async fn check_no_duplicates(
    db: &impl ConnectionTrait,
    db_type: SupportedDbType,
) -> Result<(), DbErr> {
    // MariaDB compares only a prefix of BLOBs when grouping, hence the hash
    let (key_table, public_key) = match db_type {
        SupportedDbType::MySql => ("`key`", "SHA2(public_key, 256)"),
        SupportedDbType::Postgres => ("key", "sha256(public_key)"),
        SupportedDbType::Sqlite => ("key", "public_key"),
    };
    let statement = sea_orm::Statement::from_string(
        db.get_database_backend(),
        format!(
            "SELECT COUNT(*) AS count FROM (SELECT organisation_id FROM {key_table} WHERE deleted_at IS NULL \
             GROUP BY organisation_id, {public_key} HAVING COUNT(*) > 1) duplicates"
        ),
    );
    let count = DuplicateCount::find_by_statement(statement)
        .one(db)
        .await?
        .map(|row| row.count)
        .unwrap_or_default();
    if count > 0 {
        return Err(DbErr::Migration(format!(
            "{count} public keys are stored more than once (not deleted) within the same organisation, \
             soft-delete the duplicate keys before migrating"
        )));
    }
    Ok(())
}

async fn make_hash_not_null_sqlite(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(KeyNew::Table)
                .col(uuid_char(Key::Id).primary_key())
                .col(timestamp(Key::CreatedDate, manager))
                .col(timestamp(Key::LastModified, manager))
                .col(timestamp_null(Key::DeletedAt, manager))
                .col(string(Key::Name))
                .col(large_blob(Key::PublicKey, manager))
                .col(string_len(Key::PublicKeyHash, 64))
                .col(large_blob_null(Key::KeyReference, manager))
                .col(string(Key::StorageType))
                .col(string(Key::KeyType))
                .col(uuid_char(Key::OrganisationId))
                .col(boolean(Key::Autogenerated))
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_KEY_ORGANISATION)
                        .from_tbl(KeyNew::Table)
                        .from_col(Key::OrganisationId)
                        .to_tbl(Organisation::Table)
                        .to_col(Organisation::Id),
                )
                .to_owned(),
        )
        .await?;

    let copied_columns = vec![
        Key::Id,
        Key::CreatedDate,
        Key::LastModified,
        Key::DeletedAt,
        Key::Name,
        Key::PublicKey,
        Key::PublicKeyHash,
        Key::KeyReference,
        Key::StorageType,
        Key::KeyType,
        Key::OrganisationId,
        Key::Autogenerated,
    ];
    manager
        .exec_stmt(
            Query::insert()
                .into_table(KeyNew::Table)
                .columns(copied_columns.clone())
                .select_from(
                    Query::select()
                        .columns(copied_columns)
                        .from(Key::Table)
                        .to_owned(),
                )
                .map_err(|e| DbErr::Migration(e.to_string()))?
                .to_owned(),
        )
        .await?;

    manager
        .drop_table(Table::drop().table(Key::Table).to_owned())
        .await?;

    manager
        .rename_table(Table::rename().table(KeyNew::Table, Key::Table).to_owned())
        .await?;

    manager
        .create_index(
            Index::create()
                .if_not_exists()
                .name(INDEX_KEY_CREATED_DATE)
                .table(Key::Table)
                .col(Key::CreatedDate)
                .to_owned(),
        )
        .await?;

    add_nullable_unique_idx(
        Key::Table,
        Key::DeletedAt,
        INDEX_UNIQUE_KEY_NAME_ORGANISATION_DELETED_AT,
        NullableIdxOpts {
            non_nullable_columns: vec![Key::Name, Key::OrganisationId],
            ..Default::default()
        },
        manager,
    )
    .await
}

#[derive(Clone, DeriveIden)]
#[allow(clippy::enum_variant_names)]
enum Key {
    Table,
    Id,
    CreatedDate,
    LastModified,
    DeletedAt,
    Name,
    PublicKey,
    PublicKeyHash,
    KeyReference,
    StorageType,
    KeyType,
    OrganisationId,
    Autogenerated,
}

#[derive(DeriveIden)]
enum KeyNew {
    Table,
}
