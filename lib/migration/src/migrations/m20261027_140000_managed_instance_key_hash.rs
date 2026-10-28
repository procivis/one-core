use sea_orm::{ConnectionTrait, FromQueryResult};
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::string_len_null;
use sha2::{Digest, Sha256};

use crate::migrations::m20260720_091548_instance::ManagedInstance;
use crate::supported_db_type::{SupportedDbType, WithSupportedDbType};

#[derive(DeriveMigrationName)]
pub struct Migration;

const INDEX_NAME: &str = "index-ManagedInstance-AuthenticationKey-Organisation-Role-Unique";
const PAGE_SIZE: u64 = 1000;

/// Moves the unique index of the authentication key from the JWK to its SHA-256.
///
/// A JWK can be longer than an index key. MariaDB then builds a `USING HASH` unique index, and
/// its duplicate check deadlocks concurrent inserts.
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        manager
            .alter_table(
                Table::alter()
                    .table(ManagedInstance::Table)
                    .add_column_if_not_exists(string_len_null(Col::AuthenticationKeyHash, 64))
                    .to_owned(),
            )
            .await?;
        match manager.supported_db_type() {
            SupportedDbType::MySql => {
                db.execute_unprepared(&format!(
                    "ALTER TABLE managed_instance DROP INDEX IF EXISTS `{INDEX_NAME}`"
                ))
                .await?;
                db.execute_unprepared(
                    "UPDATE managed_instance SET authentication_key_hash = SHA2(CONVERT(authentication_key_jwk USING utf8mb4), 256) \
                     WHERE authentication_key_hash IS NULL AND authentication_key_jwk IS NOT NULL",
                )
                .await?;
            }
            SupportedDbType::Postgres => {
                db.execute_unprepared(&format!("DROP INDEX IF EXISTS \"{INDEX_NAME}\""))
                    .await?;
                db.execute_unprepared(
                    "UPDATE managed_instance SET authentication_key_hash = encode(sha256(convert_to(authentication_key_jwk, 'UTF8')), 'hex') \
                     WHERE authentication_key_hash IS NULL AND authentication_key_jwk IS NOT NULL",
                )
                .await?;
            }
            SupportedDbType::Sqlite => {
                db.execute_unprepared(&format!("DROP INDEX IF EXISTS \"{INDEX_NAME}\""))
                    .await?;
                backfill_rows(db).await?;
            }
        }
        manager
            .create_index(
                Index::create()
                    .name(INDEX_NAME)
                    .unique()
                    .table(ManagedInstance::Table)
                    .col(Col::AuthenticationKeyHash)
                    .col(ManagedInstance::OrganisationId)
                    .col(ManagedInstance::Role)
                    .to_owned(),
            )
            .await
    }
}

#[derive(FromQueryResult)]
struct Row {
    id: String,
    authentication_key_jwk: String,
}

async fn backfill_rows(db: &impl ConnectionTrait) -> Result<(), DbErr> {
    let mut cursor: Option<String> = None;
    loop {
        let mut query = Query::select();
        query
            .columns([ManagedInstance::Id, ManagedInstance::AuthenticationKeyJwk])
            .from(ManagedInstance::Table)
            .and_where(Expr::col(ManagedInstance::AuthenticationKeyJwk).is_not_null())
            .order_by(ManagedInstance::Id, Order::Asc)
            .limit(PAGE_SIZE);
        if let Some(id) = &cursor {
            query.and_where(Expr::col(ManagedInstance::Id).gt(id));
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
                    .table(ManagedInstance::Table)
                    .value(
                        Col::AuthenticationKeyHash,
                        hex::encode(Sha256::digest(&row.authentication_key_jwk)),
                    )
                    .and_where(Expr::col(ManagedInstance::Id).eq(&row.id)),
            )
            .await?;
        }
    }
}

#[derive(DeriveIden)]
enum Col {
    AuthenticationKeyHash,
}
