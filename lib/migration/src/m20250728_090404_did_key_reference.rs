use std::collections::HashMap;

use sea_orm::{DatabaseBackend, FromQueryResult};
use sea_orm_migration::prelude::*;
use shared_types::{DidId, KeyId};

use crate::m20240110_000001_initial::{Did, Key, KeyDid, KeyRole};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(Debug, FromQueryResult)]
pub struct DidQueryResult {
    id: DidId,
    did: String,
    method: String,
    key_id: KeyId,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let backend = db.get_database_backend();

        let entries = DidQueryResult::find_by_statement(
            backend.build(
                Query::select()
                    .distinct()
                    .columns([Did::Id, Did::Did, Did::Method])
                    .column((KeyDid::Table, KeyDid::KeyId))
                    .from(Did::Table)
                    .inner_join(
                        KeyDid::Table,
                        Expr::col((Did::Table, Did::Id)).equals((KeyDid::Table, KeyDid::DidId)),
                    ),
            ),
        )
        .all(db)
        .await?;

        let mut reference_mapping: HashMap<(DidId, KeyId), String> = HashMap::new();
        entries.iter().try_for_each(
            |DidQueryResult {
                 id,
                 method,
                 did,
                 key_id,
             }| {
                let reference = match method.as_str() {
                    "KEY" => did
                        .strip_prefix("did:key:")
                        .ok_or(DbErr::Custom("invalid did:key value".to_string()))?
                        .to_string(),
                    "JWK" => "0".to_string(),
                    "WEB" | "WEBVH" => format!("key-{key_id}"),
                    method => {
                        return Err(DbErr::Custom(format!("Unknown did method: {method}")));
                    }
                };
                reference_mapping.insert((*id, *key_id), reference);
                Ok::<(), DbErr>(())
            },
        )?;

        manager
            .alter_table(
                Table::alter()
                    .table(KeyDid::Table)
                    .add_column(ColumnDef::new(KeyDidNew::Reference).string_len(4000).null())
                    .to_owned(),
            )
            .await?;

        for ((did_id, key_id), reference) in reference_mapping {
            db.execute(
                backend.build(
                    Query::update()
                        .table(KeyDid::Table)
                        .value(KeyDidNew::Reference, reference)
                        .and_where(Expr::col(KeyDid::DidId).eq(did_id))
                        .and_where(Expr::col(KeyDid::KeyId).eq(key_id)),
                ),
            )
            .await?;
        }

        match backend {
            DatabaseBackend::MySql | DatabaseBackend::Postgres => {
                manager
                    .alter_table(
                        Table::alter()
                            .table(KeyDid::Table)
                            .modify_column(
                                ColumnDef::new(KeyDidNew::Reference)
                                    .string_len(4000)
                                    .not_null(),
                            )
                            .to_owned(),
                    )
                    .await?;
            }
            DatabaseBackend::Sqlite => recreate_table(manager).await?,
        };

        Ok(())
    }
}

async fn recreate_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(KeyDidNew::Table)
                .col(ColumnDef::new(KeyDidNew::DidId).char_len(36).not_null())
                .col(ColumnDef::new(KeyDidNew::KeyId).char_len(36).not_null())
                .col(
                    ColumnDef::new(KeyDidNew::Role)
                        .enumeration(
                            KeyDidNew::Table,
                            [
                                KeyRole::Authentication,
                                KeyRole::AssertionMethod,
                                KeyRole::KeyAgreement,
                                KeyRole::CapabilityInvocation,
                                KeyRole::CapabilityDelegation,
                            ],
                        )
                        .not_null(),
                )
                .col(
                    ColumnDef::new(KeyDidNew::Reference)
                        .string_len(4000)
                        .not_null(),
                )
                .primary_key(
                    Index::create()
                        .name("pk-KeyDid")
                        .col(KeyDidNew::DidId)
                        .col(KeyDidNew::KeyId)
                        .col(KeyDidNew::Role)
                        .primary(),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name("fk-KeyDid-DidId")
                        .from_tbl(KeyDidNew::Table)
                        .from_col(KeyDidNew::DidId)
                        .to_tbl(Did::Table)
                        .to_col(Did::Id),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name("fk-KeyDid-KeyId")
                        .from_tbl(KeyDidNew::Table)
                        .from_col(KeyDidNew::KeyId)
                        .to_tbl(Key::Table)
                        .to_col(Key::Id),
                )
                .to_owned(),
        )
        .await?;

    let copied_columns = [
        KeyDidNew::DidId,
        KeyDidNew::KeyId,
        KeyDidNew::Role,
        KeyDidNew::Reference,
    ];

    manager
        .exec_stmt(
            Query::insert()
                .into_table(KeyDidNew::Table)
                .columns(copied_columns)
                .select_from(
                    Query::select()
                        .from(KeyDid::Table)
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

    manager
        .drop_table(Table::drop().table(KeyDid::Table).to_owned())
        .await?;

    manager
        .rename_table(
            Table::rename()
                .table(KeyDidNew::Table, KeyDid::Table)
                .to_owned(),
        )
        .await?;

    // Enable foreign keys for SQLite
    manager
        .get_connection()
        .execute_unprepared("PRAGMA defer_foreign_keys = OFF;")
        .await?;

    Ok(())
}

#[derive(DeriveIden, Clone, Copy)]
pub enum KeyDidNew {
    Table,
    DidId,
    KeyId,
    Role,
    Reference,
}
