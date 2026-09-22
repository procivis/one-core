use std::collections::{BTreeSet, HashMap};

use sea_orm::{DbBackend, FromQueryResult};
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{big_integer, integer, text, text_null};

use crate::batch_utils::get_ids;
use crate::datatype::{timestamp, uuid_char};
use crate::foreign_key::{disable_foreign_key_checks, enable_foreign_key_checks};
use crate::migrations::m20260417_150300_initial::{CredentialSchema, ProofSchema};
use crate::migrations::m20260429_120000_credential_schema_multiformat::CredentialSchemaFormat;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(FromQueryResult)]
struct ProofInputSchemaRow {
    id: i64,
    credential_schema: String,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Validate before DDL, since MySQL does not roll back schema changes.
        let inputs = ProofInputSchemaRow::find_by_statement(
            manager.get_database_backend().build(
                Query::select()
                    .columns([ProofInputSchema::Id, ProofInputSchema::CredentialSchema])
                    .from(ProofInputSchema::Table)
                    .order_by(ProofInputSchema::Id, Order::Asc),
            ),
        )
        .all(manager.get_connection())
        .await?;
        let schema_ids: BTreeSet<_> = inputs
            .iter()
            .map(|input| input.credential_schema.clone())
            .collect();
        let mut backfill = HashMap::with_capacity(schema_ids.len());
        let mut invalid_schemas = Vec::new();
        for schema_id in schema_ids {
            let mut formats: Vec<String> = get_ids(
                manager,
                Query::select()
                    .expr_as(Expr::col(CredentialSchemaFormat::Format), "id")
                    .from(CredentialSchemaFormat::Table)
                    .and_where(
                        Expr::col(CredentialSchemaFormat::CredentialSchemaId).eq(&schema_id),
                    ),
            )
            .await?;
            formats.sort();
            let reason = if formats.is_empty() {
                Some("referenced credential schema has no formats")
            } else if formats
                .windows(2)
                .any(|pair| matches!(pair, [first, second] if first == second))
            {
                Some("referenced credential schema has duplicate formats")
            } else {
                None
            };
            if let Some(reason) = reason {
                invalid_schemas.push(format!("{schema_id}: {reason}"));
            }
            backfill.insert(schema_id, formats.join(","));
        }
        if !invalid_schemas.is_empty() {
            let report = format!(
                "Cannot migrate proof input formats: {} invalid credential schemas:\n{}",
                invalid_schemas.len(),
                invalid_schemas.join("\n")
            );
            tracing::error!("{report}");
            return Err(DbErr::Migration(report));
        }

        manager
            .alter_table(
                Table::alter()
                    .table(ProofInputSchema::Table)
                    .add_column(text_null(ProofInputSchema::Formats))
                    .to_owned(),
            )
            .await?;
        for batch in inputs.chunks(1000) {
            let mut formats = CaseStatement::new();
            for input in batch {
                formats = formats.case(
                    Expr::col(ProofInputSchema::Id).eq(input.id),
                    backfill
                        .get(&input.credential_schema)
                        .ok_or_else(|| {
                            DbErr::Migration(format!(
                                "Missing backfill formats for credential schema {}",
                                input.credential_schema
                            ))
                        })?
                        .clone(),
                );
            }
            manager
                .exec_stmt(
                    Query::update()
                        .table(ProofInputSchema::Table)
                        .value(
                            ProofInputSchema::Formats,
                            formats.finally(Expr::col(ProofInputSchema::Formats)),
                        )
                        .and_where(
                            Expr::col(ProofInputSchema::Id)
                                .is_in(batch.iter().map(|input| input.id)),
                        )
                        .to_owned(),
                )
                .await?;
        }

        if manager.get_database_backend() == DbBackend::Sqlite {
            rebuild_sqlite_table(manager).await
        } else {
            manager
                .alter_table(
                    Table::alter()
                        .table(ProofInputSchema::Table)
                        .modify_column(text(ProofInputSchema::Formats))
                        .to_owned(),
                )
                .await
        }
    }
}

async fn rebuild_sqlite_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    disable_foreign_key_checks(manager).await?;
    manager
        .create_table(
            Table::create()
                .table(ProofInputSchemaNew::Table)
                .col(
                    big_integer(ProofInputSchema::Id)
                        .auto_increment()
                        .primary_key(),
                )
                .col(timestamp(ProofInputSchema::CreatedDate, manager))
                .col(timestamp(ProofInputSchema::LastModified, manager))
                .col(integer(ProofInputSchema::Order))
                .col(uuid_char(ProofInputSchema::CredentialSchema))
                .col(uuid_char(ProofInputSchema::ProofSchema))
                .col(text(ProofInputSchema::Formats))
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-ProofInputSchema-CredentialSchema")
                        .from(
                            ProofInputSchemaNew::Table,
                            ProofInputSchema::CredentialSchema,
                        )
                        .to(CredentialSchema::Table, CredentialSchema::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-ProofInputSchema-ProofSchema")
                        .from(ProofInputSchemaNew::Table, ProofInputSchema::ProofSchema)
                        .to(ProofSchema::Table, ProofSchema::Id),
                )
                .to_owned(),
        )
        .await?;
    let columns = [
        ProofInputSchema::Id,
        ProofInputSchema::CreatedDate,
        ProofInputSchema::LastModified,
        ProofInputSchema::Order,
        ProofInputSchema::CredentialSchema,
        ProofInputSchema::ProofSchema,
        ProofInputSchema::Formats,
    ];
    manager
        .exec_stmt(
            Query::insert()
                .into_table(ProofInputSchemaNew::Table)
                .columns(columns)
                .select_from(
                    Query::select()
                        .columns(columns)
                        .from(ProofInputSchema::Table)
                        .to_owned(),
                )
                .map_err(|error| DbErr::Migration(error.to_string()))?
                .to_owned(),
        )
        .await?;
    manager
        .drop_table(Table::drop().table(ProofInputSchema::Table).to_owned())
        .await?;
    manager
        .rename_table(
            Table::rename()
                .table(ProofInputSchemaNew::Table, ProofInputSchema::Table)
                .to_owned(),
        )
        .await?;
    enable_foreign_key_checks(manager).await
}

#[derive(Clone, Copy, DeriveIden)]
enum ProofInputSchema {
    Table,
    Id,
    CreatedDate,
    LastModified,
    Order,
    CredentialSchema,
    ProofSchema,
    Formats,
}

#[derive(DeriveIden)]
enum ProofInputSchemaNew {
    Table,
}
