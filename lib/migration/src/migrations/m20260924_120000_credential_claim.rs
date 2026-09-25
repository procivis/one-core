use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{boolean, string};

use crate::datatype::{large_blob_null, timestamp, uuid_char};

#[derive(DeriveMigrationName)]
pub struct Migration;

const OWNER_INDEX: &str = "index-Claim-Path-CredentialId-Unique";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .if_not_exists()
                    .table(CredentialClaim::Table)
                    .col(uuid_char(CredentialClaim::CredentialId))
                    .col(uuid_char(CredentialClaim::ClaimId))
                    .primary_key(
                        Index::create()
                            .col(CredentialClaim::CredentialId)
                            .col(CredentialClaim::ClaimId),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-CredentialClaim-CredentialId")
                            .from(CredentialClaim::Table, CredentialClaim::CredentialId)
                            .to(Alias::new("credential"), Alias::new("id")),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-CredentialClaim-ClaimId")
                            .from(CredentialClaim::Table, CredentialClaim::ClaimId)
                            .to(Claim::Table, Claim::Id),
                    )
                    .to_owned(),
            )
            .await?;
        if !manager
            .has_index("credential_claim", "index-CredentialClaim-ClaimId")
            .await?
        {
            manager
                .create_index(
                    Index::create()
                        .name("index-CredentialClaim-ClaimId")
                        .table(CredentialClaim::Table)
                        .col(CredentialClaim::ClaimId)
                        .to_owned(),
                )
                .await?;
        }

        if manager.has_column("claim", "credential_id").await? {
            let existing_association = Query::select()
                .expr(Expr::value(1))
                .from(CredentialClaim::Table)
                .and_where(
                    Expr::col((CredentialClaim::Table, CredentialClaim::CredentialId))
                        .equals((Claim::Table, Claim::CredentialId)),
                )
                .and_where(
                    Expr::col((CredentialClaim::Table, CredentialClaim::ClaimId))
                        .equals((Claim::Table, Claim::Id)),
                )
                .to_owned();
            manager
                .exec_stmt(
                    Query::insert()
                        .into_table(CredentialClaim::Table)
                        .columns([CredentialClaim::CredentialId, CredentialClaim::ClaimId])
                        .select_from(
                            Query::select()
                                .columns([
                                    (Claim::Table, Claim::CredentialId),
                                    (Claim::Table, Claim::Id),
                                ])
                                .from(Claim::Table)
                                .and_where(Expr::exists(existing_association).not())
                                .to_owned(),
                        )
                        .map_err(|error| DbErr::Migration(error.to_string()))?
                        .to_owned(),
                )
                .await?;

            if manager.get_database_backend() == DbBackend::Sqlite {
                rebuild_sqlite_claims(manager).await?;
            } else {
                if manager.has_index("claim", OWNER_INDEX).await? {
                    manager
                        .drop_index(
                            Index::drop()
                                .name(OWNER_INDEX)
                                .table(Claim::Table)
                                .to_owned(),
                        )
                        .await?;
                }
                manager
                    .alter_table(
                        Table::alter()
                            .table(Claim::Table)
                            .drop_foreign_key(Alias::new("fk-Claim-CredentialId"))
                            .drop_column(Claim::CredentialId)
                            .to_owned(),
                    )
                    .await?;
            }
        }
        if !manager
            .has_index("claim", "index-Claim-ClaimSchemaId")
            .await?
        {
            manager
                .create_index(
                    Index::create()
                        .name("index-Claim-ClaimSchemaId")
                        .table(Claim::Table)
                        .col(Claim::ClaimSchemaId)
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}

async fn rebuild_sqlite_claims(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let connection = manager.get_connection();
    connection
        .execute_unprepared("PRAGMA defer_foreign_keys = ON")
        .await?;
    let replacement = Alias::new("claim_without_credential");
    manager
        .create_table(
            Table::create()
                .table(replacement.clone())
                .col(uuid_char(Claim::Id).primary_key())
                .col(timestamp(Claim::CreatedDate, manager))
                .col(timestamp(Claim::LastModified, manager))
                .col(large_blob_null(Claim::Value, manager))
                .col(string(Claim::Path))
                .col(boolean(Claim::SelectivelyDisclosable))
                .col(uuid_char(Claim::ClaimSchemaId))
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-Claim-ClaimSchemaId")
                        .from(replacement.clone(), Claim::ClaimSchemaId)
                        .to(Alias::new("claim_schema"), Alias::new("id")),
                )
                .to_owned(),
        )
        .await?;
    let columns = [
        Claim::Id,
        Claim::CreatedDate,
        Claim::LastModified,
        Claim::Value,
        Claim::Path,
        Claim::SelectivelyDisclosable,
        Claim::ClaimSchemaId,
    ];
    manager
        .exec_stmt(
            Query::insert()
                .into_table(replacement.clone())
                .columns(columns.clone())
                .select_from(
                    Query::select()
                        .columns(columns)
                        .from(Claim::Table)
                        .to_owned(),
                )
                .map_err(|error| DbErr::Migration(error.to_string()))?
                .to_owned(),
        )
        .await?;
    manager
        .drop_table(Table::drop().table(Claim::Table).to_owned())
        .await?;
    manager
        .rename_table(Table::rename().table(replacement, Claim::Table).to_owned())
        .await?;
    connection
        .execute_unprepared("PRAGMA defer_foreign_keys = OFF")
        .await?;
    Ok(())
}

#[derive(DeriveIden)]
enum CredentialClaim {
    Table,
    CredentialId,
    ClaimId,
}

#[derive(Clone, DeriveIden)]
#[expect(clippy::enum_variant_names)]
enum Claim {
    Table,
    Id,
    CredentialId,
    ClaimSchemaId,
    CreatedDate,
    LastModified,
    Value,
    Path,
    SelectivelyDisclosable,
}
