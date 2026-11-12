use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;
use sea_orm_migration_sqlite::{ForeignKeyRef, SchemaManagerExt, TableExt};

use crate::datatype::uuid_char;

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
    manager
        .recreate_table(
            Table::recreate()
                .table(Claim::Table)
                .drop_foreign_key(ForeignKeyRef::new(["credential_id"], "credential", ["id"]))
                .drop_column(Claim::CredentialId)
                .discard_indexes()
                .to_owned(),
        )
        .await
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
}
