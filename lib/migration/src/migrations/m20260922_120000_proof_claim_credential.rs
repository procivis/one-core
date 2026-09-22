use sea_orm_migration::prelude::*;

use crate::datatype::uuid_char;

#[derive(DeriveMigrationName)]
pub struct Migration;

const STAGING: &str = "proof_claim_with_credential";
const LEGACY: &str = "proof_claim_without_credential";
const CREDENTIAL_INDEX: &str = "index-ProofClaim-CredentialId";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.has_table("proof_claim").await?
            && !manager.has_column("proof_claim", "credential_id").await?
        {
            copy_proof_claims(manager).await?;
            manager
                .rename_table(
                    Table::rename()
                        .table(ProofClaim::Table, Alias::new(LEGACY))
                        .to_owned(),
                )
                .await?;
        }

        if !manager.has_table("proof_claim").await? {
            manager
                .rename_table(
                    Table::rename()
                        .table(Alias::new(STAGING), ProofClaim::Table)
                        .to_owned(),
                )
                .await?;
        }

        if !manager.has_index("proof_claim", CREDENTIAL_INDEX).await? {
            manager
                .create_index(
                    Index::create()
                        .name(CREDENTIAL_INDEX)
                        .table(ProofClaim::Table)
                        .col(ProofClaim::CredentialId)
                        .to_owned(),
                )
                .await?;
        }
        manager
            .drop_table(
                Table::drop()
                    .if_exists()
                    .table(Alias::new(LEGACY))
                    .to_owned(),
            )
            .await
    }
}

async fn copy_proof_claims(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let connection = manager.get_connection();

    manager
        .create_table(
            Table::create()
                .if_not_exists()
                .table(Alias::new(STAGING))
                .col(uuid_char(ProofClaim::ProofId))
                .col(uuid_char(ProofClaim::CredentialId))
                .col(uuid_char(ProofClaim::ClaimId))
                .primary_key(
                    Index::create()
                        .name("pk-ProofClaim-Credential")
                        .col(ProofClaim::ProofId)
                        .col(ProofClaim::CredentialId)
                        .col(ProofClaim::ClaimId),
                )
                // New names allow both tables to coexist on MySQL during the copy.
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-ProofClaim-Proof")
                        .from(Alias::new(STAGING), ProofClaim::ProofId)
                        .to(Proof::Table, Proof::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-ProofClaim-Credential")
                        .from(Alias::new(STAGING), ProofClaim::CredentialId)
                        .to(Credential::Table, Credential::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-ProofClaim-Claim")
                        .from(Alias::new(STAGING), ProofClaim::ClaimId)
                        .to(Claim::Table, Claim::Id),
                )
                .to_owned(),
        )
        .await?;

    // A failed previous copy may have left rows in the staging table.
    manager
        .exec_stmt(Query::delete().from_table(Alias::new(STAGING)).to_owned())
        .await?;
    manager
        .exec_stmt(
            Query::insert()
                .into_table(Alias::new(STAGING))
                .columns([
                    ProofClaim::ProofId,
                    ProofClaim::CredentialId,
                    ProofClaim::ClaimId,
                ])
                .select_from(
                    // Preserve the recorded claim owner, including holder batch
                    // parents: legacy rows do not identify the presented item.
                    // Mapping those historical references to concrete items is
                    // deferred to a separate holder claim migration.
                    Query::select()
                        .column((ProofClaim::Table, ProofClaim::ProofId))
                        .column((Claim::Table, Claim::CredentialId))
                        .column((ProofClaim::Table, ProofClaim::ClaimId))
                        .from(ProofClaim::Table)
                        .inner_join(
                            Claim::Table,
                            Expr::col((Claim::Table, Claim::Id))
                                .equals((ProofClaim::Table, ProofClaim::ClaimId)),
                        )
                        .to_owned(),
                )
                .map_err(|err| DbErr::Migration(err.to_string()))?
                .to_owned(),
        )
        .await?;

    let mut counts = Vec::new();
    for table in ["proof_claim", STAGING] {
        let row = connection
            .query_one(
                manager.get_database_backend().build(
                    Query::select()
                        .expr(Expr::col(ProofClaim::ClaimId).count())
                        .from(Alias::new(table)),
                ),
            )
            .await?
            .ok_or_else(|| DbErr::Migration("Missing proof claim copy count".into()))?;
        counts.push(row.try_get_by_index::<i64>(0)?);
    }
    if counts.first() != counts.last() {
        return Err(DbErr::Migration(
            "Proof claim backfill changed the row count".into(),
        ));
    }
    Ok(())
}

#[derive(DeriveIden)]
enum ProofClaim {
    Table,
    ProofId,
    CredentialId,
    ClaimId,
}
#[derive(DeriveIden)]
enum Claim {
    Table,
    Id,
    CredentialId,
}
#[derive(DeriveIden)]
enum Credential {
    Table,
    Id,
}
#[derive(DeriveIden)]
enum Proof {
    Table,
    Id,
}
