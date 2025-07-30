use m20240110_000001_initial::ProofSchema as OldProofSchema;
use m20240223_094129_validity_constraint_in_proof_schema::ProofSchema as NewProofSchema;
use sea_orm::{DbBackend, Statement};
use sea_orm_migration::prelude::*;

use crate::m20240110_000001_initial::{
    self, ClaimSchema, CredentialSchemaClaimSchema, ProofSchemaClaimSchema,
};
use crate::m20240223_094129_validity_constraint_in_proof_schema;
use crate::m20240314_101347_recreate_proof_input_schema_and_proof_input_claim_schema_tables::{
    ProofInputClaimSchema, ProofInputSchema,
};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == sea_orm::DatabaseBackend::Postgres {
            // Skip because it is not supported. If support for Postgres is added in the future
            // the schema can be setup in its entirety in a new, later migration.
            return Ok(());
        }
        let db = manager.get_connection();
        let backend = db.get_database_backend();

        db.execute(migrate_proof_input_schema_data(&backend).await?)
            .await?;

        db.execute(migrate_proof_input_claim_schema(&backend).await?)
            .await?;

        manager
            .drop_table(
                Table::drop()
                    .table(ProofSchemaClaimSchema::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(NewProofSchema::Table)
                    .drop_column(NewProofSchema::ValidityConstraint)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

async fn migrate_proof_input_claim_schema(backend: &DbBackend) -> Result<Statement, DbErr> {
    let temp_sub_query_input = Query::select()
        .distinct()
        .expr_as(
            Expr::col((ClaimSchema::Table, ClaimSchema::Id)),
            Alias::new("claim_schema_id"),
        )
        .expr_as(
            Expr::col((ProofInputSchema::Table, ProofInputSchema::Id)),
            Alias::new("proof_input_schema_id"),
        )
        .expr_as(
            Expr::col((
                CredentialSchemaClaimSchema::Table,
                CredentialSchemaClaimSchema::Order,
            )),
            Alias::new("order"),
        )
        .expr_as(
            Expr::col((
                CredentialSchemaClaimSchema::Table,
                CredentialSchemaClaimSchema::Required,
            )),
            Alias::new("required"),
        )
        .from(CredentialSchemaClaimSchema::Table)
        .inner_join(
            ClaimSchema::Table,
            Expr::col((
                CredentialSchemaClaimSchema::Table,
                CredentialSchemaClaimSchema::ClaimSchemaId,
            ))
            .equals((ClaimSchema::Table, ClaimSchema::Id)),
        )
        .inner_join(
            ProofSchemaClaimSchema::Table,
            Expr::col((ClaimSchema::Table, ClaimSchema::Id)).equals((
                ProofSchemaClaimSchema::Table,
                ProofSchemaClaimSchema::ClaimSchemaId,
            )),
        )
        .inner_join(
            OldProofSchema::Table,
            Expr::col((OldProofSchema::Table, OldProofSchema::Id)).equals((
                ProofSchemaClaimSchema::Table,
                ProofSchemaClaimSchema::ProofSchemaId,
            )),
        )
        .inner_join(
            ProofInputSchema::Table,
            Expr::col((ProofInputSchema::Table, ProofInputSchema::CredentialSchema)).equals((
                CredentialSchemaClaimSchema::Table,
                CredentialSchemaClaimSchema::CredentialSchemaId,
            )),
        )
        .to_owned();

    let insert_statement = Query::insert()
        .into_table(ProofInputClaimSchema::Table)
        .columns([
            ProofInputClaimSchema::ClaimSchemaId,
            ProofInputClaimSchema::ProofInputSchemaId,
            ProofInputClaimSchema::Order,
            ProofInputClaimSchema::Required,
        ])
        .select_from(temp_sub_query_input)
        .map_err(|e| DbErr::Migration(e.to_string()))?
        .to_owned();

    let stm = backend.build(&insert_statement);

    Ok(stm)
}

async fn migrate_proof_input_schema_data(backend: &DbBackend) -> Result<Statement, DbErr> {
    let temp_sub_query_input = Query::select()
        .distinct()
        .column((OldProofSchema::Table, OldProofSchema::CreatedDate))
        .column((OldProofSchema::Table, OldProofSchema::LastModified))
        .expr(Expr::val(0))
        .column((NewProofSchema::Table, NewProofSchema::ValidityConstraint))
        .expr_as(
            Expr::col((
                CredentialSchemaClaimSchema::Table,
                CredentialSchemaClaimSchema::CredentialSchemaId,
            )),
            Alias::new("credential_schema"),
        )
        .expr_as(
            Expr::col((
                ProofSchemaClaimSchema::Table,
                ProofSchemaClaimSchema::ProofSchemaId,
            )),
            Alias::new("proof_schema"),
        )
        .from(CredentialSchemaClaimSchema::Table)
        .inner_join(
            ClaimSchema::Table,
            Expr::col((
                CredentialSchemaClaimSchema::Table,
                CredentialSchemaClaimSchema::ClaimSchemaId,
            ))
            .equals((ClaimSchema::Table, ClaimSchema::Id)),
        )
        .inner_join(
            ProofSchemaClaimSchema::Table,
            Expr::col((ClaimSchema::Table, ClaimSchema::Id)).equals((
                ProofSchemaClaimSchema::Table,
                ProofSchemaClaimSchema::ClaimSchemaId,
            )),
        )
        .inner_join(
            OldProofSchema::Table,
            Expr::col((OldProofSchema::Table, OldProofSchema::Id)).equals((
                ProofSchemaClaimSchema::Table,
                ProofSchemaClaimSchema::ProofSchemaId,
            )),
        )
        .to_owned();

    let insert_statement = Query::insert()
        .into_table(ProofInputSchema::Table)
        .columns([
            ProofInputSchema::CreatedDate,
            ProofInputSchema::LastModified,
            ProofInputSchema::Order,
            ProofInputSchema::ValidityConstraint,
            ProofInputSchema::CredentialSchema,
            ProofInputSchema::ProofSchema,
        ])
        .select_from(temp_sub_query_input)
        .map_err(|e| DbErr::Migration(e.to_string()))?
        .to_owned();

    let stm = backend.build(&insert_statement);

    Ok(stm)
}
