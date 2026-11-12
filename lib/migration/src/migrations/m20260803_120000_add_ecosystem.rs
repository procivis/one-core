use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{string, string_null};
use sea_orm_migration_sqlite::{SchemaManagerExt, TableExt};

use crate::foreign_key::{disable_foreign_key_checks, enable_foreign_key_checks};
use crate::migrations::m20260417_150300_initial::{
    Credential, CredentialSchema, Proof, ProofSchema, TrustCollection,
};
use crate::nullable_unique_idx::{NullableIdxOpts, add_nullable_unique_idx};
use crate::supported_db_type::{SupportedDbType, WithSupportedDbType};

const EUDI_ECOSYSTEM: &str = "EUDI";

const INDEX_CREDENTIAL_SCHEMA_ECOSYSTEM: &str = "index-CredentialSchema-Ecosystem";
const INDEX_PROOF_SCHEMA_ECOSYSTEM: &str = "index-ProofSchema-Ecosystem";
const INDEX_CREDENTIAL_ECOSYSTEM: &str = "index-Credential-Ecosystem";
const INDEX_PROOF_ECOSYSTEM: &str = "index-Proof-Ecosystem";

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(CredentialSchema::Table)
                    .add_column(string_null(Col::Ecosystem))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(ProofSchema::Table)
                    .add_column(string_null(Col::Ecosystem))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Credential::Table)
                    .add_column(string_null(Col::Ecosystem))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Proof::Table)
                    .add_column(string_null(Col::Ecosystem))
                    .to_owned(),
            )
            .await?;

        disable_foreign_key_checks(manager).await?;
        if manager.supported_db_type() == SupportedDbType::Sqlite {
            trust_collection_sqlite(manager).await?;
        } else {
            trust_collection_sane(manager).await?;
        }
        enable_foreign_key_checks(manager).await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name(INDEX_CREDENTIAL_SCHEMA_ECOSYSTEM)
                    .table(CredentialSchema::Table)
                    .col(Col::Ecosystem)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name(INDEX_PROOF_SCHEMA_ECOSYSTEM)
                    .table(ProofSchema::Table)
                    .col(Col::Ecosystem)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name(INDEX_CREDENTIAL_ECOSYSTEM)
                    .table(Credential::Table)
                    .col(Col::Ecosystem)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name(INDEX_PROOF_ECOSYSTEM)
                    .table(Proof::Table)
                    .col(Col::Ecosystem)
                    .to_owned(),
            )
            .await
    }
}

/// All existing trust collections belong to the EUDI ecosystem.
async fn trust_collection_sane(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .alter_table(
            Table::alter()
                .table(TrustCollection::Table)
                .add_column(string_null(Col::Ecosystem))
                .to_owned(),
        )
        .await?;

    manager
        .exec_stmt(
            Query::update()
                .table(TrustCollection::Table)
                .values([(Col::Ecosystem, EUDI_ECOSYSTEM.into())])
                .to_owned(),
        )
        .await?;

    manager
        .alter_table(
            Table::alter()
                .table(TrustCollection::Table)
                .modify_column(string(Col::Ecosystem))
                .to_owned(),
        )
        .await
}

async fn trust_collection_sqlite(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .recreate_table(
            Table::recreate()
                .table(TrustCollection::Table)
                .add_column_with_value(string(Col::Ecosystem), Expr::value(EUDI_ECOSYSTEM))
                .discard_indexes()
                .to_owned(),
        )
        .await?;

    add_nullable_unique_idx(
        TrustCollection::Table,
        TrustCollection::DeactivatedAt,
        "index-TrustCol-Name-Org-DeactivatedAt-Unique",
        NullableIdxOpts {
            non_nullable_columns: vec![TrustCollection::Name, TrustCollection::OrganisationId],
            null_value: Some("not_deactivated"),
            ..Default::default()
        },
        manager,
    )
    .await
}

#[derive(DeriveIden)]
enum Col {
    Ecosystem,
}
