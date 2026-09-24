use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{string, string_null, text_null};

use crate::datatype::{timestamp, timestamp_null, uuid_char};
use crate::foreign_key::{disable_foreign_key_checks, enable_foreign_key_checks};
use crate::migrations::m20260417_150300_initial::{
    Credential, CredentialSchema, Organisation, Proof, ProofSchema, TrustCollection,
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
        .create_table(
            Table::create()
                .table(TrustCollectionNew::Table)
                .col(uuid_char(TrustCollection::Id).primary_key())
                .col(timestamp(TrustCollection::CreatedDate, manager))
                .col(timestamp(TrustCollection::LastModified, manager))
                .col(timestamp_null(TrustCollection::DeactivatedAt, manager))
                .col(string(TrustCollection::Name))
                .col(text_null(TrustCollection::RemoteTrustCollectionUrl))
                .col(uuid_char(TrustCollection::OrganisationId))
                .col(string(Col::Ecosystem))
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name("fk-TrustCollection-OrganisationId")
                        .from_tbl(TrustCollectionNew::Table)
                        .from_col(TrustCollection::OrganisationId)
                        .to_tbl(Organisation::Table)
                        .to_col(Organisation::Id),
                )
                .to_owned(),
        )
        .await?;

    let copied_columns = [
        TrustCollection::Id.into_iden(),
        TrustCollection::CreatedDate.into_iden(),
        TrustCollection::LastModified.into_iden(),
        TrustCollection::DeactivatedAt.into_iden(),
        TrustCollection::Name.into_iden(),
        TrustCollection::RemoteTrustCollectionUrl.into_iden(),
        TrustCollection::OrganisationId.into_iden(),
    ];
    manager
        .exec_stmt(
            Query::insert()
                .into_table(TrustCollectionNew::Table)
                .columns(
                    copied_columns
                        .iter()
                        .cloned()
                        .chain([Col::Ecosystem.into_iden()]),
                )
                .select_from(
                    Query::select()
                        .columns(copied_columns)
                        .expr_as(Expr::value(EUDI_ECOSYSTEM), Col::Ecosystem.into_iden())
                        .from(TrustCollection::Table)
                        .to_owned(),
                )
                .map_err(|e| DbErr::Migration(e.to_string()))?
                .to_owned(),
        )
        .await?;

    manager
        .drop_table(Table::drop().table(TrustCollection::Table).to_owned())
        .await?;

    manager
        .rename_table(
            Table::rename()
                .table(TrustCollectionNew::Table, TrustCollection::Table)
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
enum TrustCollectionNew {
    Table,
}

#[derive(DeriveIden)]
enum Col {
    Ecosystem,
}
