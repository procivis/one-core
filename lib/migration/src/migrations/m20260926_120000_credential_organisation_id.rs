use sea_orm::sea_query::IndexOrder;
use sea_orm_migration::prelude::*;
use sea_orm_migration_sqlite::{SchemaManagerExt, TableExt};

use crate::datatype::{uuid_char, uuid_char_null};
use crate::foreign_key::{disable_foreign_key_checks, enable_foreign_key_checks};
use crate::migrations::m20260417_150300_initial::{
    Credential, CredentialSchema, INDEX_CREDENTIAL_CREATED_DATE, INDEX_CREDENTIAL_DELETED_AT,
    INDEX_CREDENTIAL_LIST, INDEX_CREDENTIAL_ROLE, INDEX_CREDENTIAL_STATE,
    INDEX_CREDENTIAL_SUSPEND_END_DATE, Organisation,
};
use crate::migrations::m20260526_095002_credential_grouping::CredentialNew as CredentialWithType;
use crate::supported_db_type::{SupportedDbType, WithSupportedDbType};

#[derive(DeriveMigrationName)]
pub struct Migration;

const FK_CREDENTIAL_ORGANISATION: &str = "fk-Credential-OrganisationId";
const INDEX_CREDENTIAL_TYPE: &str = "index-Credential-Type";
const INDEX_CREDENTIAL_ECOSYSTEM: &str = "index-Credential-Ecosystem";
const INDEX_CREDENTIAL_EARLIEST_EXPIRING_BATCH_ITEM: &str =
    "index-Credential-EarliestExpiringBatchItem";
const INDEX_CREDENTIAL_ORGANISATION_ID_DELETED_AT_ROLE_CREATED_DATE: &str =
    "index-Credential-OrganisationId-DeletedAt-Role-CreatedDate";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Credential::Table)
                    .add_column(uuid_char_null(CredentialNew::OrganisationId))
                    .to_owned(),
            )
            .await?;

        fill_organisation_id(manager).await?;

        disable_foreign_key_checks(manager).await?;
        if manager.supported_db_type() == SupportedDbType::Sqlite {
            organisation_id_not_null_sqlite(manager).await?;
        } else {
            organisation_id_not_null(manager).await?;
        }
        enable_foreign_key_checks(manager).await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum CredentialNew {
    OrganisationId,
    Ecosystem,
    ExpiresAt,
    Format,
}

// one statement for all rows: dev has tens of thousands of organisations and schemas
async fn fill_organisation_id(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let organisation_of_schema = Query::select()
        .column((CredentialSchema::Table, CredentialSchema::OrganisationId))
        .from(CredentialSchema::Table)
        .and_where(
            Expr::col((CredentialSchema::Table, CredentialSchema::Id))
                .equals((Credential::Table, Credential::CredentialSchemaId)),
        )
        .to_owned();

    manager
        .exec_stmt(
            Query::update()
                .table(Credential::Table)
                .value(
                    CredentialNew::OrganisationId,
                    SimpleExpr::SubQuery(
                        None,
                        Box::new(organisation_of_schema.into_sub_query_statement()),
                    ),
                )
                .to_owned(),
        )
        .await?;

    Ok(())
}

/// Desk filters by organisation, deleted_at and role and sorts by creation date. `type` is in the
/// index only so its filter is checked in the index instead of in the row
fn organisation_index() -> IndexCreateStatement {
    Index::create()
        .name(INDEX_CREDENTIAL_ORGANISATION_ID_DELETED_AT_ROLE_CREATED_DATE)
        .table(Credential::Table)
        .col(CredentialNew::OrganisationId)
        .col(Credential::DeletedAt)
        .col(Credential::Role)
        .col(Credential::CreatedDate)
        .col(Credential::Id)
        .col(CredentialWithType::Type)
        .to_owned()
}

async fn organisation_id_not_null(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .alter_table(
            Table::alter()
                .table(Credential::Table)
                .modify_column(uuid_char(CredentialNew::OrganisationId))
                .add_foreign_key(
                    TableForeignKey::new()
                        .name(FK_CREDENTIAL_ORGANISATION)
                        .from_tbl(Credential::Table)
                        .from_col(CredentialNew::OrganisationId)
                        .to_tbl(Organisation::Table)
                        .to_col(Organisation::Id),
                )
                .to_owned(),
        )
        .await?;

    manager.create_index(organisation_index()).await?;

    // MariaDB merged these two single column indexes for the list query instead of using the one
    // above
    for index in [INDEX_CREDENTIAL_ROLE, INDEX_CREDENTIAL_DELETED_AT] {
        manager
            .drop_index(
                Index::drop()
                    .name(index)
                    .table(Credential::Table)
                    .to_owned(),
            )
            .await?;
    }

    Ok(())
}

// SQLite cannot make a column NOT NULL: rebuild the table, without the two single column indexes
async fn organisation_id_not_null_sqlite(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .recreate_table(
            Table::recreate()
                .table(Credential::Table)
                .modify_column(uuid_char(CredentialNew::OrganisationId))
                .add_foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_CREDENTIAL_ORGANISATION)
                        .from_tbl(Credential::Table)
                        .from_col(CredentialNew::OrganisationId)
                        .to_tbl(Organisation::Table)
                        .to_col(Organisation::Id)
                        .to_owned(),
                )
                .discard_indexes()
                .to_owned(),
        )
        .await?;

    let indexes = vec![
        Index::create()
            .name(INDEX_CREDENTIAL_LIST)
            .table(Credential::Table)
            .col(Credential::DeletedAt)
            .col(Credential::Role)
            .col(Credential::CreatedDate)
            .col(Credential::Id)
            .to_owned(),
        Index::create()
            .name(INDEX_CREDENTIAL_CREATED_DATE)
            .table(Credential::Table)
            .col(Credential::CreatedDate)
            .to_owned(),
        Index::create()
            .name(INDEX_CREDENTIAL_STATE)
            .table(Credential::Table)
            .col(Credential::State)
            .to_owned(),
        Index::create()
            .name(INDEX_CREDENTIAL_SUSPEND_END_DATE)
            .table(Credential::Table)
            .col(Credential::SuspendEndDate)
            .to_owned(),
        Index::create()
            .name(INDEX_CREDENTIAL_TYPE)
            .table(Credential::Table)
            .col(CredentialWithType::Type)
            .to_owned(),
        Index::create()
            .name(INDEX_CREDENTIAL_ECOSYSTEM)
            .table(Credential::Table)
            .col(CredentialNew::Ecosystem)
            .to_owned(),
        Index::create()
            .name(INDEX_CREDENTIAL_EARLIEST_EXPIRING_BATCH_ITEM)
            .table(Credential::Table)
            .col(CredentialWithType::ConsumedAt)
            .col(Credential::State)
            .col(CredentialWithType::ParentId)
            .col(CredentialNew::Format)
            .col(CredentialWithType::Type)
            .col(Credential::DeletedAt)
            .col((CredentialNew::ExpiresAt, IndexOrder::Asc))
            .col((Credential::Id, IndexOrder::Desc))
            .to_owned(),
        organisation_index(),
    ];
    for index in indexes {
        manager.create_index(index).await?;
    }

    Ok(())
}
