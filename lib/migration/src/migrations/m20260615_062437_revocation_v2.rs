use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{
    boolean, integer_null, json_binary_null, string, string_len_null, string_null, text_null,
};

use crate::datatype::{timestamp, timestamp_null, uuid_char};
use crate::migrations::m20260417_150300_initial::Organisation;
use crate::nullable_unique_idx::{NullableIdxOpts, add_nullable_unique_idx};
use crate::supported_db_type::{SupportedDbType, WithSupportedDbType};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();

        db.execute(
            Query::update()
                .table(CredentialSchema::Table)
                .value(CredentialSchema::AllowRevocation, false)
                .and_where(Expr::col(CredentialSchema::AllowRevocation).is_null())
                .and_where(Expr::col(CredentialSchema::RevocationMethod).is_null()),
        )
        .await?;

        db.execute(
            Query::update()
                .table(CredentialSchema::Table)
                .value(CredentialSchema::AllowRevocation, false)
                .and_where(Expr::col(CredentialSchema::AllowRevocation).is_null())
                .and_where(
                    Expr::col(CredentialSchema::RevocationMethod).eq("MDOC_MSO_UPDATE_SUSPENSION"),
                ),
        )
        .await?;

        db.execute(
            Query::update()
                .table(CredentialSchema::Table)
                .value(CredentialSchema::AllowRevocation, true)
                .and_where(Expr::col(CredentialSchema::AllowRevocation).is_null())
                .and_where(Expr::col(CredentialSchema::RevocationMethod).is_not_null()),
        )
        .await?;

        if manager.supported_db_type() == SupportedDbType::Sqlite {
            sqlite_migration(manager).await?;
        } else {
            manager
                .alter_table(
                    Table::alter()
                        .table(CredentialSchema::Table)
                        .modify_column(
                            ColumnDef::new(CredentialSchema::AllowRevocation)
                                .boolean()
                                .not_null(),
                        )
                        .to_owned(),
                )
                .await?;

            manager
                .alter_table(
                    Table::alter()
                        .table(CredentialSchema::Table)
                        .drop_column(CredentialSchema::RevocationMethod)
                        .to_owned(),
                )
                .await?;
        }

        Ok(())
    }
}

async fn sqlite_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let db = manager.get_connection();
    db.execute_unprepared("PRAGMA defer_foreign_keys = ON;")
        .await?;

    manager
        .create_table(
            Table::create()
                .table(CredentialSchemaNew::Table)
                .col(uuid_char(CredentialSchema::Id).primary_key())
                .col(timestamp(CredentialSchema::CreatedDate, manager))
                .col(timestamp(CredentialSchema::LastModified, manager))
                .col(timestamp_null(CredentialSchema::DeletedAt, manager))
                .col(string(CredentialSchema::Name))
                .col(string(CredentialSchema::LayoutType))
                .col(json_binary_null(CredentialSchema::LayoutProperties))
                .col(string(CredentialSchema::ImportedSourceUrl))
                .col(boolean(CredentialSchema::AllowSuspension))
                .col(boolean(CredentialSchema::AllowRevocation))
                .col(boolean(CredentialSchema::RequiresWalletInstanceAttestation))
                .col(string_null(CredentialSchema::KeyStorageSecurity))
                .col(string_null(CredentialSchema::TransactionCodeType))
                .col(integer_null(CredentialSchema::TransactionCodeLength))
                .col(string_len_null(
                    CredentialSchema::TransactionCodeDescription,
                    300,
                ))
                .col(uuid_char(CredentialSchema::OrganisationId))
                .col(integer_null(CredentialSchema::BatchSize))
                .col(text_null(CredentialSchema::EmbeddedDisclosurePolicy))
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name("fk-CredentialSchema-OrganisationId")
                        .from_tbl(CredentialSchema::Table)
                        .from_col(CredentialSchema::OrganisationId)
                        .to_tbl(Organisation::Table)
                        .to_col(Organisation::Id),
                )
                .to_owned(),
        )
        .await?;

    let copied_columns = vec![
        CredentialSchema::Id,
        CredentialSchema::CreatedDate,
        CredentialSchema::LastModified,
        CredentialSchema::DeletedAt,
        CredentialSchema::Name,
        CredentialSchema::LayoutType,
        CredentialSchema::LayoutProperties,
        CredentialSchema::ImportedSourceUrl,
        CredentialSchema::AllowSuspension,
        CredentialSchema::AllowRevocation,
        CredentialSchema::RequiresWalletInstanceAttestation,
        CredentialSchema::KeyStorageSecurity,
        CredentialSchema::TransactionCodeType,
        CredentialSchema::TransactionCodeLength,
        CredentialSchema::TransactionCodeDescription,
        CredentialSchema::BatchSize,
        CredentialSchema::EmbeddedDisclosurePolicy,
        CredentialSchema::OrganisationId,
    ];
    manager
        .exec_stmt(
            Query::insert()
                .into_table(CredentialSchemaNew::Table)
                .columns(copied_columns.to_vec())
                .select_from(
                    Query::select()
                        .from(CredentialSchema::Table)
                        .columns(copied_columns)
                        .to_owned(),
                )
                .map_err(|e| DbErr::Migration(e.to_string()))?
                .to_owned(),
        )
        .await?;

    manager
        .drop_table(Table::drop().table(CredentialSchema::Table).to_owned())
        .await?;
    manager
        .rename_table(
            Table::rename()
                .table(CredentialSchemaNew::Table, CredentialSchema::Table)
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name("index-CredentialSchema-CreatedDate")
                .table(CredentialSchema::Table)
                .col(CredentialSchema::CreatedDate)
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name("index-CredentialSchema-OrganisationId-DeletedAt-CreatedDate")
                .table(CredentialSchema::Table)
                .col(CredentialSchema::OrganisationId)
                .col(CredentialSchema::DeletedAt)
                .col(CredentialSchema::CreatedDate)
                .to_owned(),
        )
        .await?;

    add_nullable_unique_idx(
        CredentialSchema::Table,
        CredentialSchema::DeletedAt,
        "index_CredentialSchema_Name-OrganisationId-DeletedAt_Unique",
        NullableIdxOpts {
            non_nullable_columns: vec![CredentialSchema::Name, CredentialSchema::OrganisationId],
            ..Default::default()
        },
        manager,
    )
    .await?;

    db.execute_unprepared("PRAGMA defer_foreign_keys = OFF;")
        .await?;

    Ok(())
}

#[derive(Clone, DeriveIden)]
enum CredentialSchema {
    Table,
    Id,
    CreatedDate,
    LastModified,
    DeletedAt,
    Name,
    LayoutType,
    LayoutProperties,
    ImportedSourceUrl,
    AllowSuspension,
    RequiresWalletInstanceAttestation,
    KeyStorageSecurity,
    TransactionCodeType,
    TransactionCodeLength,
    TransactionCodeDescription,
    OrganisationId,
    BatchSize,
    AllowRevocation,
    EmbeddedDisclosurePolicy,

    RevocationMethod,
}

#[derive(Clone, DeriveIden)]
enum CredentialSchemaNew {
    Table,
}
