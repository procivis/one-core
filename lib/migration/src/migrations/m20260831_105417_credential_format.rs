use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::*;

use crate::batch_utils::get_ids;
use crate::datatype::{timestamp, uuid_char, uuid_char_null};
use crate::foreign_key::{disable_foreign_key_checks, enable_foreign_key_checks};
use crate::migrations::m20260417_150300_initial::{Credential, CredentialSchema};
use crate::migrations::m20260429_120000_credential_schema_multiformat::CredentialSchemaFormat;
use crate::migrations::m20260526_095002_credential_grouping::CredentialNew as CredentialWithType;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();
        if backend == DbBackend::Sqlite {
            up_sqlite(manager).await?;
        } else {
            manager
                .drop_index(
                    Index::drop()
                        .name("index-CredentialSchemaFormat-CredentialSchemaId-SchemaId_Unique")
                        .table(CredentialSchemaFormat::Table)
                        .to_owned(),
                )
                .await?;
            manager
                .drop_index(
                    Index::drop()
                        .name("index-CredentialSchemaFormat-SchemaId-Format-CredentialSchemaId")
                        .table(CredentialSchemaFormat::Table)
                        .to_owned(),
                )
                .await?;

            manager
                .alter_table(
                    Table::alter()
                        .table(CredentialSchemaFormat::Table)
                        .rename_column(
                            CredentialSchemaFormat::SchemaId,
                            CredentialSchemaFormatNew::EcosystemSchemaId,
                        )
                        .to_owned(),
                )
                .await?;

            manager
                .create_index(
                    Index::create()
                        .name("index-CredentialSchemaFormat-CredentialSchemaId-ESchemaId_Unique")
                        .unique()
                        .table(CredentialSchemaFormat::Table)
                        .col(CredentialSchemaFormat::CredentialSchemaId)
                        .col(CredentialSchemaFormatNew::EcosystemSchemaId)
                        .to_owned(),
                )
                .await?;
            manager
                .create_index(
                    Index::create()
                        .name("index-CredentialSchemaFormat-ESchemaId-Format-CredentialSchemaId")
                        .table(CredentialSchemaFormat::Table)
                        .col(CredentialSchemaFormatNew::EcosystemSchemaId)
                        .col(CredentialSchemaFormat::Format)
                        .col(CredentialSchemaFormat::CredentialSchemaId)
                        .to_owned(),
                )
                .await?;

            manager
                .alter_table(
                    Table::alter()
                        .table(Credential::Table)
                        .add_column(uuid_char_null(CredentialNew::Format))
                        .to_owned(),
                )
                .await?;
            manager
                .alter_table(
                    Table::alter()
                        .table(Credential::Table)
                        .add_foreign_key(
                            ForeignKeyCreateStatement::new()
                                .name("fk-Credential-Format")
                                .from_tbl(Credential::Table)
                                .from_col(CredentialNew::Format)
                                .to_tbl(CredentialSchemaFormat::Table)
                                .to_col(CredentialSchemaFormat::Id)
                                .get_foreign_key(),
                        )
                        .to_owned(),
                )
                .await?;
        }

        fill_format(manager).await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum CredentialSchemaFormatNew {
    Table,
    EcosystemSchemaId,
}

#[derive(DeriveIden)]
enum CredentialNew {
    Format,
}

async fn up_sqlite(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    disable_foreign_key_checks(manager).await?;

    manager
        .create_table(
            Table::create()
                .table(CredentialSchemaFormatNew::Table)
                .col(uuid_char(CredentialSchemaFormat::Id).primary_key())
                .col(timestamp(CredentialSchemaFormat::CreatedDate, manager))
                .col(timestamp(CredentialSchemaFormat::LastModified, manager))
                .col(uuid_char(CredentialSchemaFormat::CredentialSchemaId))
                .col(string(CredentialSchemaFormat::Format))
                .col(string(CredentialSchemaFormatNew::EcosystemSchemaId))
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name("fk-CredentialSchemaFormat-CredentialSchemaId")
                        .from_tbl(CredentialSchemaFormat::Table)
                        .from_col(CredentialSchemaFormat::CredentialSchemaId)
                        .to_tbl(CredentialSchema::Table)
                        .to_col(CredentialSchema::Id),
                )
                .to_owned()
                .to_owned(),
        )
        .await?;

    manager
        .exec_stmt(
            Query::insert()
                .into_table(CredentialSchemaFormatNew::Table)
                .columns([
                    CredentialSchemaFormat::Id.into_iden(),
                    CredentialSchemaFormat::CreatedDate.into_iden(),
                    CredentialSchemaFormat::LastModified.into_iden(),
                    CredentialSchemaFormat::CredentialSchemaId.into_iden(),
                    CredentialSchemaFormat::Format.into_iden(),
                    CredentialSchemaFormatNew::EcosystemSchemaId.into_iden(),
                ])
                .select_from(
                    Query::select()
                        .columns([
                            CredentialSchemaFormat::Id,
                            CredentialSchemaFormat::CreatedDate,
                            CredentialSchemaFormat::LastModified,
                            CredentialSchemaFormat::CredentialSchemaId,
                            CredentialSchemaFormat::Format,
                            CredentialSchemaFormat::SchemaId,
                        ])
                        .from(CredentialSchemaFormat::Table)
                        .to_owned(),
                )
                .map_err(|e| DbErr::Migration(e.to_string()))?
                .to_owned(),
        )
        .await?;

    manager
        .drop_table(
            Table::drop()
                .table(CredentialSchemaFormat::Table)
                .to_owned(),
        )
        .await?;

    manager
        .rename_table(
            Table::rename()
                .table(
                    CredentialSchemaFormatNew::Table,
                    CredentialSchemaFormat::Table,
                )
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name("index-CredentialSchemaFormat-CredentialSchemaId-Format_Unique")
                .unique()
                .table(CredentialSchemaFormat::Table)
                .col(CredentialSchemaFormat::CredentialSchemaId)
                .col(CredentialSchemaFormat::Format)
                .to_owned(),
        )
        .await?;
    manager
        .create_index(
            Index::create()
                .name("index-CredentialSchemaFormat-CredentialSchemaId-ESchemaId_Unique")
                .unique()
                .table(CredentialSchemaFormat::Table)
                .col(CredentialSchemaFormat::CredentialSchemaId)
                .col(CredentialSchemaFormatNew::EcosystemSchemaId)
                .to_owned(),
        )
        .await?;
    manager
        .create_index(
            Index::create()
                .name("index-CredentialSchemaFormat-ESchemaId-Format-CredentialSchemaId")
                .table(CredentialSchemaFormat::Table)
                .col(CredentialSchemaFormatNew::EcosystemSchemaId)
                .col(CredentialSchemaFormat::Format)
                .col(CredentialSchemaFormat::CredentialSchemaId)
                .to_owned(),
        )
        .await?;

    enable_foreign_key_checks(manager).await?;

    manager
        .get_connection()
        .execute_unprepared(
            r#"
                ALTER TABLE credential 
                ADD COLUMN format CHAR(36) REFERENCES credential_schema_format(id) DEFAULT NULL;
                "#,
        )
        .await?;

    Ok(())
}

async fn fill_format(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let credential_schema_ids: Vec<String> = get_ids(
        manager,
        Query::select()
            .distinct()
            .expr_as(Expr::col(Credential::CredentialSchemaId), "id")
            .from(Credential::Table)
            .cond_where(Expr::col(CredentialWithType::Type).ne("BATCH_PARENT")),
    )
    .await?;

    for (index, credential_schema_id) in credential_schema_ids.iter().enumerate() {
        tracing::debug!(
            "Updating credentials for credential-schema {credential_schema_id}, {index}/{}",
            credential_schema_ids.len()
        );

        let mut formats: Vec<String> = get_ids(
            manager,
            Query::select()
                .column(CredentialSchemaFormat::Id)
                .from(CredentialSchemaFormat::Table)
                .and_where(
                    Expr::col(CredentialSchemaFormat::CredentialSchemaId).eq(credential_schema_id),
                ),
        )
        .await?;

        let Some(format_id) = formats.pop() else {
            continue;
        };
        if !formats.is_empty() {
            continue;
        }

        manager
            .exec_stmt(
                Query::update()
                    .table(Credential::Table)
                    .value(CredentialNew::Format, format_id)
                    .cond_where(Expr::col(Credential::CredentialSchemaId).eq(credential_schema_id))
                    .and_where(Expr::col(CredentialWithType::Type).ne("BATCH_PARENT"))
                    .to_owned(),
            )
            .await?;
    }

    Ok(())
}
