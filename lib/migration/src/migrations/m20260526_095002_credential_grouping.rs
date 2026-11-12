use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{string, string_null};
use sea_orm_migration_sqlite::{SchemaManagerExt, TableExt};

use crate::datatype::{timestamp_null, uuid_char_null};
use crate::migrations::m20260417_150300_initial::Credential;
use crate::supported_db_type::{SupportedDbType, WithSupportedDbType};

#[derive(DeriveMigrationName)]
pub struct Migration;

const FK_CREDENTIAL_CREDENTIAL: &str = "fk-Credential-Credential";
const INDEX_CREDENTIAL_TYPE: &str = "index-Credential-Type";
const INDEX_CREDENTIAL_CONSUMED_AT: &str = "index-Credential-ConsumedAt";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // SQLite can only do one alter operation at a time
        manager
            .alter_table(
                Table::alter()
                    .table(Credential::Table)
                    .add_column(string_null(CredentialNew::Type))
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Credential::Table)
                    .add_column(timestamp_null(CredentialNew::ConsumedAt, manager))
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Credential::Table)
                    .add_column(uuid_char_null(CredentialNew::ParentId))
                    .to_owned(),
            )
            .await?;
        manager
            .exec_stmt(
                Query::update()
                    .table(Credential::Table)
                    .value(CredentialNew::Type, "SINGLE")
                    .to_owned(),
            )
            .await?;

        if manager.supported_db_type() == SupportedDbType::Sqlite {
            sqlite_type_not_null(manager).await?;
        } else {
            manager
                .alter_table(
                    Table::alter()
                        .table(Credential::Table)
                        .modify_column(string(CredentialNew::Type))
                        .add_foreign_key(
                            TableForeignKey::new()
                                .name(FK_CREDENTIAL_CREDENTIAL)
                                .from_tbl(Credential::Table)
                                .from_col(CredentialNew::ParentId)
                                .to_tbl(Credential::Table)
                                .to_col(Credential::Id),
                        )
                        .to_owned(),
                )
                .await?;
        }

        // Add indices for new columns
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name(INDEX_CREDENTIAL_TYPE)
                    .table(Credential::Table)
                    .col(CredentialNew::Type)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name(INDEX_CREDENTIAL_CONSUMED_AT)
                    .table(Credential::Table)
                    .col(CredentialNew::ConsumedAt)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}

async fn sqlite_type_not_null(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .recreate_table(
            Table::recreate()
                .table(Credential::Table)
                .modify_column(string(CredentialNew::Type))
                .add_foreign_key(
                    ForeignKey::create()
                        .name(FK_CREDENTIAL_CREDENTIAL)
                        .from_tbl(Credential::Table)
                        .from_col(CredentialNew::ParentId)
                        .to_tbl(Credential::Table)
                        .to_col(Credential::Id)
                        .to_owned(),
                )
                .to_owned(),
        )
        .await?;

    Ok(())
}

#[derive(DeriveIden)]
pub enum CredentialNew {
    Type,
    ConsumedAt,
    ParentId,
}
