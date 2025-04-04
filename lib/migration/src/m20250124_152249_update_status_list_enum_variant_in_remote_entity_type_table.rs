use extension::postgres::TypeAlterStatement;
use sea_orm::{DatabaseBackend, EnumIter, Iterable};
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DatabaseBackend::MySql => {
                manager
                    .truncate_table(
                        TableTruncateStatement::new()
                            .table(RemoteEntityCache::Table)
                            .take(),
                    )
                    .await?;
                manager
                    .alter_table(
                        Table::alter()
                            .table(RemoteEntityCache::Table)
                            .modify_column(
                                ColumnDef::new(RemoteEntityCache::Type)
                                    .enumeration(
                                        RemoteEntityTypeEnum::Table,
                                        RemoteEntityType::iter(),
                                    )
                                    .not_null(),
                            )
                            .take(),
                    )
                    .await?;
            }
            DatabaseBackend::Sqlite => {
                manager
                    .exec_stmt(
                        Query::update()
                            .table(RemoteEntityCache::Table)
                            .value(
                                RemoteEntityCache::Type,
                                RemoteEntityType::StatusListCredential.to_string(),
                            )
                            .and_where(
                                Expr::col(RemoteEntityCache::Type)
                                    .eq(Expr::val("STATUSLIST_CREDENTIAL")),
                            )
                            .to_owned(),
                    )
                    .await?;
            }
            // Postgres not supported at the moment, adding this as a reference.
            DatabaseBackend::Postgres => {
                manager
                    .alter_type(
                        TypeAlterStatement::new()
                            .name(RemoteEntityTypeEnum::Table)
                            .rename_value(
                                Alias::new("STATUSLIST_CREDENTIAL"),
                                Alias::new("STATUS_LIST_CREDENTIAL"),
                            ),
                    )
                    .await?;
            }
        }

        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum RemoteEntityCache {
    Table,
    Type,
}

#[derive(DeriveIden)]
pub enum RemoteEntityTypeEnum {
    Table,
}

#[derive(DeriveIden, EnumIter)]
pub enum RemoteEntityType {
    #[sea_orm(iden = "DID_DOCUMENT")]
    DidDocument,

    #[sea_orm(iden = "JSON_LD_CONTEXT")]
    JsonLdContext,

    #[sea_orm(iden = "STATUS_LIST_CREDENTIAL")]
    StatusListCredential,

    #[sea_orm(iden = "VCT_METADATA")]
    VctMetadata,

    #[sea_orm(iden = "JSON_SCHEMA")]
    JsonSchema,
}
