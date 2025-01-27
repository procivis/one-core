use extension::postgres::TypeAlterStatement;
use sea_orm::{DatabaseBackend, EnumIter, Iterable};
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Query to update old status list name to new
        let update_status_list_variant_name = Query::update()
            .table(RemoteEntityCache::Table)
            .value(
                RemoteEntityCache::Type,
                RemoteEntityType::StatusListCredentialNew.to_string(),
            )
            .and_where(Expr::col(RemoteEntityCache::Type).eq(Expr::val(
                RemoteEntityType::StatusListCredentialOld.to_string(),
            )))
            .to_owned();

        match manager.get_database_backend() {
            DatabaseBackend::MySql => {
                // Add new enum variant
                mysql_update_enum_variants(manager, RemoteEntityType::iter()).await?;
                manager.exec_stmt(update_status_list_variant_name).await?;
                // Remove old variant
                mysql_update_enum_variants(manager, RemoteEntityTypeUpdated::iter()).await?;
            }
            DatabaseBackend::Sqlite => {
                manager.exec_stmt(update_status_list_variant_name).await?;
            }
            // Postgres not supported, adding this as a reference.
            DatabaseBackend::Postgres => {
                manager
                    .alter_type(
                        TypeAlterStatement::new()
                            .name(RemoteEntityTypeEnum::Table)
                            .rename_value(
                                RemoteEntityType::StatusListCredentialOld,
                                RemoteEntityType::StatusListCredentialNew,
                            ),
                    )
                    .await?;
            }
        }

        Ok(())
    }
}

async fn mysql_update_enum_variants<T: IntoIden>(
    manager: &SchemaManager<'_>,
    enums: impl IntoIterator<Item = T>,
) -> Result<(), DbErr> {
    manager
        .alter_table(
            Table::alter()
                .table(RemoteEntityCache::Table)
                .modify_column(
                    ColumnDef::new(RemoteEntityCache::Type)
                        .enumeration(RemoteEntityTypeEnum::Table, enums)
                        .not_null(),
                )
                .to_owned(),
        )
        .await
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

    #[sea_orm(iden = "STATUSLIST_CREDENTIAL")]
    StatusListCredentialOld,

    #[sea_orm(iden = "STATUS_LIST_CREDENTIAL")]
    StatusListCredentialNew,

    #[sea_orm(iden = "VCT_METADATA")]
    VctMetadata,

    #[sea_orm(iden = "JSON_SCHEMA")]
    JsonSchema,
}

#[derive(DeriveIden, EnumIter)]
pub enum RemoteEntityTypeUpdated {
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
