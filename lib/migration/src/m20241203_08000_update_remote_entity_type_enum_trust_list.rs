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
                            .to_owned(),
                    )
                    .await?;
            }
            // we don't need to change enums for sqlite since they are stored as TEXT
            DatabaseBackend::Sqlite => {}
            // Postgres not supported but adding this as a reference.
            DatabaseBackend::Postgres => {
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
                                    .extra("ADD VALUE 'VCT_METADATA'"),
                            )
                            .to_owned(),
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

    #[sea_orm(iden = "STATUSLIST_CREDENTIAL")]
    StatusListCredential,

    #[sea_orm(iden = "VCT_METADATA")]
    VctMetadata,

    #[sea_orm(iden = "JSON_SCHEMA")]
    JsonSchema,

    #[sea_orm(iden = "TRUST_LIST")]
    TrustList,
}
