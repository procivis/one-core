use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;

use crate::m20240726_084216_rename_jsonldcontextprovider_to_cacheprovider::RemoteEntityCache;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == DbBackend::MySql {
            manager
                .alter_table(
                    Table::alter()
                        .table(RemoteEntityCache::Table)
                        .modify_column(
                            ColumnDef::new(RemoteEntityCache::Key)
                                .string_len(4096)
                                .not_null(),
                        )
                        .to_owned(),
                )
                .await?;
        }

        Ok(())
    }
}
