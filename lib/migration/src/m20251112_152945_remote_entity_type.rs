use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DbBackend::MySql => {
                manager
                    .alter_table(
                        Table::alter()
                            .table(RemoteEntityCache::Table)
                            .add_column(ColumnDef::new(RemoteEntityCache::TmpType).string().null())
                            .to_owned(),
                    )
                    .await?;

                manager
                    .exec_stmt(
                        Query::update()
                            .table(RemoteEntityCache::Table)
                            .value(
                                RemoteEntityCache::TmpType,
                                SimpleExpr::Column(RemoteEntityCache::Type.into_column_ref()),
                            )
                            .to_owned(),
                    )
                    .await?;

                manager
                    .alter_table(
                        Table::alter()
                            .table(RemoteEntityCache::Table)
                            .drop_column(RemoteEntityCache::Type)
                            .to_owned(),
                    )
                    .await?;

                manager
                    .alter_table(
                        Table::alter()
                            .table(RemoteEntityCache::Table)
                            .rename_column(RemoteEntityCache::TmpType, RemoteEntityCache::Type)
                            .to_owned(),
                    )
                    .await?;

                manager
                    .alter_table(
                        Table::alter()
                            .table(RemoteEntityCache::Table)
                            .modify_column(
                                ColumnDef::new(RemoteEntityCache::Type).string().not_null(),
                            )
                            .to_owned(),
                    )
                    .await?;
            }
            DbBackend::Sqlite | DbBackend::Postgres => {}
        }
        Ok(())
    }
}

#[derive(Iden)]
pub enum RemoteEntityCache {
    Table,
    Type,
    TmpType,
}
