use sea_orm_migration::prelude::*;

use crate::datatype::ColumnDefExt;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let delete_statement = Query::delete()
            .from_table(RemoteEntityCache::Table)
            .and_where(Expr::col(RemoteEntityCache::Persistent).eq(false))
            .to_owned();
        manager.exec_stmt(delete_statement).await?;
        manager
            .alter_table(
                Table::alter()
                    .table(RemoteEntityCache::Table)
                    .add_column(
                        ColumnDef::new(RemoteEntityCache::ExpirationDate)
                            .datetime_millisecond_precision(manager)
                            .null()
                            .to_owned(),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(RemoteEntityCache::Table)
                    .drop_column(RemoteEntityCache::Persistent)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
pub enum RemoteEntityCache {
    Table,
    Persistent,
    ExpirationDate,
}
