use sea_orm_migration::prelude::*;
pub const UNIQUE_NAME_IN_ORGANISATION_INDEX: &str = "index-Organisation-Name-Unique";

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Organisation::Table)
                    .add_column_if_not_exists(
                        ColumnDef::new(Organisation::Name)
                            .text()
                            .default("temporary name".to_owned()) // required because of the not null constraint
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .exec_stmt(
                Query::update()
                    .table(Organisation::Table)
                    .value(
                        Organisation::Name,
                        SimpleExpr::Column(Organisation::Id.into_column_ref()),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name(UNIQUE_NAME_IN_ORGANISATION_INDEX)
                    .unique()
                    .table(Organisation::Table)
                    .col(Organisation::Name)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum Organisation {
    Table,
    Id,
    Name,
}
