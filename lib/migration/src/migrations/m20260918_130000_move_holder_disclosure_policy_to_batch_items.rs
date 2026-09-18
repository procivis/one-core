use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let parent = Alias::new("parent");
        // Keep any policy already stored on an item. Include consumed and deleted items
        // so their configuration policy is preserved as well.
        manager
            .exec_stmt(
                Query::update()
                    .table(Credential::Table)
                    .value(
                        Credential::EmbeddedDisclosurePolicy,
                        Expr::col((parent.clone(), Credential::EmbeddedDisclosurePolicy)),
                    )
                    .from(TableRef::TableAlias(
                        Credential::Table.into_iden(),
                        parent.clone().into_iden(),
                    ))
                    .and_where(
                        Expr::col((Credential::Table, Credential::ParentId))
                            .equals((parent.clone(), Credential::Id)),
                    )
                    .and_where(Expr::col((Credential::Table, Credential::Role)).eq("HOLDER"))
                    .and_where(Expr::col((Credential::Table, Credential::Type)).eq("BATCH_ITEM"))
                    .and_where(Expr::col((parent.clone(), Credential::Role)).eq("HOLDER"))
                    .and_where(Expr::col((parent.clone(), Credential::Type)).eq("BATCH_PARENT"))
                    .and_where(
                        Expr::col((Credential::Table, Credential::EmbeddedDisclosurePolicy))
                            .is_null(),
                    )
                    .and_where(
                        Expr::col((parent, Credential::EmbeddedDisclosurePolicy)).is_not_null(),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .exec_stmt(
                Query::update()
                    .table(Credential::Table)
                    .value(Credential::EmbeddedDisclosurePolicy, Option::<String>::None)
                    .and_where(Expr::col(Credential::Role).eq("HOLDER"))
                    .and_where(Expr::col(Credential::Type).eq("BATCH_PARENT"))
                    .and_where(Expr::col(Credential::EmbeddedDisclosurePolicy).is_not_null())
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum Credential {
    Table,
    Id,
    ParentId,
    Role,
    Type,
    EmbeddedDisclosurePolicy,
}
