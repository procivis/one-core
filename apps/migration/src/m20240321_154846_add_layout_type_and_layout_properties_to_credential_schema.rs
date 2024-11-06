use sea_orm::{EnumIter, Iterable};
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(CredentialSchema::Table)
                    .add_column(
                        ColumnDef::new(CredentialSchema::LayoutProperties)
                            .json()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(CredentialSchema::Table)
                    .add_column(
                        ColumnDef::new(CredentialSchema::LayoutType)
                            .enumeration(CredentialSchemaLayoutTypeEnum, LayoutTypeEnum::iter())
                            .default(Expr::val("CARD").as_enum(CredentialSchemaLayoutTypeEnum))
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum CredentialSchema {
    Table,
    LayoutProperties,
    LayoutType,
}

#[derive(DeriveIden)]
pub struct CredentialSchemaLayoutTypeEnum;

#[derive(EnumIter, DeriveIden)]
enum LayoutTypeEnum {
    #[sea_orm(iden = "CARD")]
    Card,
    #[sea_orm(iden = "DOCUMENT")]
    Document,
    #[sea_orm(iden = "SINGLE_ATTRIBUTE")]
    SingleAttribute,
}
