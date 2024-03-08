use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(RevocationList::Table)
                    .add_column(
                        ColumnDef::new(RevocationList::Purpose)
                            .enumeration(
                                RevocationListPurpose::Table,
                                [
                                    RevocationListPurpose::Revocation,
                                    RevocationListPurpose::Suspension,
                                ],
                            )
                            .default(SimpleExpr::Constant(Value::String(Some(Box::new(
                                RevocationListPurpose::Revocation.into_iden().to_string(),
                            )))))
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(RevocationList::Table)
                    .drop_column(RevocationList::Purpose)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum RevocationList {
    Table,
    Purpose,
}

#[derive(Iden)]
enum RevocationListPurpose {
    Table,
    #[iden = "REVOCATION"]
    Revocation,
    #[iden = "SUSPENSION"]
    Suspension,
}
