use sea_orm_migration::{prelude::*, sea_orm::DbBackend};

use crate::m20230530_000001_initial::CredentialSchema;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            sea_orm::DatabaseBackend::Sqlite => up_sqlite(manager).await,
            _ => up_other(manager).await,
        }
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == DbBackend::Sqlite {
            unimplemented!()
        } else {
            manager
                .alter_table(
                    Table::alter()
                        .table(CredentialSchema::Table)
                        .modify_column(
                            ColumnDef::new(CredentialSchema::RevocationMethod)
                                .enumeration(
                                    RevocationMethod::Table,
                                    [RevocationMethod::StatusList2021, RevocationMethod::Lvvc],
                                )
                                .not_null(),
                        )
                        .to_owned(),
                )
                .await?;
        }

        Ok(())
    }
}

#[derive(Iden)]
pub enum RevocationMethod {
    Table,
    #[iden = "NONE"]
    None,
    #[iden = "STATUSLIST2021"]
    StatusList2021,
    #[iden = "LVVC"]
    Lvvc,
}

async fn up_sqlite<'a>(manager: &'a SchemaManager<'a>) -> Result<(), DbErr> {
    manager
        .alter_table(
            Table::alter()
                .table(CredentialSchema::Table)
                .add_column(
                    ColumnDef::new(Alias::new("revocation_new"))
                        .enumeration(
                            RevocationMethod::Table,
                            [
                                RevocationMethod::None,
                                RevocationMethod::StatusList2021,
                                RevocationMethod::Lvvc,
                            ],
                        )
                        .default("NONE")
                        .not_null(),
                )
                .to_owned(),
        )
        .await?;

    // We manually copy column content here
    let db = manager.get_connection();
    db.execute_unprepared("UPDATE credential_schema SET revocation_new = revocation_method;")
        .await?;

    manager
        .alter_table(
            Table::alter()
                .table(CredentialSchema::Table)
                .drop_column(Alias::new("revocation_method"))
                .to_owned(),
        )
        .await?;

    manager
        .alter_table(
            Table::alter()
                .table(CredentialSchema::Table)
                .rename_column(
                    Alias::new("revocation_new"),
                    Alias::new("revocation_method"),
                )
                .to_owned(),
        )
        .await?;

    Ok(())
}

async fn up_other<'a>(manager: &'a SchemaManager<'a>) -> Result<(), DbErr> {
    manager
        .alter_table(
            Table::alter()
                .table(CredentialSchema::Table)
                .modify_column(
                    ColumnDef::new(CredentialSchema::RevocationMethod)
                        .enumeration(
                            RevocationMethod::Table,
                            [
                                RevocationMethod::None,
                                RevocationMethod::StatusList2021,
                                RevocationMethod::Lvvc,
                            ],
                        )
                        .not_null(),
                )
                .to_owned(),
        )
        .await?;

    Ok(())
}
