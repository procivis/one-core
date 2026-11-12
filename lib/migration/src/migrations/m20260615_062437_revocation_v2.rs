use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::boolean;
use sea_orm_migration_sqlite::{SchemaManagerExt, TableExt};

use crate::supported_db_type::{SupportedDbType, WithSupportedDbType};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();

        db.execute(
            Query::update()
                .table(CredentialSchema::Table)
                .value(CredentialSchema::AllowRevocation, false)
                .and_where(Expr::col(CredentialSchema::AllowRevocation).is_null())
                .and_where(Expr::col(CredentialSchema::RevocationMethod).is_null()),
        )
        .await?;

        db.execute(
            Query::update()
                .table(CredentialSchema::Table)
                .value(CredentialSchema::AllowRevocation, false)
                .and_where(Expr::col(CredentialSchema::AllowRevocation).is_null())
                .and_where(
                    Expr::col(CredentialSchema::RevocationMethod).eq("MDOC_MSO_UPDATE_SUSPENSION"),
                ),
        )
        .await?;

        db.execute(
            Query::update()
                .table(CredentialSchema::Table)
                .value(CredentialSchema::AllowRevocation, true)
                .and_where(Expr::col(CredentialSchema::AllowRevocation).is_null())
                .and_where(Expr::col(CredentialSchema::RevocationMethod).is_not_null()),
        )
        .await?;

        if manager.supported_db_type() == SupportedDbType::Sqlite {
            sqlite_migration(manager).await?;
        } else {
            manager
                .alter_table(
                    Table::alter()
                        .table(CredentialSchema::Table)
                        .modify_column(
                            ColumnDef::new(CredentialSchema::AllowRevocation)
                                .boolean()
                                .not_null(),
                        )
                        .to_owned(),
                )
                .await?;

            manager
                .alter_table(
                    Table::alter()
                        .table(CredentialSchema::Table)
                        .drop_column(CredentialSchema::RevocationMethod)
                        .to_owned(),
                )
                .await?;
        }

        Ok(())
    }
}

async fn sqlite_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .recreate_table(
            Table::recreate()
                .table(CredentialSchema::Table)
                .drop_column(CredentialSchema::RevocationMethod)
                .modify_column(boolean(CredentialSchema::AllowRevocation))
                .to_owned(),
        )
        .await?;

    Ok(())
}

#[derive(Clone, DeriveIden)]
enum CredentialSchema {
    Table,
    AllowRevocation,

    RevocationMethod,
}
