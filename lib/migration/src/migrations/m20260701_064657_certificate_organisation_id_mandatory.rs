use sea_orm_migration::prelude::*;
use sea_orm_migration_sqlite::{SchemaManagerExt, TableExt};

use crate::datatype::uuid_char;
use crate::foreign_key::{disable_foreign_key_checks, enable_foreign_key_checks};
use crate::migrations::m20260417_150300_initial::Certificate;
use crate::supported_db_type::{SupportedDbType, WithSupportedDbType};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .exec_stmt(
                Query::delete()
                    .from_table(Certificate::Table)
                    .and_where(Expr::col(Certificate::OrganisationId).is_null())
                    .to_owned(),
            )
            .await?;

        disable_foreign_key_checks(manager).await?;

        let backend = manager.supported_db_type();
        if backend == SupportedDbType::Sqlite {
            up_sqlite(manager).await?;
        } else {
            manager
                .alter_table(
                    Table::alter()
                        .table(Certificate::Table)
                        .modify_column(uuid_char(Certificate::OrganisationId))
                        .to_owned(),
                )
                .await?;
        }

        enable_foreign_key_checks(manager).await?;

        Ok(())
    }
}

async fn up_sqlite(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .recreate_table(
            Table::recreate()
                .table(Certificate::Table)
                .modify_column(uuid_char(Certificate::OrganisationId))
                .to_owned(),
        )
        .await?;

    Ok(())
}
