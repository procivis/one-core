use sea_orm_migration::prelude::*;
use sea_orm_migration_sqlite::{SchemaManagerExt, TableExt};

use crate::datatype::uuid_char;
use crate::foreign_key::{disable_foreign_key_checks, enable_foreign_key_checks};
use crate::migrations::m20260417_150300_initial::Identifier;
use crate::supported_db_type::{SupportedDbType, WithSupportedDbType};

#[derive(DeriveMigrationName)]
pub struct Migration;

// Mirrors the constants defined (privately) in m20260417_150300_initial for the identifier table.

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        disable_foreign_key_checks(manager).await?;

        // All the identifiers without organisation are an artifact of the legacy trust management.
        // These are identifiers belonging to verifier installations that enrolled themselves onto the
        // legacy trust lists. Given the legacy trust management has been removed, the identifiers are no longer needed.
        // And since they have not been associated with any organisation, they should not have been
        // used for other purposes since.
        manager
            .exec_stmt(
                Query::delete()
                    .from_table(Identifier::Table)
                    .and_where(Expr::col(Identifier::OrganisationId).is_null())
                    .to_owned(),
            )
            .await?;

        if manager.supported_db_type() == SupportedDbType::Sqlite {
            self.up_sqlite(manager).await?;
        } else {
            self.up_sane(manager).await?;
        }

        enable_foreign_key_checks(manager).await?;
        Ok(())
    }
}

impl Migration {
    async fn up_sane(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Identifier::Table)
                    .modify_column(uuid_char(Identifier::OrganisationId))
                    .to_owned(),
            )
            .await
    }

    async fn up_sqlite(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        manager
            .recreate_table(
                Table::recreate()
                    .table(Identifier::Table)
                    .modify_column(uuid_char(Identifier::OrganisationId))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
