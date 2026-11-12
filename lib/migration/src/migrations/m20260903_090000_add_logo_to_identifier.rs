use sea_orm_migration::prelude::*;
use sea_orm_migration_sqlite::{SchemaManagerExt, TableExt};

use crate::datatype::uuid_char_null;
use crate::foreign_key::{disable_foreign_key_checks, enable_foreign_key_checks};
use crate::migrations::m20260417_150300_initial::{BlobStorage, Identifier};
use crate::supported_db_type::{SupportedDbType, WithSupportedDbType};

#[derive(DeriveMigrationName)]
pub struct Migration;

const FK_IDENTIFIER_LOGO: &str = "fk_identifier_logo";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        disable_foreign_key_checks(manager).await?;
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
                    .add_column(uuid_char_null(Col::Logo))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Identifier::Table)
                    .add_foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name(FK_IDENTIFIER_LOGO)
                            .from_tbl(Identifier::Table)
                            .from_col(Col::Logo)
                            .to_tbl(BlobStorage::Table)
                            .to_col(BlobStorage::Id)
                            .get_foreign_key(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn up_sqlite(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        manager
            .recreate_table(
                Table::recreate()
                    .table(Identifier::Table)
                    .add_column(uuid_char_null(Col::Logo))
                    .add_foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name(FK_IDENTIFIER_LOGO)
                            .from_tbl(Identifier::Table)
                            .from_col(Col::Logo)
                            .to_tbl(BlobStorage::Table)
                            .to_col(BlobStorage::Id)
                            .to_owned(),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum Col {
    Logo,
}
