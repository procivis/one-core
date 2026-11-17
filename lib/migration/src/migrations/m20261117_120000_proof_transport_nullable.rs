use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::string_null;
use sea_orm_migration_sqlite::{SchemaManagerExt, TableExt};

use crate::migrations::m20260417_150300_initial::Proof;
use crate::supported_db_type::{SupportedDbType, WithSupportedDbType};

/// The proof transport is not known until selected, if multiple transports were offered.
/// Previously an empty string was stored as marker, now it is `NULL`.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.supported_db_type() {
            SupportedDbType::Sqlite => {
                manager
                    .recreate_table(
                        Table::recreate()
                            .table(Proof::Table)
                            .modify_column(string_null(Proof::Transport))
                            .to_owned(),
                    )
                    .await?;
            }
            r#type @ (SupportedDbType::MySql | SupportedDbType::Postgres) => {
                manager
                    .alter_table(
                        Table::alter()
                            .table(Proof::Table)
                            .modify_column(string_null(Proof::Transport))
                            .to_owned(),
                    )
                    .await?;
                if r#type == SupportedDbType::MySql {
                    // MODIFY COLUMN on a nullable column implicitly adds `DEFAULT NULL`
                    manager
                        .get_connection()
                        .execute_unprepared(
                            "ALTER TABLE `proof` ALTER COLUMN `transport` DROP DEFAULT",
                        )
                        .await?;
                }
            }
        }

        manager
            .exec_stmt(
                Query::update()
                    .table(Proof::Table)
                    .value(Proof::Transport, Option::<String>::None)
                    .and_where(Expr::col(Proof::Transport).eq(""))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Ok(())
    }
}
