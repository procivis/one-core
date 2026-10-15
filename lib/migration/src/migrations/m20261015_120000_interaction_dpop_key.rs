use sea_orm::ConnectionTrait;
use sea_orm_migration::prelude::*;

use crate::datatype::uuid_char_null;
use crate::migrations::m20260417_150300_initial::{Interaction, Key};
use crate::supported_db_type::{SupportedDbType, WithSupportedDbType};

#[derive(DeriveMigrationName)]
pub struct Migration;

const FK_INTERACTION_DPOP_KEY: &str = "fk-Interaction-DpopKeyId";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.supported_db_type() == SupportedDbType::Sqlite {
            // SQLite rejects a separate `ADD FOREIGN KEY`, but it does accept a `REFERENCES`
            // clause on an added column as long as that column defaults to NULL
            manager
                .get_connection()
                .execute_unprepared(&format!(
                    r#"ALTER TABLE "{interaction}" ADD COLUMN "{dpop_key_id}" char(36) NULL REFERENCES "{key}" ("{id}")"#,
                    interaction = Interaction::Table.to_string(),
                    dpop_key_id = Col::DpopKeyId.to_string(),
                    key = Key::Table.to_string(),
                    id = Key::Id.to_string(),
                ))
                .await?;

            return Ok(());
        }

        manager
            .alter_table(
                Table::alter()
                    .table(Interaction::Table)
                    .add_column(uuid_char_null(Col::DpopKeyId))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Interaction::Table)
                    .add_foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name(FK_INTERACTION_DPOP_KEY)
                            .from_tbl(Interaction::Table)
                            .from_col(Col::DpopKeyId)
                            .to_tbl(Key::Table)
                            .to_col(Key::Id)
                            .get_foreign_key(),
                    )
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum Col {
    DpopKeyId,
}
