use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DbBackend::Postgres => {}
            DbBackend::MySql => {
                manager
                    .alter_table(
                        Table::alter()
                            .table(RevocationList::Table)
                            .add_column_if_not_exists(
                                ColumnDef::new(RevocationList::IssuerIdentifierId)
                                    .char_len(36)
                                    .null(),
                            )
                            .to_owned()
                            .add_foreign_key(
                                TableForeignKey::new()
                                    .name("fk_revocation_list_issuer_identifier_id")
                                    .from_tbl(RevocationList::Table)
                                    .from_col(RevocationList::IssuerIdentifierId)
                                    .to_tbl(Identifier::Table)
                                    .to_col(Identifier::Id),
                            )
                            .to_owned(),
                    )
                    .await?;
            }
            DbBackend::Sqlite => {
                manager
                    .get_connection()
                    .execute_unprepared(
                        r#"
                    ALTER TABLE revocation_list 
                    ADD COLUMN issuer_identifier_id VARCHAR(36) REFERENCES identifier(id);
                    "#,
                    )
                    .await?;
            }
        }
        Ok(())
    }
}

#[derive(DeriveIden)]
enum RevocationList {
    Table,
    IssuerIdentifierId,
}

#[derive(DeriveIden)]
enum Identifier {
    Table,
    Id,
}
