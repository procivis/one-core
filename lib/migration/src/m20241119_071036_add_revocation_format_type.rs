use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == sea_orm::DatabaseBackend::Postgres {
            // Skip because it is not supported. If support for Postgres is added in the future
            // the schema can be setup in its entirety in a new, later migration.
            return Ok(());
        }
        manager
            .alter_table(
                Table::alter()
                    .table(RevocationList::Table)
                    .add_column_if_not_exists(
                        ColumnDef::new(RevocationList::Format)
                            .enumeration(
                                StatusListCredentialFormat::Table,
                                [
                                    StatusListCredentialFormat::Jwt,
                                    StatusListCredentialFormat::JsonLd,
                                ],
                            )
                            .default("JWT")
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(RevocationList::Table)
                    .add_column_if_not_exists(
                        ColumnDef::new(RevocationList::Type)
                            .string()
                            .default("BITSTRING_STATUS_LIST")
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}

#[derive(Iden)]
#[allow(unused)]
pub enum RevocationList {
    Table,
    Id,
    CreatedDate,
    LastModified,
    Credentials,
    IssuerDidId,
    Format,
    Type,
}

#[derive(Iden)]
pub enum StatusListCredentialFormat {
    Table,
    #[iden = "JWT"]
    Jwt,
    #[iden = "JSON_LD_CLASSIC"]
    JsonLd,
}
