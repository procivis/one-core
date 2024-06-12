use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Claim::Table)
                    .add_column_if_not_exists(
                        ColumnDef::new(Claim::Path).string().not_null().default(""),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(ClaimSchema::Table)
                    .add_column_if_not_exists(
                        ColumnDef::new(ClaimSchema::Array)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .to_owned(),
            )
            .await?;

        let db = manager.get_connection();
        let query = match manager.get_database_backend() {
            DatabaseBackend::Sqlite => {
                "UPDATE claim
                    SET path = (
                        SELECT key
                        FROM claim_schema
                        WHERE claim.claim_schema_id = claim_schema.id
                    )
                    WHERE EXISTS (
                        SELECT 1
                        FROM claim_schema
                        WHERE claim.claim_schema_id = claim_schema.id
                    );"
            }
            _ => {
                "UPDATE claim
                    JOIN claim_schema ON claim.claim_schema_id = claim_schema.id
                    SET claim.path = claim_schema.key;"
            }
        };
        db.execute_unprepared(query).await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Claim::Table)
                    .drop_column(Claim::Path)
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(ClaimSchema::Table)
                    .drop_column(ClaimSchema::Array)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(Iden)]
#[allow(clippy::enum_variant_names, unused)]
pub enum Claim {
    Table,
    Id,
    ClaimSchemaId,
    CredentialId,
    Value,
    CreatedDate,
    LastModified,
    Path,
}

#[derive(Iden)]
#[allow(unused)]
pub enum ClaimSchema {
    Table,
    Id,
    Datatype,
    Key,
    CreatedDate,
    LastModified,
    Array,
}
