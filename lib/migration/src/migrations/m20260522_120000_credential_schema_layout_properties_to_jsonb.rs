use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::json_binary_null;
use sea_orm_migration_sqlite::{SchemaManagerExt, TableExt};

use crate::supported_db_type::{SupportedDbType, WithSupportedDbType};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.supported_db_type() {
            SupportedDbType::MySql => {
                // JSONB type is resolved into JSON in this case, thus we don't have to execute migration there
                Ok(())
            }
            SupportedDbType::Sqlite => alter_credential_schema_sqlite(manager).await,
            SupportedDbType::Postgres => {
                // json_binary_null(CredentialSchema::LayoutProperties).using("layout_properties::JSONB") creates strange SQL:
                //    ALTER TABLE "credential_schema" ALTER COLUMN "layout_properties" TYPE jsonb, ALTER COLUMN "layout_properties" DROP NOT NULL USING 'layout_properties::JSONB'
                // so I used raw version
                let db = manager.get_connection();
                db.execute_unprepared(
                    r#"ALTER TABLE "credential_schema"
                       ALTER COLUMN "layout_properties" TYPE JSONB
                       USING "layout_properties"::JSONB"#,
                )
                .await
                .map(|_| ())
            }
        }
    }
}

async fn alter_credential_schema_sqlite(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let _db = manager.get_connection();

    manager
        .recreate_table(
            Table::recreate()
                .table(CredentialSchema::Table)
                .modify_column(json_binary_null(CredentialSchemaNew::LayoutProperties))
                .to_owned(),
        )
        .await?;

    Ok(())
}

#[derive(Clone, DeriveIden)]
enum CredentialSchema {
    Table,
}

#[derive(Clone, DeriveIden)]
enum CredentialSchemaNew {
    LayoutProperties,
}
