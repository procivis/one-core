use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;

use crate::m20240110_000001_initial::Organisation;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // truncate `certificate` table
        manager
            .exec_stmt(Query::delete().from_table(Certificate::Table).to_owned())
            .await?;

        // add to the table `certificate` a column `organisation_id` with a FK to the `organisation` table
        match manager.get_database_backend() {
            DbBackend::MySql | DbBackend::Postgres => {
                manager
                    .alter_table(
                        Table::alter()
                            .table(Certificate::Table)
                            .add_column(ColumnDef::new(Certificate::OrganisationId).string().null())
                            .add_foreign_key(
                                ForeignKey::create()
                                    .name("fk_certificate_organisation_id")
                                    .from(Certificate::Table, Certificate::OrganisationId)
                                    .to(Organisation::Table, Organisation::Id)
                                    .get_foreign_key(),
                            )
                            .to_owned(),
                    )
                    .await?
            }
            DbBackend::Sqlite => {
                let sql = r#"ALTER TABLE certificate ADD COLUMN organisation_id TEXT REFERENCES organisation(id);"#;
                manager.get_connection().execute_unprepared(sql).await?;
            }
        }

        // create unique index on Fingerprint and OrganisationId for Certificate
        manager
            .create_index(
                Index::create()
                    .unique()
                    .name("index-Certificate-Fingerprint-OrganisationId--Unique")
                    .table(Certificate::Table)
                    .col(Certificate::Fingerprint)
                    .col(Certificate::OrganisationId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum Certificate {
    Table,
    OrganisationId,
    Fingerprint,
}
