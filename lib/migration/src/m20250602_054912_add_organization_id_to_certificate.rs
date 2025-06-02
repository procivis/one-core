use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // add to the table `certificate` a column `organisation_id` with a FK to the `organisation` table
        match manager.get_database_backend() {
            DbBackend::Postgres => {
                manager
                    .alter_table(
                        Table::alter()
                            .table(Certificate::Table)
                            .add_column_if_not_exists(
                                ColumnDef::new(Certificate::OrganisationId)
                                    .char_len(36)
                                    .null(),
                            )
                            .to_owned(),
                    )
                    .await?;
                manager
                    .get_connection()
                    .execute_unprepared(
                        r#"
                        IF NOT EXISTS(
                            SELECT TABLE_NAME, COLUMN_NAME, CONSTRAINT_NAME, REFERENCED_TABLE_NAME, REFERENCED_COLUMN_NAME
                            FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE
                            WHERE TABLE_NAME = 'certificate' AND CONSTRAINT_NAME =  'fk_certificate_organisation_id'
                        ) THEN
                            ALTER TABLE certificate
                                ADD FOREIGN KEY (organisation_id) REFERENCES organisation(id);
                        END IF;
                        "#).await?;
                manager
                    .get_connection()
                    .execute_unprepared(
                        r#"
                    UPDATE certificate
                    SET organisation_id = identifier.organisation_id
                    FROM identifier
                    WHERE certificate.identifier_id = identifier.id;
                    "#,
                    )
                    .await?;
            }
            DbBackend::MySql => {
                manager
                    .alter_table(
                        Table::alter()
                            .table(Certificate::Table)
                            .add_column_if_not_exists(
                                ColumnDef::new(Certificate::OrganisationId)
                                    .char_len(36)
                                    .null(),
                            )
                            .to_owned(),
                    )
                    .await?;
                manager
                    .get_connection()
                    .execute_unprepared(
                        r#"
                        IF NOT EXISTS(
                            SELECT TABLE_NAME, COLUMN_NAME, CONSTRAINT_NAME, REFERENCED_TABLE_NAME, REFERENCED_COLUMN_NAME
                            FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE
                            WHERE TABLE_NAME = 'certificate' AND CONSTRAINT_NAME =  'fk_certificate_organisation_id'
                        ) THEN
                            ALTER TABLE certificate
                                ADD CONSTRAINT fk_certificate_organisation_id FOREIGN KEY (organisation_id) REFERENCES organisation(id);
                        END IF;
                        "#).await?;

                manager
                    .get_connection()
                    .execute_unprepared(
                        r#"
                    UPDATE certificate, identifier
                    SET
                        certificate.organisation_id = identifier.organisation_id
                    WHERE
                        certificate.identifier_id = identifier.id;
                    "#,
                    )
                    .await?;
            }
            DbBackend::Sqlite => {
                manager
                    .get_connection()
                    .execute_unprepared(
                        r#"
                    ALTER TABLE certificate 
                    ADD COLUMN organisation_id VARCHAR(36) REFERENCES organisation(id);
                    "#,
                    )
                    .await?;
                manager
                    .get_connection()
                    .execute_unprepared(
                        r#"
                    UPDATE certificate
                    SET organisation_id = identifier.organisation_id
                    FROM identifier
                    WHERE certificate.identifier_id = identifier.id;
                    "#,
                    )
                    .await?;
            }
        }

        // create unique index on Fingerprint and OrganisationId for Certificate
        manager
            .create_index(
                Index::create()
                    .unique()
                    .name("index-Certificate-Fingerprint-OrganisationId-Unique")
                    .table(Certificate::Table)
                    .col(Certificate::Fingerprint)
                    .col(Certificate::OrganisationId)
                    .if_not_exists()
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
