use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::string;

use crate::datatype::{ColumnDefExt, timestamp, uuid_char, uuid_char_null};
use crate::m20240110_000001_initial::{Key, Organisation};
use crate::m20250429_142011_add_identifier::Identifier;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DatabaseBackend::Postgres => {}
            DatabaseBackend::MySql => {
                // remove default value
                manager
                    .alter_table(
                        Table::alter()
                            .table(Certificate::Table)
                            .modify_column(
                                ColumnDef::new(Certificate::Fingerprint).string().not_null(),
                            )
                            .to_owned(),
                    )
                    .await?;

                // recreate foreign key to organisation table
                manager
                    .get_connection()
                    .execute_unprepared(
                        r#"
                            ALTER TABLE certificate
                                DROP CONSTRAINT IF EXISTS fk_certificate_organisation_id;
                        "#,
                    )
                    .await?;

                manager
                    .alter_table(
                        Table::alter()
                            .table(Certificate::Table)
                            .add_foreign_key(
                                TableForeignKey::new()
                                    .name("fk_certificate_organisation_id")
                                    .from_tbl(Certificate::Table)
                                    .from_col(Certificate::OrganisationId)
                                    .to_tbl(Organisation::Table)
                                    .to_col(Organisation::Id)
                                    .on_update(ForeignKeyAction::Restrict)
                                    .on_delete(ForeignKeyAction::Restrict),
                            )
                            .to_owned(),
                    )
                    .await?;
            }
            DatabaseBackend::Sqlite => sqlite_migration(manager).await?,
        };

        Ok(())
    }
}

#[derive(Iden)]
enum CertificateNew {
    Table,
}

#[derive(Clone, Iden)]
enum Certificate {
    Table,
    Id,
    CreatedDate,
    LastModified,
    ExpiryDate,
    IdentifierId,
    Name,
    Chain,
    State,
    KeyId,
    Fingerprint,
    OrganisationId,
}

async fn sqlite_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let db = manager.get_connection();

    db.execute_unprepared("PRAGMA defer_foreign_keys = ON;")
        .await?;

    // Create new table with the correct columns
    manager
        .create_table(
            Table::create()
                .table(CertificateNew::Table)
                .col(uuid_char(Certificate::Id).primary_key())
                .col(timestamp(Certificate::CreatedDate, manager))
                .col(timestamp(Certificate::LastModified, manager))
                .col(
                    ColumnDef::new(Certificate::ExpiryDate)
                        .datetime_second_precision(manager)
                        .not_null(),
                )
                .col(uuid_char(Certificate::IdentifierId))
                .col(string(Certificate::Name))
                .col(ColumnDef::new(Certificate::Chain).text().not_null())
                .col(string(Certificate::State))
                .col(uuid_char_null(Certificate::KeyId))
                .col(string(Certificate::Fingerprint))
                .col(uuid_char_null(Certificate::OrganisationId))
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_certificate_identifier")
                        .from_tbl(CertificateNew::Table)
                        .from_col(Certificate::IdentifierId)
                        .to_tbl(Identifier::Table)
                        .to_col(Identifier::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_certificate_key")
                        .from_tbl(CertificateNew::Table)
                        .from_col(Certificate::KeyId)
                        .to_tbl(Key::Table)
                        .to_col(Key::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_certificate_organisation_id")
                        .from_tbl(CertificateNew::Table)
                        .from_col(Certificate::OrganisationId)
                        .to_tbl(Organisation::Table)
                        .to_col(Organisation::Id),
                )
                .to_owned(),
        )
        .await?;

    // Copy data from old table to new table
    let copied_columns = vec![
        Certificate::Id,
        Certificate::CreatedDate,
        Certificate::LastModified,
        Certificate::ExpiryDate,
        Certificate::IdentifierId,
        Certificate::Name,
        Certificate::Chain,
        Certificate::State,
        Certificate::KeyId,
        Certificate::Fingerprint,
        Certificate::OrganisationId,
    ];
    manager
        .exec_stmt(
            Query::insert()
                .into_table(CertificateNew::Table)
                .columns(copied_columns.to_vec())
                .select_from(
                    Query::select()
                        .from(Certificate::Table)
                        .columns(copied_columns)
                        .to_owned(),
                )
                .map_err(|e| DbErr::Migration(e.to_string()))?
                .to_owned(),
        )
        .await?;

    // Drop old table & rename new table
    manager
        .drop_table(Table::drop().table(Certificate::Table).to_owned())
        .await?;

    manager
        .rename_table(
            Table::rename()
                .table(CertificateNew::Table, Certificate::Table)
                .to_owned(),
        )
        .await?;

    // Recreate indexes
    manager
        .create_index(
            Index::create()
                .unique()
                .name("index-Certificate-Fingerprint-OrganisationId-Unique")
                .table(Certificate::Table)
                .col(Certificate::Fingerprint)
                .col(Certificate::OrganisationId)
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .unique()
                .name("index-Certificate-Name-ExpiryDate-IdentifierId-Unique")
                .table(Certificate::Table)
                .col(Certificate::Name)
                .col(Certificate::ExpiryDate)
                .col(Certificate::IdentifierId)
                .to_owned(),
        )
        .await?;

    db.execute_unprepared("PRAGMA defer_foreign_keys = OFF;")
        .await?;

    Ok(())
}
