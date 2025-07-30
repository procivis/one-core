use sea_orm_migration::prelude::*;

use crate::datatype::ColumnDefExt;
use crate::m20240110_000001_initial::Key;
use crate::m20250429_142011_add_identifier::Identifier;

#[derive(DeriveMigrationName)]
pub struct Migration;

const UNIQUE_CERTIFICATE_NAME_EXPIRY_IN_IDENTIFIER_INDEX: &str =
    "index-Certificate-Name-ExpiryDate-IdentifierId-Unique";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == sea_orm::DatabaseBackend::Postgres {
            // Skip because it is not supported. If support for Postgres is added in the future
            // the schema can be setup in its entirety in a new, later migration.
            return Ok(());
        }
        manager
            .create_table(
                Table::create()
                    .table(Certificate::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Certificate::Id)
                            .char_len(36)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Certificate::CreatedDate)
                            .datetime_millisecond_precision(manager)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Certificate::LastModified)
                            .datetime_millisecond_precision(manager)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Certificate::ExpiryDate)
                            .datetime_second_precision(manager)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Certificate::IdentifierId)
                            .char_len(36)
                            .not_null(),
                    )
                    .col(ColumnDef::new(Certificate::Name).string().not_null())
                    .col(ColumnDef::new(Certificate::Chain).text().not_null())
                    .col(ColumnDef::new(Certificate::State).string().not_null())
                    .col(ColumnDef::new(Certificate::KeyId).char_len(36))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_certificate_identifier")
                            .from(Certificate::Table, Certificate::IdentifierId)
                            .to(Identifier::Table, Identifier::Id),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_certificate_key")
                            .from(Certificate::Table, Certificate::KeyId)
                            .to(Key::Table, Key::Id),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name(UNIQUE_CERTIFICATE_NAME_EXPIRY_IN_IDENTIFIER_INDEX)
                    .table(Certificate::Table)
                    .col(Certificate::Name)
                    .col(Certificate::ExpiryDate)
                    .col(Certificate::IdentifierId)
                    .unique()
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum Certificate {
    Table,
    Id,
    IdentifierId,
    CreatedDate,
    LastModified,
    ExpiryDate,
    Name,
    Chain,
    State,
    KeyId,
}
