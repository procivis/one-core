use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::*;

use crate::datatype::{ColumnDefExt, timestamp, timestamp_null, uuid_char, uuid_char_null};
use crate::m20240110_000001_initial::{Key, Organisation};
use crate::m20250429_142011_add_identifier::Identifier;
use crate::m20250512_110852_certificate::Certificate;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == DatabaseBackend::Postgres {
            return Ok(());
        }

        manager
            .create_table(
                Table::create()
                    .table(TrustListPublication::Table)
                    .col(uuid_char(TrustListPublication::Id).primary_key())
                    .col(timestamp(TrustListPublication::CreatedDate, manager))
                    .col(timestamp(TrustListPublication::LastModified, manager))
                    .col(text(TrustListPublication::Name))
                    .col(string_null(TrustListPublication::Role))
                    .col(string(TrustListPublication::Type))
                    .col(
                        ColumnDef::new(TrustListPublication::Metadata)
                            .large_blob(manager)
                            .not_null(),
                    )
                    .col(timestamp_null(TrustListPublication::DeactivatedAt, manager))
                    .col(
                        ColumnDef::new(TrustListPublication::Content)
                            .large_blob(manager)
                            .null(),
                    )
                    .col(big_unsigned(TrustListPublication::SequenceNumber))
                    .col(uuid_char_null(TrustListPublication::OrganisationId))
                    .col(uuid_char_null(TrustListPublication::IdentifierId))
                    .col(uuid_char_null(TrustListPublication::KeyId))
                    .col(uuid_char_null(TrustListPublication::CertificateId))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-TrustListPublication-OrganisationId")
                            .from_tbl(TrustListPublication::Table)
                            .from_col(TrustListPublication::OrganisationId)
                            .to_tbl(Organisation::Table)
                            .to_col(Organisation::Id),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-TrustListPublication-IdentifierId")
                            .from_tbl(TrustListPublication::Table)
                            .from_col(TrustListPublication::IdentifierId)
                            .to_tbl(Identifier::Table)
                            .to_col(Identifier::Id),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-TrustListPublication-KeyId")
                            .from_tbl(TrustListPublication::Table)
                            .from_col(TrustListPublication::KeyId)
                            .to_tbl(Key::Table)
                            .to_col(Key::Id),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-TrustListPublication-CertificateId")
                            .from_tbl(TrustListPublication::Table)
                            .from_col(TrustListPublication::CertificateId)
                            .to_tbl(Certificate::Table)
                            .to_col(Certificate::Id),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum TrustListPublication {
    Table,
    Id,
    CreatedDate,
    LastModified,
    Name,
    Role,
    Type,
    Metadata,
    DeactivatedAt,
    Content,
    SequenceNumber,
    OrganisationId,
    IdentifierId,
    KeyId,
    CertificateId,
}
