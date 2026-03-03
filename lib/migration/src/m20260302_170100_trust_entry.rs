use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::*;

use crate::datatype::{ColumnDefExt, timestamp, uuid_char, uuid_char_null};
use crate::m20250429_142011_add_identifier::Identifier;
use crate::m20260302_170000_trust_list_publication::TrustListPublication;

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
                    .table(TrustEntry::Table)
                    .col(uuid_char(TrustEntry::Id).primary_key())
                    .col(timestamp(TrustEntry::CreatedDate, manager))
                    .col(timestamp(TrustEntry::LastModified, manager))
                    .col(string(TrustEntry::Status))
                    .col(
                        ColumnDef::new(TrustEntry::Metadata)
                            .large_blob(manager)
                            .not_null(),
                    )
                    .col(uuid_char(TrustEntry::TrustListPublicationId))
                    .col(uuid_char_null(TrustEntry::IdentifierId))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-TrustEntry-TrustListPublicationId")
                            .from_tbl(TrustEntry::Table)
                            .from_col(TrustEntry::TrustListPublicationId)
                            .to_tbl(TrustListPublication::Table)
                            .to_col(TrustListPublication::Id),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-TrustEntry-IdentifierId")
                            .from_tbl(TrustEntry::Table)
                            .from_col(TrustEntry::IdentifierId)
                            .to_tbl(Identifier::Table)
                            .to_col(Identifier::Id),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum TrustEntry {
    Table,
    Id,
    CreatedDate,
    LastModified,
    Status,
    Metadata,
    TrustListPublicationId,
    IdentifierId,
}
