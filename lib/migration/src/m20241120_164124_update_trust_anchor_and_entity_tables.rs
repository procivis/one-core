use sea_orm::{DatabaseBackend, EnumIter};
use sea_orm_migration::prelude::*;

use crate::datatype::ColumnDefExt;

const TRUST_ANCHOR_NAME_UNIQUE_INDEX: &str = "UK-TrustAnchor-Name";

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let mut drop_trust_entity_statement = Table::drop().table(TrustEntity::Table).to_owned();
        let mut drop_trust_anchor_statement = Table::drop().table(TrustAnchor::Table).to_owned();

        if !matches!(manager.get_database_backend(), DatabaseBackend::Sqlite) {
            drop_trust_entity_statement.if_exists();
            drop_trust_anchor_statement.if_exists();
        }

        manager
            .drop_table(drop_trust_entity_statement.take())
            .await?;

        manager
            .drop_table(drop_trust_anchor_statement.take())
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(TrustAnchor::Table)
                    .col(
                        ColumnDef::new(TrustAnchor::Id)
                            .char_len(36)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(TrustAnchor::CreatedDate)
                            .datetime_millisecond_precision(manager)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(TrustAnchor::LastModified)
                            .datetime_millisecond_precision(manager)
                            .not_null(),
                    )
                    .col(ColumnDef::new(TrustAnchor::Name).text().not_null())
                    .col(ColumnDef::new(TrustAnchor::Type).text().not_null())
                    .col(ColumnDef::new(TrustAnchor::PublisherReference).text())
                    .col(
                        ColumnDef::new(TrustAnchor::IsPublisher)
                            .boolean()
                            .not_null(),
                    )
                    .take(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(TrustEntity::Table)
                    .col(
                        ColumnDef::new(TrustEntity::Id)
                            .char_len(36)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(TrustEntity::CreatedDate)
                            .datetime_millisecond_precision(manager)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(TrustEntity::LastModified)
                            .datetime_millisecond_precision(manager)
                            .not_null(),
                    )
                    .col(ColumnDef::new(TrustEntity::Name).text().not_null())
                    .col(ColumnDef::new(TrustEntity::Logo).large_blob(manager))
                    .col(ColumnDef::new(TrustEntity::Website).text())
                    .col(ColumnDef::new(TrustEntity::TermsUrl).text())
                    .col(ColumnDef::new(TrustEntity::PrivacyUrl).text())
                    .col(
                        ColumnDef::new(TrustEntity::Role)
                            .enumeration(
                                TrustEntityRole::Table,
                                [
                                    TrustEntityRole::Issuer,
                                    TrustEntityRole::Verifier,
                                    TrustEntityRole::Both,
                                ],
                            )
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(TrustEntity::State)
                            .enumeration(
                                TrustEntityState::Table,
                                [
                                    TrustEntityState::Active,
                                    TrustEntityState::Removed,
                                    TrustEntityState::Withdrawn,
                                    TrustEntityState::RemovedAndWithDrawn,
                                ],
                            )
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(TrustEntity::TrustAnchorId)
                            .char_len(36)
                            .not_null(),
                    )
                    .col(ColumnDef::new(TrustEntity::DidId).char_len(36).not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("FK-TrustEntity-TrustAnchorId")
                            .from_tbl(TrustEntity::Table)
                            .from_col(TrustEntity::TrustAnchorId)
                            .to_tbl(TrustAnchor::Table)
                            .to_col(TrustAnchor::Id),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("FK-TrustEntity-DidId")
                            .from_tbl(TrustEntity::Table)
                            .from_col(TrustEntity::DidId)
                            .to_tbl(Did::Table)
                            .to_col(Did::Id),
                    )
                    .take(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name(TRUST_ANCHOR_NAME_UNIQUE_INDEX)
                    .table(TrustAnchor::Table)
                    .col(TrustAnchor::Name)
                    .unique()
                    .take(),
            )
            .await
    }
}

#[derive(DeriveIden)]
pub enum TrustAnchor {
    Table,
    Id,
    CreatedDate,
    LastModified,
    Name,
    Type,
    PublisherReference,
    IsPublisher,
}

#[derive(DeriveIden)]
pub enum TrustEntity {
    Table,
    Id,
    CreatedDate,
    LastModified,
    Name,
    Logo,
    Website,
    TermsUrl,
    PrivacyUrl,
    Role,
    TrustAnchorId,
    State,
    DidId,
}

#[derive(DeriveIden, EnumIter)]
pub enum TrustEntityRole {
    Table,
    #[sea_orm(iden = "ISSUER")]
    Issuer,
    #[sea_orm(iden = "VERIFIER")]
    Verifier,
    #[sea_orm(iden = "BOTH")]
    Both,
}

#[derive(DeriveIden, EnumIter)]
pub enum TrustEntityState {
    Table,
    #[sea_orm(iden = "ACTIVE")]
    Active,
    #[sea_orm(iden = "REMOVED")]
    Removed,
    #[sea_orm(iden = "WITHDRAWN")]
    Withdrawn,
    #[sea_orm(iden = "REMOVED_AND_WITHDRAWN")]
    RemovedAndWithDrawn,
}

#[derive(DeriveIden)]
pub enum Did {
    Table,
    Id,
}
