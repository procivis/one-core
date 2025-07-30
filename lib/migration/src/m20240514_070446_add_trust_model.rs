use sea_orm::{EnumIter, Iterable};
use sea_orm_migration::prelude::*;

use crate::datatype::ColumnDefExt;
use crate::m20240110_000001_initial::Organisation;
use crate::m20240130_105023_add_history::{History, HistoryAction};

const UNIQUE_TRUST_ANCHOR_NAME_IN_ORGANISATION_INDEX: &str =
    "index-TrustAnchor-Name-OrganisationId-Unique";
const UNIQUE_TRUST_ENTITY_ENTITY_ID_IN_ANCHOR: &str =
    "index-TrustEntity-EntityId-TrustAnchorId-Unique";

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            // Skip because it is not supported. If support for Postgres is added in the future
            // the schema can be setup in its entirety in a new, later migration.
            sea_orm::DatabaseBackend::Postgres => return Ok(()),
            sea_orm::DatabaseBackend::MySql => {
                manager
                    .alter_table(
                        Table::alter()
                            .table(History::Table)
                            .modify_column(ColumnDef::new(History::EntityType).enumeration(
                                HistoryAction::Table,
                                UpdatedHistoryEntityType::iter(),
                            ))
                            .to_owned(),
                    )
                    .await?;
            }
            sea_orm::DatabaseBackend::Sqlite => {}
        };

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
                    .col(ColumnDef::new(TrustAnchor::Name).string().not_null())
                    .col(ColumnDef::new(TrustAnchor::Type).string().not_null())
                    .col(
                        ColumnDef::new(TrustAnchor::PublisherReference)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(TrustAnchor::Role)
                            .enumeration(
                                TrustAnchorRole::Table,
                                [TrustAnchorRole::Client, TrustAnchorRole::Publisher],
                            )
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(TrustAnchor::Priority)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(TrustAnchor::OrganisationId)
                            .char_len(36)
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-TrustAnchor-OrganisationId")
                            .from_tbl(TrustAnchor::Table)
                            .from_col(TrustAnchor::OrganisationId)
                            .to_tbl(Organisation::Table)
                            .to_col(Organisation::Id),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name(UNIQUE_TRUST_ANCHOR_NAME_IN_ORGANISATION_INDEX)
                    .table(TrustAnchor::Table)
                    .col(TrustAnchor::Name)
                    .col(TrustAnchor::OrganisationId)
                    .unique()
                    .to_owned(),
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
                    .col(ColumnDef::new(TrustEntity::EntityId).string().not_null())
                    .col(ColumnDef::new(TrustEntity::Name).string().not_null())
                    .col(ColumnDef::new(TrustEntity::Logo).string())
                    .col(ColumnDef::new(TrustEntity::Website).string())
                    .col(ColumnDef::new(TrustEntity::TermsUrl).string())
                    .col(ColumnDef::new(TrustEntity::PrivacyUrl).string())
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
                        ColumnDef::new(TrustEntity::TrustAnchorId)
                            .char_len(36)
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-TrustEntity-TrustAnchorId")
                            .from_tbl(TrustEntity::Table)
                            .from_col(TrustEntity::TrustAnchorId)
                            .to_tbl(TrustAnchor::Table)
                            .to_col(TrustAnchor::Id),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name(UNIQUE_TRUST_ENTITY_ENTITY_ID_IN_ANCHOR)
                    .table(TrustEntity::Table)
                    .col(TrustEntity::EntityId)
                    .col(TrustEntity::TrustAnchorId)
                    .unique()
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(Iden, EnumIter)]
enum UpdatedHistoryEntityType {
    #[iden = "KEY"]
    Key,
    #[iden = "DID"]
    Did,
    #[iden = "CREDENTIAL"]
    Credential,
    #[iden = "CREDENTIAL_SCHEMA"]
    CredentialSchema,
    #[iden = "PROOF"]
    Proof,
    #[iden = "PROOF_SCHEMA"]
    ProofSchema,
    #[iden = "ORGANISATION"]
    Organisation,
    #[iden = "BACKUP"]
    Backup,
    #[iden = "TRUST_ANCHOR"]
    TrustAnchor,
    #[iden = "TRUST_ENTITY"]
    TrustEntity,
}

#[derive(Iden)]
pub enum TrustAnchor {
    Table,
    Id,
    CreatedDate,
    LastModified,
    Name,
    Type,
    PublisherReference,
    Role,
    Priority,
    OrganisationId,
}

#[derive(Iden, EnumIter)]
pub enum TrustAnchorRole {
    Table,
    #[iden = "CLIENT"]
    Client,
    #[iden = "PUBLISHER"]
    Publisher,
}

#[derive(Iden)]
pub enum TrustEntity {
    Table,
    Id,
    CreatedDate,
    LastModified,
    EntityId,
    Name,
    Logo,
    Website,
    TermsUrl,
    PrivacyUrl,
    Role,
    TrustAnchorId,
}

#[derive(Iden, EnumIter)]
pub enum TrustEntityRole {
    Table,
    #[iden = "ISSUER"]
    Issuer,
    #[iden = "VERIFIER"]
    Verifier,
    #[iden = "BOTH"]
    Both,
}
