use sea_orm::DbBackend;
use sea_orm_migration::prelude::*;

use crate::datatype::ColumnDefExt;
use crate::m20240110_000001_initial::Organisation;
use crate::m20241120_164124_update_trust_anchor_and_entity_tables::{TrustAnchor, TrustEntity};
use crate::m20250113_115815_trust_entity_unique_did::UNIQUE_DID_ID_TRUST_ANCHOR_ID_IN_TRUST_ENTITY;

pub const UNIQUE_ENTITY_KEY_STATE_TRUST_ANCHOR_DEACTIVATED_IN_TRUST_ENTITY: &str =
    "idx-EntityKey-AnchorId-State-DeactivatedAt-Unique";
pub const UNIQUE_NAME_TRUST_ANCHOR_ID_ORGANISATION_ID_IN_TRUST_ENTITY: &str =
    "idx-Name-TrustAnchorId-OrganisationId-Unique";

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DbBackend::Sqlite => sqlite_migration(manager).await,
            _ => migration(manager).await,
        }
    }
}

async fn migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .alter_table(
            Table::alter()
                .table(TrustEntity::Table)
                .add_column(
                    ColumnDef::new(TrustEntityNew::OrganisationId)
                        .char_len(36)
                        .null(),
                )
                .add_column(ColumnDef::new(TrustEntityNew::Type).string().null())
                .add_column(
                    ColumnDef::new(TrustEntityNew::EntityKey)
                        .text()
                        .string_len(4000) // did values can be large
                        .null(),
                )
                .add_column(
                    ColumnDef::new(TrustEntityNew::Content)
                        .large_blob(manager)
                        .null(),
                )
                .add_column(
                    ColumnDef::new(TrustEntityNew::DeactivatedAt)
                        .datetime_millisecond_precision(manager)
                        .null(),
                )
                .add_foreign_key(
                    ForeignKey::create()
                        .name("FK-TrustEntity-OrganisationId")
                        .from_tbl(TrustEntity::Table)
                        .from_col(TrustEntityNew::OrganisationId)
                        .to_tbl(Organisation::Table)
                        .to_col(Organisation::Id)
                        .get_foreign_key(),
                )
                .to_owned(),
        )
        .await?;

    let db = manager.get_connection();
    db.execute_unprepared(
        r#"
                UPDATE trust_entity, did
                SET
                    trust_entity.organisation_id = did.organisation_id,
                    trust_entity.entity_key = did.did,
                    trust_entity.type = 'DID'
                WHERE
                    trust_entity.did_id = did.id;
                "#,
    )
    .await?;

    manager
        .alter_table(
            Table::alter()
                .table(TrustEntity::Table)
                .drop_foreign_key(Alias::new("FK-TrustEntity-DidId"))
                .modify_column(ColumnDef::new(TrustEntityNew::Type).string().not_null())
                .modify_column(
                    ColumnDef::new(TrustEntityNew::EntityKey)
                        .text()
                        .string_len(4000) // did values can be large
                        .not_null(),
                )
                .to_owned(),
        )
        .await?;

    manager
        .drop_index(
            Index::drop()
                .name(UNIQUE_DID_ID_TRUST_ANCHOR_ID_IN_TRUST_ENTITY)
                .table(TrustEntity::Table)
                .to_owned(),
        )
        .await?;

    manager
        .alter_table(
            Table::alter()
                .table(TrustEntity::Table)
                .drop_column(TrustEntity::DidId)
                .to_owned(),
        )
        .await?;

    let add_generated_column_deactivated_at = "ALTER TABLE trust_entity ADD COLUMN deactivated_at_materialized VARCHAR(50) AS (COALESCE(deactivated_at, 'not_deactivated')) PERSISTENT;".to_string();
    db.execute_unprepared(&add_generated_column_deactivated_at)
        .await?;

    let add_generated_column_org_id = "ALTER TABLE trust_entity ADD COLUMN organisation_id_materialized VARCHAR(50) AS (COALESCE(TRIM(organisation_id), 'no_organisation')) PERSISTENT;".to_string();
    db.execute_unprepared(&add_generated_column_org_id).await?;

    let create_unique_index_entity_key = format!(
        "CREATE UNIQUE INDEX `{UNIQUE_ENTITY_KEY_STATE_TRUST_ANCHOR_DEACTIVATED_IN_TRUST_ENTITY}` ON trust_entity(`entity_key`, `trust_anchor_id`, `state`, `deactivated_at_materialized`);"
    );
    db.execute_unprepared(&create_unique_index_entity_key)
        .await?;

    let create_unique_index_name = format!(
        "CREATE UNIQUE INDEX `{UNIQUE_NAME_TRUST_ANCHOR_ID_ORGANISATION_ID_IN_TRUST_ENTITY}` ON trust_entity(`name`, `trust_anchor_id`, `organisation_id_materialized`);"
    );
    db.execute_unprepared(&create_unique_index_name).await?;
    Ok(())
}

async fn sqlite_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let db = manager.get_connection();
    // Disable foreign keys for SQLite
    db.execute_unprepared("PRAGMA defer_foreign_keys = ON;")
        .await?;

    // table can simply be dropped as it is empty on mobile apps anyway
    manager
        .drop_table(Table::drop().table(TrustEntity::Table).to_owned())
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
                .col(ColumnDef::new(TrustEntity::Role).string().not_null())
                .col(ColumnDef::new(TrustEntity::State).string().not_null())
                .col(
                    ColumnDef::new(TrustEntity::TrustAnchorId)
                        .char_len(36)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(TrustEntityNew::OrganisationId)
                        .char_len(36)
                        .null(),
                )
                .col(ColumnDef::new(TrustEntityNew::Type).string().null())
                .col(
                    ColumnDef::new(TrustEntityNew::EntityKey)
                        .text()
                        .string_len(4000) // did values can be large
                        .null(),
                )
                .col(
                    ColumnDef::new(TrustEntityNew::Content)
                        .large_blob(manager)
                        .null(),
                )
                .col(
                    ColumnDef::new(TrustEntityNew::DeactivatedAt)
                        .datetime_millisecond_precision(manager)
                        .null(),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("FK-TrustEntity-TrustAnchorId")
                        .from_tbl(TrustEntityNew::Table)
                        .from_col(TrustEntity::TrustAnchorId)
                        .to_tbl(TrustAnchor::Table)
                        .to_col(TrustAnchor::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("FK-TrustEntity-OrganisationId")
                        .from_tbl(TrustEntityNew::Table)
                        .from_col(TrustEntityNew::OrganisationId)
                        .to_tbl(Organisation::Table)
                        .to_col(Organisation::Id),
                )
                .take(),
        )
        .await?;

    let create_unique_index_entity_key = format!(
        "CREATE UNIQUE INDEX `{UNIQUE_ENTITY_KEY_STATE_TRUST_ANCHOR_DEACTIVATED_IN_TRUST_ENTITY}` ON trust_entity(`entity_key`, `trust_anchor_id`, `state`, COALESCE(deactivated_at, 'not_deactivated'));"
    );
    db.execute_unprepared(&create_unique_index_entity_key)
        .await?;

    let create_unique_index_name = format!(
        "CREATE UNIQUE INDEX `{UNIQUE_NAME_TRUST_ANCHOR_ID_ORGANISATION_ID_IN_TRUST_ENTITY}` ON trust_entity(`name`, `trust_anchor_id`, COALESCE(organisation_id, 'no_organisation'));"
    );
    db.execute_unprepared(&create_unique_index_name).await?;

    // Enable foreign keys for SQLite
    db.execute_unprepared("PRAGMA defer_foreign_keys = OFF;")
        .await?;

    Ok(())
}

#[derive(DeriveIden)]
enum TrustEntityNew {
    Table,
    Content,
    Type,
    EntityKey,
    OrganisationId,
    DeactivatedAt,
}
