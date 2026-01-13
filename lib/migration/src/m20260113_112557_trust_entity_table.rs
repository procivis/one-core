use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::*;

use crate::datatype::{timestamp, timestamp_null, uuid_char, uuid_char_null};
use crate::m20240110_000001_initial::Organisation;
use crate::m20240514_070446_add_trust_model::TrustAnchor;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DatabaseBackend::Postgres | DatabaseBackend::MySql => {}
            DatabaseBackend::Sqlite => sqlite_migration(manager).await?,
        };

        Ok(())
    }
}

#[derive(Iden)]
enum TrustEntityNew {
    Table,
}

#[derive(Clone, Iden)]
enum TrustEntity {
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
    State,
    TrustAnchorId,
    OrganisationId,
    Type,
    EntityKey,
    Content,
    DeactivatedAt,
}

async fn sqlite_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let db = manager.get_connection();

    db.execute_unprepared("PRAGMA defer_foreign_keys = ON;")
        .await?;

    // Create new table with the correct columns
    manager
        .create_table(
            Table::create()
                .table(TrustEntityNew::Table)
                .col(uuid_char(TrustEntity::Id).primary_key())
                .col(timestamp(TrustEntity::CreatedDate, manager))
                .col(timestamp(TrustEntity::LastModified, manager))
                .col(text(TrustEntity::Name))
                .col(blob_null(TrustEntity::Logo))
                .col(text_null(TrustEntity::Website))
                .col(text_null(TrustEntity::TermsUrl))
                .col(text_null(TrustEntity::PrivacyUrl))
                .col(string(TrustEntity::Role))
                .col(string(TrustEntity::State))
                .col(uuid_char(TrustEntity::TrustAnchorId))
                .col(uuid_char_null(TrustEntity::OrganisationId))
                .col(string(TrustEntity::Type))
                .col(string_len(TrustEntity::EntityKey, 4000))
                .col(blob_null(TrustEntity::Content))
                .col(timestamp_null(TrustEntity::DeactivatedAt, manager))
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
                        .from_col(TrustEntity::OrganisationId)
                        .to_tbl(Organisation::Table)
                        .to_col(Organisation::Id),
                )
                .to_owned(),
        )
        .await?;

    // Copy data from old table to new table
    let copied_columns = vec![
        TrustEntity::Id,
        TrustEntity::CreatedDate,
        TrustEntity::LastModified,
        TrustEntity::Name,
        TrustEntity::Logo,
        TrustEntity::Website,
        TrustEntity::TermsUrl,
        TrustEntity::PrivacyUrl,
        TrustEntity::Role,
        TrustEntity::State,
        TrustEntity::TrustAnchorId,
        TrustEntity::OrganisationId,
        TrustEntity::Type,
        TrustEntity::EntityKey,
        TrustEntity::Content,
        TrustEntity::DeactivatedAt,
    ];
    manager
        .exec_stmt(
            Query::insert()
                .into_table(TrustEntityNew::Table)
                .columns(copied_columns.to_vec())
                .select_from(
                    Query::select()
                        .from(TrustEntity::Table)
                        .columns(copied_columns)
                        .to_owned(),
                )
                .map_err(|e| DbErr::Migration(e.to_string()))?
                .to_owned(),
        )
        .await?;

    // Drop old table & rename new table
    manager
        .drop_table(Table::drop().table(TrustEntity::Table).to_owned())
        .await?;

    manager
        .rename_table(
            Table::rename()
                .table(TrustEntityNew::Table, TrustEntity::Table)
                .to_owned(),
        )
        .await?;

    // Recreate indexes
    manager.get_connection().execute_unprepared(
        "CREATE UNIQUE INDEX `idx-TrustEntity-Name-OrganisationId-DeactivatedAt-Unique` ON `trust_entity`(`name`, `organisation_id`, COALESCE(deactivated_at, 'not_deactivated'));"
    ).await?;

    manager.get_connection().execute_unprepared(
        "CREATE UNIQUE INDEX `idx-TrustEntity-EntityKey-AnchorId-DeactivatedAt-Unique` ON `trust_entity`(`entity_key`, `trust_anchor_id`, COALESCE(deactivated_at, 'not_deactivated'));"
    ).await?;

    db.execute_unprepared("PRAGMA defer_foreign_keys = OFF;")
        .await?;

    Ok(())
}
