use sea_orm_migration::prelude::*;

use crate::m20241120_164124_update_trust_anchor_and_entity_tables::{TrustAnchor, TrustEntity};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == sea_orm::DatabaseBackend::Postgres {
            // Skip because it is not supported. If support for Postgres is added in the future
            // the schema can be setup in its entirety in a new, later migration.
            return Ok(());
        }
        let db = manager.get_connection();
        let db_backend = manager.get_database_backend();

        db.execute(db_backend.build(Query::delete().from_table(TrustEntity::Table)))
            .await?;
        db.execute(db_backend.build(Query::delete().from_table(TrustAnchor::Table)))
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(TrustAnchor::Table)
                    .drop_column(TrustAnchor::PublisherReference)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(TrustAnchor::Table)
                    .add_column(
                        ColumnDef::new(TrustAnchor::PublisherReference)
                            .text()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await
    }
}
