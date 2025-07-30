use std::collections::HashSet;

use sea_orm::FromQueryResult;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(Debug, FromQueryResult)]
pub struct TrustEntityResult {
    id: String,
    did_id: String,
    trust_anchor_id: String,
}

#[derive(Debug, DeriveIden)]
pub enum TrustEntity {
    Table,
    Id,
    CreatedDate,
    DidId,
    TrustAnchorId,
}

pub const UNIQUE_DID_ID_TRUST_ANCHOR_ID_IN_TRUST_ENTITY: &str =
    "index-TrustEntity-DidId-TrustAnchorId-Unique";

#[derive(Debug, Eq, Hash, PartialEq)]
struct DidTrustAnchorCombo {
    did_id: String,
    trust_anchor_id: String,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == sea_orm::DatabaseBackend::Postgres {
            // Skip because it is not supported. If support for Postgres is added in the future
            // the schema can be setup in its entirety in a new, later migration.
            return Ok(());
        }
        let db = manager.get_connection();
        let backend = db.get_database_backend();

        let mut id_combinations = HashSet::new();

        let trust_entities = TrustEntityResult::find_by_statement(
            backend.build(
                Query::select()
                    .columns([
                        TrustEntity::Id,
                        TrustEntity::DidId,
                        TrustEntity::TrustAnchorId,
                    ])
                    .from(TrustEntity::Table)
                    .order_by(TrustEntity::CreatedDate, Order::Asc),
            ),
        )
        .all(db)
        .await?;

        let mut ids_to_delete = HashSet::new();
        for trust_entity in trust_entities {
            let already_exists = id_combinations.insert(DidTrustAnchorCombo {
                did_id: trust_entity.did_id,
                trust_anchor_id: trust_entity.trust_anchor_id,
            });
            if !already_exists {
                ids_to_delete.insert(trust_entity.id);
            }
        }

        if !ids_to_delete.is_empty() {
            let query = Query::delete()
                .from_table(TrustEntity::Table)
                .and_where(Expr::col(TrustEntity::Id).is_in(ids_to_delete))
                .to_owned();
            manager.exec_stmt(query).await?;
        }

        manager
            .create_index(
                Index::create()
                    .name(UNIQUE_DID_ID_TRUST_ANCHOR_ID_IN_TRUST_ENTITY)
                    .unique()
                    .table(TrustEntity::Table)
                    .col(TrustEntity::DidId)
                    .col(TrustEntity::TrustAnchorId)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
