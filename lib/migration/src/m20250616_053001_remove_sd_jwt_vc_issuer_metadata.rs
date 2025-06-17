use std::collections::HashSet;

use sea_orm::FromQueryResult;
use sea_orm_migration::prelude::*;

use crate::m20240110_000001_initial::Did;
use crate::m20241120_164124_update_trust_anchor_and_entity_tables::TrustEntity;
use crate::m20250608_142503_remove_did_mdl::{
    IdResult, delete_credentials, delete_dids, delete_history_events, delete_identifiers,
    delete_interactions, delete_key_did_relations, delete_proofs, delete_revocation_lists,
    find_dids_with_method, find_identifiers, find_key_ids_for_dids,
};
use crate::m20250611_110354_trust_entity_remove_did_add_org_type_content_entitykey::TrustEntityNew;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let dids = find_dids_with_method(manager, "SD_JWT_VC_ISSUER_METADATA").await?;
        remove_dids_and_related_entities(manager, &dids).await
    }
}

pub(super) async fn remove_dids_and_related_entities(
    manager: &SchemaManager<'_>,
    did_ids: &[String],
) -> Result<(), DbErr> {
    if did_ids.is_empty() {
        return Ok(());
    }

    let db = manager.get_connection();

    let mut ids_to_delete_history: HashSet<String> = HashSet::new();
    ids_to_delete_history.extend(did_ids.to_owned());
    let mut interaction_ids: HashSet<String> = HashSet::new();

    delete_trust_entities(db, did_ids, &mut ids_to_delete_history).await?;

    let identifier_ids = find_identifiers(db, did_ids).await?;
    delete_revocation_lists(db, &identifier_ids).await?;

    let key_ids_of_mdl_dids = find_key_ids_for_dids(db, did_ids).await?;

    delete_proofs(
        db,
        &identifier_ids,
        &key_ids_of_mdl_dids,
        &mut ids_to_delete_history,
        &mut interaction_ids,
    )
    .await?;
    delete_credentials(
        db,
        &identifier_ids,
        &key_ids_of_mdl_dids,
        &mut ids_to_delete_history,
        &mut interaction_ids,
    )
    .await?;
    delete_identifiers(
        db,
        &identifier_ids,
        &key_ids_of_mdl_dids,
        &mut ids_to_delete_history,
    )
    .await?;

    delete_key_did_relations(db, &key_ids_of_mdl_dids).await?;
    delete_dids(db, did_ids).await?;

    delete_interactions(db, &interaction_ids).await?;
    delete_history_events(db, &ids_to_delete_history).await?;

    Ok(())
}

async fn delete_trust_entities(
    db: &SchemaManagerConnection<'_>,
    did_ids: &[String],
    ids_to_delete: &mut HashSet<String>,
) -> Result<(), DbErr> {
    let backend = db.get_database_backend();
    let trust_entity_query = Query::select()
        .column(ColumnRef::TableColumn(
            TrustEntity::Table.into_iden(),
            TrustEntity::Id.into_iden(),
        ))
        .from(TrustEntity::Table)
        .join(
            JoinType::LeftJoin,
            Did::Table,
            Expr::col((TrustEntity::Table, TrustEntityNew::EntityKey))
                .eq(Expr::col((Did::Table, Did::Did))),
        )
        .and_where(Expr::col((Did::Table, Did::Id)).is_in(did_ids))
        .to_owned();

    let trust_entities = IdResult::find_by_statement(backend.build(&trust_entity_query))
        .all(db)
        .await?;

    let trust_entity_ids: Vec<String> = trust_entities.into_iter().map(|te| te.id).collect();
    if trust_entity_ids.is_empty() {
        return Ok(());
    }

    let delete_trust_query = Query::delete()
        .from_table(TrustEntity::Table)
        .and_where(Expr::col(TrustEntity::Id).is_in(&trust_entity_ids))
        .to_owned();

    db.execute(backend.build(&delete_trust_query)).await?;

    ids_to_delete.extend(trust_entity_ids);
    Ok(())
}
