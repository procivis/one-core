use std::collections::HashMap;

use one_core::model::localized_text::LocalizedText;
use one_core::model::relation::{AsyncBatchLoader, BatchModelLoader, RelatedVec};
use one_core::repository::error::DataLayerError;
use sea_orm::sea_query::UnionType;
use sea_orm::{ColumnTrait, Condition, EntityTrait, Order, QueryFilter, QueryTrait, Select};
use shared_types::EntityId;

use crate::entity::localized_text;
use crate::mapper::to_data_layer_error;
use crate::transaction_context::TransactionManagerImpl;

mod mapper;
mod repository;
#[cfg(test)]
mod test;

pub(crate) struct LocalizedTextProvider {
    pub db: TransactionManagerImpl,
}

pub(crate) struct LocalizedTextLoader {
    pub db: TransactionManagerImpl,
}

#[async_trait::async_trait]
impl AsyncBatchLoader<EntityId, Vec<LocalizedText>> for LocalizedTextLoader {
    async fn load(
        &self,
        ids: &[EntityId],
    ) -> Result<HashMap<EntityId, Vec<LocalizedText>>, DataLayerError> {
        load_localized_texts(
            [Condition::all().add(localized_text::Column::EntityId.is_in(ids))],
            &self.db,
        )
        .await
    }
}

/// Translations matching any of `conditions`, grouped by entity
///
/// The conditions must not match the same rows: they are combined with `UNION ALL`, which does not
/// deduplicate, so a translation matching several conditions would be returned multiple times.
pub(crate) async fn load_localized_texts(
    conditions: impl IntoIterator<Item = Condition>,
    db: &TransactionManagerImpl,
) -> Result<HashMap<EntityId, Vec<LocalizedText>>, DataLayerError> {
    let Some(select) = localized_texts_query(conditions) else {
        return Ok(HashMap::new());
    };
    let translations: Vec<localized_text::Model> =
        select.all(db).await.map_err(to_data_layer_error)?;

    let mut by_entity: HashMap<_, Vec<_>> = HashMap::new();
    for translation in translations {
        by_entity
            .entry(translation.entity_id)
            .or_default()
            .push(translation.into());
    }
    Ok(by_entity)
}

/// The conditions are combined with `UNION ALL` instead of `OR`: MariaDB and Postgres scan the
/// whole table for an `OR` involving an `IN (subquery)`, while each `UNION ALL` part uses an index.
///
/// E.g. the translations of a credential schema and its claim schemas on MariaDB (column list
/// shortened to `...`):
/// ```sql
/// SELECT `localized_text`.`entity_id`, ... FROM `localized_text`
///   WHERE `localized_text`.`entity_id` IN (
///     SELECT `id` FROM `claim_schema` WHERE `claim_schema`.`credential_schema_id` IN (?)
///   )
/// UNION ALL (
///   SELECT `localized_text`.`entity_id`, ... FROM `localized_text`
///     WHERE `localized_text`.`entity_id` IN (?)
/// )
/// ORDER BY `lang` ASC, `field` ASC
/// ```
fn localized_texts_query(
    conditions: impl IntoIterator<Item = Condition>,
) -> Option<Select<localized_text::Entity>> {
    let mut selects = conditions
        .into_iter()
        .map(|condition| localized_text::Entity::find().filter(condition));
    let mut select = selects.next()?;
    for other in selects {
        QueryTrait::query(&mut select).union(UnionType::All, other.into_query());
    }
    // unqualified columns, as the order applies to the result of the union
    QueryTrait::query(&mut select)
        .order_by(localized_text::Column::Lang, Order::Asc)
        .order_by(localized_text::Column::Field, Order::Asc);
    Some(select)
}

pub(crate) fn localized_texts(
    id: EntityId,
    db: TransactionManagerImpl,
) -> RelatedVec<LocalizedText> {
    RelatedVec::new(BatchModelLoader::new([id], LocalizedTextLoader { db }).list(id))
}
