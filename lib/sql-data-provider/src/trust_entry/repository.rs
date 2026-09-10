use autometrics::autometrics;
use one_core::model::trust_entry::{
    GetTrustEntryList, TrustEntry, TrustEntryListQuery, UpdateTrustEntryRequest,
};
use one_core::repository::error::{DataLayerError, EntityKind};
use one_core::repository::trust_entry_repository::TrustEntryRepository;
use sea_orm::ActiveValue::{Set, Unchanged};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, PaginatorTrait, QueryFilter,
    QueryOrder, QuerySelect, RelationTrait,
};
use shared_types::{TrustEntryId, TrustListPublicationId};

use super::TrustEntryProvider;
use super::entities::{TrustEntryWithIdentifier, trust_entry_from_model_with_identifier};
use super::mapper::trust_entry_from_model;
use crate::common::calculate_pages_count;
use crate::entity::{identifier, trust_entry};
use crate::list_query_generic::SelectWithListQuery;
use crate::mapper::{to_data_layer_error, to_update_data_layer_error};

#[autometrics]
#[async_trait::async_trait]
impl TrustEntryRepository for TrustEntryProvider {
    async fn create(&self, entity: TrustEntry) -> Result<TrustEntryId, DataLayerError> {
        let id = entity.id;
        let model: trust_entry::ActiveModel = entity.into();
        model.insert(&self.db).await.map_err(to_data_layer_error)?;
        Ok(id)
    }

    async fn get(&self, id: TrustEntryId) -> Result<TrustEntry, DataLayerError> {
        let entity_model = trust_entry::Entity::find_by_id(id)
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?
            .ok_or_else(|| DataLayerError::EntityNotFound {
                kind: EntityKind::TrustEntry,
                id: id.into(),
            })?;

        Ok(trust_entry_from_model(
            entity_model,
            &self.identifier_repository,
            &self.trust_list_publication_repository,
        ))
    }

    async fn list(
        &self,
        trust_list_publication_id: TrustListPublicationId,
        query: TrustEntryListQuery,
    ) -> Result<GetTrustEntryList, DataLayerError> {
        let limit = query
            .pagination
            .as_ref()
            .map(|pagination| pagination.page_size as _);

        let query = trust_entry::Entity::find()
            .select_only()
            .columns([
                trust_entry::Column::Id,
                trust_entry::Column::CreatedDate,
                trust_entry::Column::LastModified,
                trust_entry::Column::State,
                trust_entry::Column::Metadata,
                trust_entry::Column::TrustListPublicationId,
            ])
            .join(
                sea_orm::JoinType::LeftJoin,
                trust_entry::Relation::Identifier.def(),
            )
            .column_as(identifier::Column::Id, "identifier_id")
            .column_as(identifier::Column::CreatedDate, "identifier_created_date")
            .column_as(identifier::Column::LastModified, "identifier_last_modified")
            .column_as(identifier::Column::Name, "identifier_name")
            .column_as(identifier::Column::Type, "identifier_type")
            .column_as(identifier::Column::IsRemote, "identifier_is_remote")
            .column_as(identifier::Column::State, "identifier_state")
            .column_as(
                identifier::Column::OrganisationId,
                "identifier_organisation_id",
            )
            .column_as(identifier::Column::DidId, "identifier_did_id")
            .column_as(identifier::Column::KeyId, "identifier_key_id")
            // list query
            .filter(trust_entry::Column::TrustListPublicationId.eq(trust_list_publication_id))
            .with_list_query(&query, self.db.get_database_backend())
            .order_by_desc(trust_entry::Column::CreatedDate)
            .order_by_desc(trust_entry::Column::Id);

        let (items_count, trust_entries) = tokio::join!(
            query.to_owned().count(&self.db),
            query.into_model::<TrustEntryWithIdentifier>().all(&self.db),
        );

        let items_count = items_count.map_err(to_data_layer_error)?;
        let trust_entries = trust_entries.map_err(to_data_layer_error)?;

        Ok(GetTrustEntryList {
            values: trust_entries
                .into_iter()
                .map(|trust_entry| {
                    trust_entry_from_model_with_identifier(
                        trust_entry,
                        &self.organisation_repository,
                        &self.did_repository,
                        &self.key_repository,
                        &self.certificate_repository,
                        &self.trust_list_publication_repository,
                        &self.trust_information_repository,
                        &self.localized_text_repository,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?,
            total_pages: calculate_pages_count(items_count, limit.unwrap_or(0)),
            total_items: items_count,
        })
    }

    async fn update(
        &self,
        id: TrustEntryId,
        request: UpdateTrustEntryRequest,
    ) -> Result<(), DataLayerError> {
        let state = match request.state {
            None => Unchanged(trust_entry::TrustEntryState::Active),
            Some(state) => Set(state.into()),
        };

        let metadata = match request.metadata {
            None => Unchanged(Default::default()),
            Some(metadata) => Set(metadata),
        };

        trust_entry::ActiveModel {
            id: Unchanged(id),
            last_modified: Set(one_core::clock::now_utc()),
            state,
            metadata,
            ..Default::default()
        }
        .update(&self.db)
        .await
        .map_err(to_update_data_layer_error)?;

        Ok(())
    }

    async fn delete(&self, id: TrustEntryId) -> Result<(), DataLayerError> {
        trust_entry::Entity::delete_by_id(id)
            .exec(&self.db)
            .await
            .map_err(to_data_layer_error)?;
        Ok(())
    }
}
