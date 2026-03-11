use autometrics::autometrics;
use one_core::model::trust_entry::{
    GetTrustEntryList, TrustEntry, TrustEntryListQuery, TrustEntryRelations,
    UpdateTrustEntryRequest,
};
use one_core::repository::error::DataLayerError;
use one_core::repository::trust_entry_repository::TrustEntryRepository;
use one_dto_mapper::convert_inner;
use sea_orm::ActiveValue::{Set, Unchanged};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder,
    QuerySelect, RelationTrait,
};
use shared_types::{TrustEntryId, TrustListPublicationId};
use time::OffsetDateTime;

use super::TrustEntryProvider;
use crate::common::calculate_pages_count;
use crate::entity::{identifier, trust_entry};
use crate::list_query_generic::SelectWithListQuery;
use crate::mapper::{to_data_layer_error, to_update_data_layer_error};
use crate::trust_entry::entities::TrustEntryWithIdentifier;

#[autometrics]
#[async_trait::async_trait]
impl TrustEntryRepository for TrustEntryProvider {
    async fn create(&self, entity: TrustEntry) -> Result<TrustEntryId, DataLayerError> {
        let id = entity.id;
        let model: trust_entry::ActiveModel = entity.into();
        model.insert(&self.db).await.map_err(to_data_layer_error)?;
        Ok(id)
    }

    async fn get(
        &self,
        id: TrustEntryId,
        relations: &TrustEntryRelations,
    ) -> Result<Option<TrustEntry>, DataLayerError> {
        let entity_model = trust_entry::Entity::find_by_id(id)
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        let Some(entity_model) = entity_model else {
            return Ok(None);
        };

        let trust_list_publication_id = entity_model.trust_list_publication_id;
        let identifier_id = entity_model.identifier_id;

        let mut result = TrustEntry::from(entity_model);

        if let Some(publication_relations) = &relations.trust_list_publication {
            result.trust_list_publication = Some(
                self.trust_list_publication_repository
                    .get(trust_list_publication_id, publication_relations)
                    .await?
                    .ok_or(DataLayerError::MissingRequiredRelation {
                        relation: "trust_entry-trust_list_publication",
                        id: trust_list_publication_id.to_string(),
                    })?,
            );
        }

        if let Some(identifier_relations) = &relations.identifier {
            result.identifier = Some(
                self.identifier_repository
                    .get(identifier_id, identifier_relations)
                    .await?
                    .ok_or(DataLayerError::MissingRequiredRelation {
                        relation: "trust_entry-identifier",
                        id: identifier_id.to_string(),
                    })?,
            );
        }

        Ok(Some(result))
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
                trust_entry::Column::Status,
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
            // list query
            .filter(trust_entry::Column::TrustListPublicationId.eq(trust_list_publication_id))
            .with_list_query(&query)
            .order_by_desc(trust_entry::Column::CreatedDate)
            .order_by_desc(trust_entry::Column::Id);

        let (items_count, trust_entries) = tokio::join!(
            query.to_owned().count(&self.db),
            query.into_model::<TrustEntryWithIdentifier>().all(&self.db),
        );

        let items_count = items_count.map_err(to_data_layer_error)?;
        let trust_entries = trust_entries.map_err(to_data_layer_error)?;

        Ok(GetTrustEntryList {
            values: convert_inner(trust_entries),
            total_pages: calculate_pages_count(items_count, limit.unwrap_or(0)),
            total_items: items_count,
        })
    }

    async fn update(
        &self,
        id: TrustEntryId,
        request: UpdateTrustEntryRequest,
    ) -> Result<(), DataLayerError> {
        let status = match request.status {
            None => Unchanged(trust_entry::TrustEntryStatus::Active),
            Some(status) => Set(status.into()),
        };

        let metadata = match request.metadata {
            None => Unchanged(Default::default()),
            Some(metadata) => Set(metadata),
        };

        trust_entry::ActiveModel {
            id: Unchanged(id),
            last_modified: Set(OffsetDateTime::now_utc()),
            status,
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
