use autometrics::autometrics;
use one_core::model::trust_entry::{
    GetTrustEntryList, TrustEntry, TrustEntryListQuery, TrustEntryRelations,
    UpdateTrustEntryRequest,
};
use one_core::repository::error::DataLayerError;
use one_core::repository::trust_entry_repository::TrustEntryRepository;
use sea_orm::ActiveValue::{Set, Unchanged};
use sea_orm::{ActiveModelTrait, EntityTrait, QueryOrder};
use shared_types::TrustEntryId;
use time::OffsetDateTime;

use super::TrustEntryProvider;
use crate::common::list_query_with_base_model;
use crate::entity::trust_entry;
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

        if let Some(identifier_id) = identifier_id
            && let Some(identifier_relations) = &relations.identifier
        {
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

    async fn list(&self, query: TrustEntryListQuery) -> Result<GetTrustEntryList, DataLayerError> {
        let db_query = trust_entry::Entity::find()
            .with_list_query(&query)
            .order_by_desc(trust_entry::Column::CreatedDate)
            .order_by_desc(trust_entry::Column::Id);

        list_query_with_base_model(db_query, query, &self.db).await
    }

    async fn update(
        &self,
        id: TrustEntryId,
        request: UpdateTrustEntryRequest,
    ) -> Result<(), DataLayerError> {
        let status = match request.status {
            None => Unchanged(trust_entry::TrustEntryState::Active),
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
