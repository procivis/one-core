use autometrics::autometrics;
use one_core::model::key::{GetKeyList, Key, KeyListQuery, KeyRelations};
use one_core::model::organisation::{Organisation, OrganisationRelations};
use one_core::repository::error::DataLayerError;
use one_core::repository::key_repository::KeyRepository;
use sea_orm::ActiveValue::NotSet;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, Set};
use shared_types::KeyId;

use crate::common::list_query_with_base_model;
use crate::entity::key;
use crate::key::KeyProvider;
use crate::key::mapper::from_model_and_relations;
use crate::list_query_generic::SelectWithListQuery;
use crate::mapper::to_data_layer_error;

impl KeyProvider {
    async fn get_organisation(
        &self,
        key: &key::Model,
        organisation_relations: &Option<OrganisationRelations>,
    ) -> Result<Option<Organisation>, DataLayerError> {
        match &organisation_relations {
            None => Ok(None),
            Some(organisation_relations) => Ok(Some(
                self.organisation_repository
                    .get_organisation(&key.organisation_id, organisation_relations)
                    .await?
                    .ok_or(DataLayerError::MissingRequiredRelation {
                        relation: "key-organisation",
                        id: key.organisation_id.to_string(),
                    })?,
            )),
        }
    }
}

#[autometrics]
#[async_trait::async_trait]
impl KeyRepository for KeyProvider {
    async fn create_key(&self, request: Key) -> Result<KeyId, DataLayerError> {
        let organisation_id = request.organisation.ok_or(DataLayerError::MappingError)?.id;

        key::ActiveModel {
            id: Set(request.id),
            created_date: Set(request.created_date),
            last_modified: Set(request.last_modified),
            name: Set(request.name),
            public_key: Set(request.public_key),
            key_reference: Set(request.key_reference),
            storage_type: Set(request.storage_type),
            key_type: Set(request.key_type),
            organisation_id: Set(organisation_id),
            deleted_at: NotSet,
        }
        .insert(&self.db)
        .await
        .map_err(to_data_layer_error)?;

        Ok(request.id)
    }

    async fn get_key(
        &self,
        id: &KeyId,
        relations: &KeyRelations,
    ) -> Result<Option<Key>, DataLayerError> {
        let key = key::Entity::find_by_id(*id)
            .filter(key::Column::DeletedAt.is_null())
            .one(&self.db)
            .await
            .map_err(|e| {
                tracing::error!("Error while fetching key {}. Error: {}", id, e.to_string());
                DataLayerError::Db(e.into())
            })?;

        let Some(key) = key else {
            return Ok(None);
        };

        let organisation = self.get_organisation(&key, &relations.organisation).await?;

        let key = from_model_and_relations(key, organisation);

        Ok(Some(key))
    }

    async fn get_keys(&self, ids: &[KeyId]) -> Result<Vec<Key>, DataLayerError> {
        let keys = key::Entity::find()
            .filter(key::Column::DeletedAt.is_null())
            .filter(key::Column::Id.is_in(ids.iter().map(ToString::to_string)))
            .all(&self.db)
            .await
            .map_err(|e| {
                tracing::error!("Error while fetching keys. Error: {}", e.to_string());
                DataLayerError::Db(e.into())
            })?;

        Ok(keys
            .into_iter()
            .map(|key| from_model_and_relations(key, None))
            .collect())
    }

    async fn get_key_list(&self, query_params: KeyListQuery) -> Result<GetKeyList, DataLayerError> {
        let query = key::Entity::find()
            .filter(key::Column::DeletedAt.is_null())
            .with_list_query(&query_params)
            .order_by_desc(key::Column::CreatedDate)
            .order_by_desc(key::Column::Id);

        list_query_with_base_model(query, query_params, &self.db).await
    }
}
