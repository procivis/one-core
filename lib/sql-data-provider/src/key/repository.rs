use crate::entity::key;
use crate::key::mapper::from_model_and_relations;
use crate::key::KeyProvider;
use crate::list_query::SelectWithListQuery;
use one_core::model::key::{GetKeyList, GetKeyQuery, Key, KeyId, KeyRelations};
use one_core::model::organisation::{Organisation, OrganisationRelations};
use one_core::repository::error::DataLayerError;
use one_core::repository::key_repository::KeyRepository;
use sea_orm::{ActiveModelTrait, EntityTrait, PaginatorTrait, QueryOrder, Set};
use std::str::FromStr;
use uuid::Uuid;

use super::mapper::create_list_response;

impl KeyProvider {
    async fn get_organisation(
        &self,
        key: &key::Model,
        organisation_relations: &Option<OrganisationRelations>,
    ) -> Result<Option<Organisation>, DataLayerError> {
        match &organisation_relations {
            None => Ok(None),
            Some(organisation_relations) => {
                let organisation_id = Uuid::from_str(&key.organisation_id)
                    .map_err(|_| DataLayerError::MappingError)?;
                Ok(Some(
                    self.organisation_repository
                        .get_organisation(&organisation_id, organisation_relations)
                        .await?,
                ))
            }
        }
    }
}

#[async_trait::async_trait]
impl KeyRepository for KeyProvider {
    async fn create_key(&self, request: Key) -> Result<KeyId, DataLayerError> {
        let organisation_id = request
            .organisation
            .ok_or(DataLayerError::MappingError)?
            .id
            .to_string();

        key::ActiveModel {
            id: Set(request.id.to_string()),
            created_date: Set(request.created_date),
            last_modified: Set(request.last_modified),
            name: Set(request.name),
            public_key: Set(request.public_key),
            key_reference: Set(request.key_reference),
            storage_type: Set(request.storage_type),
            key_type: Set(request.key_type),
            organisation_id: Set(organisation_id),
        }
        .insert(&self.db)
        .await
        .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

        Ok(request.id)
    }

    async fn get_key(&self, id: &KeyId, relations: &KeyRelations) -> Result<Key, DataLayerError> {
        let key = key::Entity::find_by_id(id.to_string())
            .one(&self.db)
            .await
            .map_err(|e| {
                tracing::error!("Error while fetching key {}. Error: {}", id, e.to_string());
                DataLayerError::GeneralRuntimeError(e.to_string())
            })?
            .ok_or(DataLayerError::RecordNotFound)?;

        let organisation = self.get_organisation(&key, &relations.organisation).await?;

        from_model_and_relations(key, organisation)
    }
    async fn get_key_list(&self, query_params: GetKeyQuery) -> Result<GetKeyList, DataLayerError> {
        let limit: u64 = query_params.page_size as u64;

        let query = key::Entity::find()
            .with_organisation_id(&query_params, &key::Column::OrganisationId)
            .with_list_query(&query_params, &Some(vec![key::Column::Name]))
            .order_by_desc(key::Column::CreatedDate)
            .order_by_desc(key::Column::Id);

        let items_count = query
            .to_owned()
            .count(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

        let keys: Vec<key::Model> = query
            .all(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

        Ok(create_list_response(keys, limit, items_count))
    }
}
