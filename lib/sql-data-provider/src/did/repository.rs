use std::{collections::HashMap, str::FromStr};

use autometrics::autometrics;
use one_core::model::{
    did::{Did, DidListQuery, DidRelations, GetDidList, RelatedKey, UpdateDidRequest},
    key::{Key, KeyId},
};
use one_core::repository::{did_repository::DidRepository, error::DataLayerError};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, Set,
    Unchanged,
};
use shared_types::{DidId, DidValue};
use uuid::Uuid;

use super::{mapper::create_list_response, DidProvider};
use crate::{
    entity::{did, key_did},
    list_query_generic::SelectWithListQuery,
    mapper::to_data_layer_error,
};

impl DidProvider {
    async fn resolve_relations(
        &self,
        model: did::Model,
        relations: &DidRelations,
    ) -> Result<Did, DataLayerError> {
        let mut result: Did = model.clone().into();

        if let Some(organisation_relations) = &relations.organisation {
            let organisation_id = Uuid::from_str(&model.organisation_id)?;

            result.organisation = Some(
                self.organisation_repository
                    .get_organisation(&organisation_id, organisation_relations)
                    .await?
                    .ok_or(DataLayerError::MissingRequiredRelation {
                        relation: "did-organisation",
                        id: organisation_id.to_string(),
                    })?,
            );
        }

        if let Some(key_relations) = &relations.keys {
            let key_dids = key_did::Entity::find()
                .filter(key_did::Column::DidId.eq(model.id))
                .all(&self.db)
                .await
                .map_err(|e| DataLayerError::Db(e.into()))?;

            let mut related_keys: Vec<RelatedKey> = vec![];
            let mut key_map: HashMap<KeyId, Key> = HashMap::default();
            for key_did_model in key_dids {
                let key_id = Uuid::from_str(&key_did_model.key_id)?;
                let key = if let Some(key) = key_map.get(&key_id) {
                    key.to_owned()
                } else {
                    let key = self
                        .key_repository
                        .get_key(&key_id, key_relations)
                        .await?
                        .ok_or(DataLayerError::MissingRequiredRelation {
                            relation: "did-key",
                            id: key_id.to_string(),
                        })?;

                    key_map.insert(key_id, key.to_owned());
                    key
                };

                related_keys.push(RelatedKey {
                    role: key_did_model.role.into(),
                    key,
                })
            }
            result.keys = Some(related_keys);
        }

        Ok(result)
    }
}

#[autometrics]
#[async_trait::async_trait]
impl DidRepository for DidProvider {
    async fn get_did(
        &self,
        id: &DidId,
        relations: &DidRelations,
    ) -> Result<Option<Did>, DataLayerError> {
        let did = did::Entity::find_by_id(id)
            .one(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        match did {
            None => Ok(None),
            Some(did) => Ok(Some(self.resolve_relations(did, relations).await?)),
        }
    }

    async fn get_did_by_value(
        &self,
        value: &DidValue,
        relations: &DidRelations,
    ) -> Result<Option<Did>, DataLayerError> {
        let did = did::Entity::find()
            .filter(did::Column::Did.eq(value))
            .one(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        match did {
            None => Ok(None),
            Some(did) => Ok(Some(self.resolve_relations(did, relations).await?)),
        }
    }

    async fn get_did_list(&self, query_params: DidListQuery) -> Result<GetDidList, DataLayerError> {
        let query = did::Entity::find()
            .with_list_query(&query_params)
            .order_by_desc(did::Column::CreatedDate)
            .order_by_desc(did::Column::Id);

        let limit = query_params
            .pagination
            .map(|pagination| pagination.page_size as u64);

        let items_count = query
            .to_owned()
            .count(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        let dids: Vec<did::Model> = query
            .all(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        Ok(create_list_response(dids, limit, items_count))
    }

    async fn create_did(&self, request: Did) -> Result<DidId, DataLayerError> {
        let keys = request.keys.to_owned();

        let did = did::ActiveModel::try_from(request)?
            .insert(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        if let Some(keys) = keys {
            key_did::Entity::insert_many(
                keys.into_iter()
                    .map(|key| key_did::ActiveModel {
                        did_id: Set(did.id.to_string()),
                        key_id: Set(key.key.id.to_string()),
                        role: Set(key.role.into()),
                    })
                    .collect::<Vec<_>>(),
            )
            .exec(&self.db)
            .await
            .map_err(to_data_layer_error)?;
        }

        Ok(did.id)
    }

    async fn update_did(&self, request: UpdateDidRequest) -> Result<(), DataLayerError> {
        let UpdateDidRequest { id, deactivated } = request;

        let did: did::ActiveModel = did::ActiveModel {
            id: Unchanged(id),
            deactivated: deactivated.map(Set).unwrap_or_default(),
            ..Default::default()
        };

        did.update(&self.db).await.map_err(|err| match err {
            sea_orm::DbErr::RecordNotUpdated => DataLayerError::RecordNotUpdated,
            err => DataLayerError::Db(err.into()),
        })?;

        Ok(())
    }
}
