use super::{mapper::create_list_response, DidProvider};
use crate::{entity::did, error_mapper::to_data_layer_error, list_query::SelectWithListQuery};
use one_core::{
    model::did::{Did, DidId, DidRelations, DidValue, GetDidList, GetDidQuery},
    repository::{did_repository::DidRepository, error::DataLayerError},
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder,
};
use std::str::FromStr;
use uuid::Uuid;

#[async_trait::async_trait]
impl DidRepository for DidProvider {
    async fn get_did(&self, id: &DidId, _relations: &DidRelations) -> Result<Did, DataLayerError> {
        let did = did::Entity::find_by_id(id.to_string())
            .one(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?
            .ok_or(DataLayerError::RecordNotFound)?;

        did.try_into()
    }

    async fn get_did_by_value(
        &self,
        value: &DidValue,
        _relations: &DidRelations,
    ) -> Result<Did, DataLayerError> {
        let did: did::Model = did::Entity::find()
            .filter(did::Column::Did.eq(value))
            .one(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?
            .ok_or(DataLayerError::RecordNotFound)?;

        did.try_into()
    }

    async fn get_did_list(&self, query_params: GetDidQuery) -> Result<GetDidList, DataLayerError> {
        let limit: u64 = query_params.page_size as u64;

        let query = did::Entity::find()
            .with_organisation_id(&query_params, &did::Column::OrganisationId)
            .with_list_query(
                &query_params,
                &Some(vec![did::Column::Name, did::Column::Did]),
            )
            .order_by_desc(did::Column::CreatedDate)
            .order_by_desc(did::Column::Id);

        let items_count = query
            .to_owned()
            .count(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

        let dids: Vec<did::Model> = query
            .all(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

        Ok(create_list_response(dids, limit, items_count))
    }

    async fn create_did(&self, request: Did) -> Result<DidId, DataLayerError> {
        let did = did::ActiveModel::from(request)
            .insert(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Uuid::from_str(&did.id).map_err(|_| DataLayerError::MappingError)
    }
}
