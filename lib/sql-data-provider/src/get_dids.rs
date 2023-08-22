use one_core::repository::data_provider::{GetDidQuery, GetDidsResponse, SortableDidColumn};
use one_core::repository::error::DataLayerError;
use sea_orm::{sea_query::SimpleExpr, EntityTrait, IntoSimpleExpr, PaginatorTrait, QueryOrder};

use crate::entity::{did, Did};
use crate::list_query::SelectWithListQuery;
use crate::OldProvider;

use super::common::calculate_pages_count;
use super::list_query::GetEntityColumn;

impl GetEntityColumn for SortableDidColumn {
    fn get_simple_expr(&self) -> SimpleExpr {
        match self {
            SortableDidColumn::Name => did::Column::Name.into_simple_expr(),
            SortableDidColumn::CreatedDate => did::Column::CreatedDate.into_simple_expr(),
        }
    }
}

impl OldProvider {
    pub async fn get_dids(
        &self,
        query_params: GetDidQuery,
    ) -> Result<GetDidsResponse, DataLayerError> {
        let limit: u64 = query_params.page_size as u64;

        let query = Did::find()
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

        Ok(GetDidsResponse {
            values: dids.into_iter().map(|item| item.into()).collect(),
            total_pages: calculate_pages_count(items_count, limit),
            total_items: items_count,
        })
    }
}

#[cfg(test)]
mod tests {
    use one_core::repository::data_provider::{GetDidQuery, SortDirection, SortableDidColumn};
    use time::macros::datetime;
    use uuid::Uuid;

    use crate::{entity::did, list_query::from_pagination, test_utilities::*};
    use sea_orm::{ActiveModelTrait, Set};

    #[tokio::test]
    async fn test_get_one_did() {
        let data_layer = setup_test_data_provider_and_connection().await.unwrap();

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();

        let did_name = "test did name";
        let did = "test:did";
        let id = insert_did(&data_layer.db, did_name, did, &organisation_id)
            .await
            .unwrap();

        let result = data_layer
            .get_dids(from_pagination(0, 1, organisation_id.to_owned()))
            .await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(1, response.total_items);
        assert_eq!(1, response.total_pages);
        assert_eq!(1, response.values.len());
        assert_eq!(id, response.values[0].id);
    }

    #[tokio::test]
    async fn test_get_empty_result() {
        let data_layer = setup_test_data_provider_and_connection().await.unwrap();

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();

        let result = data_layer
            .get_dids(from_pagination(0, 10, organisation_id.to_owned()))
            .await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(0, response.total_items);
        assert_eq!(0, response.total_pages);
    }

    #[tokio::test]
    async fn test_get_empty_incorrect_organisation() {
        let data_layer = setup_test_data_provider_and_connection().await.unwrap();

        let result = data_layer
            .get_dids(from_pagination(0, 10, Uuid::new_v4().to_string()))
            .await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(0, response.total_items);
        assert_eq!(0, response.total_pages);
    }

    #[tokio::test]
    async fn test_get_pages() {
        let data_layer = setup_test_data_provider_and_connection().await.unwrap();

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();

        let did_name = "test did name";
        let did = "test:did";

        for _ in 0..50 {
            insert_did(
                &data_layer.db,
                did_name,
                &format!("{}:{}", did, Uuid::new_v4()),
                &organisation_id,
            )
            .await
            .unwrap();
        }

        let result = data_layer
            .get_dids(from_pagination(0, 10, organisation_id.to_owned()))
            .await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(50, response.total_items);
        assert_eq!(5, response.total_pages);
        assert_eq!(10, response.values.len());

        let result = data_layer
            .get_dids(from_pagination(0, 2, organisation_id.to_owned()))
            .await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(50, response.total_items);
        assert_eq!(25, response.total_pages);
        assert_eq!(2, response.values.len());

        let result = data_layer
            .get_dids(from_pagination(5, 10, organisation_id.to_owned()))
            .await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(50, response.total_items);
        assert_eq!(5, response.total_pages);
        assert_eq!(0, response.values.len());
    }

    #[tokio::test]
    async fn test_filtering() {
        let data_layer = setup_test_data_provider_and_connection().await.unwrap();

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();

        let did_name = "name";
        let did_value = "did:value";

        insert_did(&data_layer.db, did_name, did_value, &organisation_id)
            .await
            .unwrap();

        // not found
        let result = data_layer
            .get_dids(GetDidQuery {
                page: 0,
                page_size: 2,
                sort: None,
                sort_direction: None,
                name: Some("nothing".to_owned()),
                organisation_id: organisation_id.to_owned(),
            })
            .await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(0, response.values.len());

        // by name
        let result = data_layer
            .get_dids(GetDidQuery {
                page: 0,
                page_size: 2,
                sort: None,
                sort_direction: None,
                name: Some(did_name.to_owned()),
                organisation_id: organisation_id.to_owned(),
            })
            .await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(1, response.values.len());

        // by value
        let result = data_layer
            .get_dids(GetDidQuery {
                page: 0,
                page_size: 2,
                sort: None,
                sort_direction: None,
                name: Some(did_value.to_owned()),
                organisation_id: organisation_id.to_owned(),
            })
            .await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(1, response.values.len());
    }

    #[tokio::test]
    async fn test_did_sorting() {
        let data_layer = setup_test_data_provider_and_connection().await.unwrap();

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();

        let older_a_did = did::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            did: Set("did1:did1".to_owned()),
            created_date: Set(datetime!(2023-02-01 21:00 +0)),
            last_modified: Set(get_dummy_date()),
            name: Set("a".to_owned()),
            type_field: Set(did::DidType::Local),
            method: Set(did::DidMethod::Key),
            organisation_id: Set(organisation_id.to_owned()),
        }
        .insert(&data_layer.db)
        .await
        .unwrap();

        let newer_b_did = did::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            did: Set("did2:did2".to_owned()),
            created_date: Set(datetime!(2023-02-02 21:00 +0)),
            last_modified: Set(get_dummy_date()),
            name: Set("b".to_owned()),
            type_field: Set(did::DidType::Local),
            method: Set(did::DidMethod::Key),
            organisation_id: Set(organisation_id.to_owned()),
        }
        .insert(&data_layer.db)
        .await
        .unwrap();

        // sort by name - default Ascending
        let result = data_layer
            .get_dids(GetDidQuery {
                page: 0,
                page_size: 2,
                sort: Some(SortableDidColumn::Name),
                sort_direction: None,
                name: None,
                organisation_id: organisation_id.to_owned(),
            })
            .await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(2, response.total_items);
        assert_eq!(1, response.total_pages);
        assert_eq!(2, response.values.len());
        assert_eq!(older_a_did.id, response.values[0].id);

        // sort by name - explicit Descending
        let result = data_layer
            .get_dids(GetDidQuery {
                page: 0,
                page_size: 2,
                sort: Some(SortableDidColumn::Name),
                sort_direction: Some(SortDirection::Descending),
                name: None,
                organisation_id: organisation_id.to_owned(),
            })
            .await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(2, response.total_items);
        assert_eq!(1, response.total_pages);
        assert_eq!(2, response.values.len());
        assert_eq!(newer_b_did.id, response.values[0].id);

        // sort by name - explicit Ascending
        let result = data_layer
            .get_dids(GetDidQuery {
                page: 0,
                page_size: 2,
                sort: Some(SortableDidColumn::Name),
                sort_direction: Some(SortDirection::Ascending),
                name: None,
                organisation_id: organisation_id.to_owned(),
            })
            .await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(2, response.total_items);
        assert_eq!(1, response.total_pages);
        assert_eq!(2, response.values.len());
        assert_eq!(older_a_did.id, response.values[0].id);

        // sort by CreatedDate - default Ascending
        let result = data_layer
            .get_dids(GetDidQuery {
                page: 0,
                page_size: 2,
                sort: Some(SortableDidColumn::CreatedDate),
                sort_direction: None,
                name: None,
                organisation_id: organisation_id.to_owned(),
            })
            .await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(2, response.total_items);
        assert_eq!(1, response.total_pages);
        assert_eq!(2, response.values.len());
        assert_eq!(older_a_did.id, response.values[0].id);

        // sort by CreatedDate - explicit Descending
        let result = data_layer
            .get_dids(GetDidQuery {
                page: 0,
                page_size: 2,
                sort: Some(SortableDidColumn::CreatedDate),
                sort_direction: Some(SortDirection::Descending),
                name: None,
                organisation_id: organisation_id.to_owned(),
            })
            .await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(2, response.total_items);
        assert_eq!(1, response.total_pages);
        assert_eq!(2, response.values.len());
        assert_eq!(newer_b_did.id, response.values[0].id);

        // sort by CreatedDate - explicit Ascending
        let result = data_layer
            .get_dids(GetDidQuery {
                page: 0,
                page_size: 2,
                sort: Some(SortableDidColumn::CreatedDate),
                sort_direction: Some(SortDirection::Ascending),
                name: None,
                organisation_id: organisation_id.to_owned(),
            })
            .await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(2, response.total_items);
        assert_eq!(1, response.total_pages);
        assert_eq!(2, response.values.len());
        assert_eq!(older_a_did.id, response.values[0].id);

        // no sorting specified - default Descending by CreatedDate
        let result = data_layer
            .get_dids(from_pagination(0, 2, organisation_id.to_owned()))
            .await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(2, response.total_items);
        assert_eq!(1, response.total_pages);
        assert_eq!(2, response.values.len());
        assert_eq!(newer_b_did.id, response.values[0].id);
    }
}
