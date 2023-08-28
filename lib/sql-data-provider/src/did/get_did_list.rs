use super::{mapper::create_list_response, DidProvider};
use crate::{entity::did, list_query::SelectWithListQuery};
use one_core::{
    model::did::{GetDidList, GetDidQuery},
    repository::error::DataLayerError,
};
use sea_orm::{EntityTrait, PaginatorTrait, QueryOrder};

impl DidProvider {
    pub async fn get_did_list_impl(
        &self,
        query_params: GetDidQuery,
    ) -> Result<GetDidList, DataLayerError> {
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
}

#[cfg(test)]
mod tests {

    use crate::{
        did::test_utilities::*, entity::did, list_query::from_pagination, test_utilities::*,
    };
    use one_core::{
        model::{
            common::SortDirection,
            did::{GetDidQuery, SortableDidColumn},
        },
        repository::did_repository::DidRepository,
    };
    use sea_orm::{ActiveModelTrait, Set};
    use time::macros::datetime;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_get_did_list_one_did() {
        let TestSetupWithDid {
            provider,
            did_id,
            organisation_id,
            ..
        } = setup_with_did().await;

        let result = provider
            .get_did_list(from_pagination(0, 1, organisation_id.to_string()))
            .await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(1, response.total_items);
        assert_eq!(1, response.total_pages);
        assert_eq!(1, response.values.len());
        assert_eq!(did_id, response.values[0].id);
    }

    #[tokio::test]
    async fn test_get_did_list_empty_result() {
        let TestSetup {
            provider,
            organisation_id,
            ..
        } = setup_empty().await;

        let result = provider
            .get_did_list(from_pagination(0, 1, organisation_id.to_string()))
            .await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(0, response.total_items);
        assert_eq!(0, response.total_pages);
        assert_eq!(0, response.values.len());
    }

    #[tokio::test]
    async fn test_get_did_list_empty_incorrect_organisation() {
        let TestSetupWithDid { provider, .. } = setup_with_did().await;

        let result = provider
            .get_did_list(from_pagination(0, 1, Uuid::new_v4().to_string()))
            .await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(0, response.total_items);
        assert_eq!(0, response.total_pages);
        assert_eq!(0, response.values.len());
    }

    #[tokio::test]
    async fn test_get_did_list_pages() {
        let TestSetup {
            provider,
            organisation_id,
            db,
        } = setup_empty().await;

        for i in 0..50 {
            insert_did(
                &db,
                "test did name",
                &format!("did:key:{}", i),
                &organisation_id.to_string(),
            )
            .await
            .unwrap();
        }

        let result = provider
            .get_did_list(from_pagination(0, 10, organisation_id.to_string()))
            .await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(50, response.total_items);
        assert_eq!(5, response.total_pages);
        assert_eq!(10, response.values.len());

        let result = provider
            .get_did_list(from_pagination(0, 2, organisation_id.to_string()))
            .await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(50, response.total_items);
        assert_eq!(25, response.total_pages);
        assert_eq!(2, response.values.len());

        let result = provider
            .get_did_list(from_pagination(5, 10, organisation_id.to_string()))
            .await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(50, response.total_items);
        assert_eq!(5, response.total_pages);
        assert_eq!(0, response.values.len());
    }

    #[tokio::test]
    async fn test_get_did_list_filtering() {
        let TestSetupWithDid {
            provider,
            did_id,
            did_name,
            did_value,
            organisation_id,
            ..
        } = setup_with_did().await;

        // not found
        let result = provider
            .get_did_list(GetDidQuery {
                page: 0,
                page_size: 2,
                sort: None,
                sort_direction: None,
                name: Some("not-found".to_owned()),
                organisation_id: organisation_id.to_string(),
            })
            .await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(0, response.values.len());

        // by name
        let result = provider
            .get_did_list(GetDidQuery {
                page: 0,
                page_size: 2,
                sort: None,
                sort_direction: None,
                name: Some(did_name.to_owned()),
                organisation_id: organisation_id.to_string(),
            })
            .await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(1, response.values.len());
        assert_eq!(did_id, response.values[0].id);

        // by value
        let result = provider
            .get_did_list(GetDidQuery {
                page: 0,
                page_size: 2,
                sort: None,
                sort_direction: None,
                name: Some(did_value.to_owned()),
                organisation_id: organisation_id.to_string(),
            })
            .await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(1, response.values.len());
        assert_eq!(did_id, response.values[0].id);
    }

    #[tokio::test]
    async fn test_get_did_list_sorting() {
        let TestSetup {
            provider,
            organisation_id,
            db,
        } = setup_empty().await;

        let older_a_did = did::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            did: Set("did1:did1".to_owned()),
            created_date: Set(datetime!(2023-02-01 21:00 +0)),
            last_modified: Set(get_dummy_date()),
            name: Set("a".to_owned()),
            type_field: Set(did::DidType::Local),
            method: Set("KEY".to_string()),
            organisation_id: Set(organisation_id.to_string()),
        }
        .insert(&db)
        .await
        .unwrap();

        let newer_b_did = did::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            did: Set("did2:did2".to_owned()),
            created_date: Set(datetime!(2023-02-02 21:00 +0)),
            last_modified: Set(get_dummy_date()),
            name: Set("b".to_owned()),
            type_field: Set(did::DidType::Local),
            method: Set("KEY".to_string()),
            organisation_id: Set(organisation_id.to_string()),
        }
        .insert(&db)
        .await
        .unwrap();

        // sort by name - default Ascending
        let result = provider
            .get_did_list(GetDidQuery {
                page: 0,
                page_size: 2,
                sort: Some(SortableDidColumn::Name),
                sort_direction: None,
                name: None,
                organisation_id: organisation_id.to_string(),
            })
            .await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(2, response.total_items);
        assert_eq!(1, response.total_pages);
        assert_eq!(2, response.values.len());
        assert_eq!(older_a_did.id, response.values[0].id.to_string());

        // sort by name - explicit Descending
        let result = provider
            .get_did_list(GetDidQuery {
                page: 0,
                page_size: 2,
                sort: Some(SortableDidColumn::Name),
                sort_direction: Some(SortDirection::Descending),
                name: None,
                organisation_id: organisation_id.to_string(),
            })
            .await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(2, response.total_items);
        assert_eq!(1, response.total_pages);
        assert_eq!(2, response.values.len());
        assert_eq!(newer_b_did.id, response.values[0].id.to_string());

        // sort by name - explicit Ascending
        let result = provider
            .get_did_list(GetDidQuery {
                page: 0,
                page_size: 2,
                sort: Some(SortableDidColumn::Name),
                sort_direction: Some(SortDirection::Ascending),
                name: None,
                organisation_id: organisation_id.to_string(),
            })
            .await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(2, response.total_items);
        assert_eq!(1, response.total_pages);
        assert_eq!(2, response.values.len());
        assert_eq!(older_a_did.id, response.values[0].id.to_string());

        // sort by CreatedDate - default Ascending
        let result = provider
            .get_did_list(GetDidQuery {
                page: 0,
                page_size: 2,
                sort: Some(SortableDidColumn::CreatedDate),
                sort_direction: None,
                name: None,
                organisation_id: organisation_id.to_string(),
            })
            .await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(2, response.total_items);
        assert_eq!(1, response.total_pages);
        assert_eq!(2, response.values.len());
        assert_eq!(older_a_did.id, response.values[0].id.to_string());

        // sort by CreatedDate - explicit Descending
        let result = provider
            .get_did_list(GetDidQuery {
                page: 0,
                page_size: 2,
                sort: Some(SortableDidColumn::CreatedDate),
                sort_direction: Some(SortDirection::Descending),
                name: None,
                organisation_id: organisation_id.to_string(),
            })
            .await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(2, response.total_items);
        assert_eq!(1, response.total_pages);
        assert_eq!(2, response.values.len());
        assert_eq!(newer_b_did.id, response.values[0].id.to_string());

        // sort by CreatedDate - explicit Ascending
        let result = provider
            .get_did_list(GetDidQuery {
                page: 0,
                page_size: 2,
                sort: Some(SortableDidColumn::CreatedDate),
                sort_direction: Some(SortDirection::Ascending),
                name: None,
                organisation_id: organisation_id.to_string(),
            })
            .await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(2, response.total_items);
        assert_eq!(1, response.total_pages);
        assert_eq!(2, response.values.len());
        assert_eq!(older_a_did.id, response.values[0].id.to_string());

        // no sorting specified - default Descending by CreatedDate
        let result = provider
            .get_did_list(from_pagination(0, 2, organisation_id.to_string()))
            .await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(2, response.total_items);
        assert_eq!(1, response.total_pages);
        assert_eq!(2, response.values.len());
        assert_eq!(newer_b_did.id, response.values[0].id.to_string());
    }
}
