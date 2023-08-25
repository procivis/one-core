/*
#[cfg(test)]
mod tests {
    use one_core::repository::{data_provider::DidType, error::DataLayerError};
    use uuid::Uuid;

    use crate::test_utilities::*;

    #[tokio::test]
    async fn test_get_existing_did() {
        let data_layer = setup_test_data_provider_and_connection().await.unwrap();

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();
        let did_name = "test did name";
        let did = "test:did";
        let id = insert_did(&data_layer.db, did_name, did, &organisation_id)
            .await
            .unwrap();

        let result = data_layer.get_did_details(&id).await;

        assert!(result.is_ok());

        let content = result.unwrap();
        assert_eq!(content.id, id);
        assert_eq!(content.did_method, "KEY");
        assert_eq!(content.did_type, DidType::Local);
        assert_eq!(content.did, did);
        assert_eq!(content.name, did_name);
        assert_eq!(content.organisation_id, organisation_id);
    }

    #[tokio::test]
    async fn test_get_existing_did_by_value() {
        let data_layer = setup_test_data_provider_and_connection().await.unwrap();

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();
        let did_name = "test did name";
        let did = "test:did";
        let id = insert_did(&data_layer.db, did_name, did, &organisation_id)
            .await
            .unwrap();

        let result = data_layer.get_did_details_by_value(did).await;

        assert!(result.is_ok());

        let content = result.unwrap();
        assert_eq!(content.id, id);
        assert_eq!(content.did_method, "KEY");
        assert_eq!(content.did_type, DidType::Local);
        assert_eq!(content.did, did);
        assert_eq!(content.name, did_name);
        assert_eq!(content.organisation_id, organisation_id);
    }

    #[tokio::test]
    async fn test_get_not_existing_did() {
        let data_layer = setup_test_data_provider_and_connection().await.unwrap();

        let id = Uuid::new_v4();

        let result = data_layer.get_did_details(&id.to_string()).await;

        assert!(matches!(result, Err(DataLayerError::RecordNotFound)));
    }
}


#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use uuid::Uuid;

    use one_core::repository::{
        data_provider::{CreateDidRequest, DidType},
        error::DataLayerError,
    };

    use crate::test_utilities::*;

    #[tokio::test]
    async fn test_create_did_simple() {
        let data_layer = setup_test_data_provider_and_connection().await.unwrap();
        let did_methods = get_did_methods();

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();

        let did = "did:key:123".to_owned();

        let request = CreateDidRequest {
            name: "Name".to_string(),
            organisation_id,
            did: did.clone(),
            did_type: DidType::Local,
            method: "KEY".to_string(),
        };

        let result = data_layer.create_did(request, &did_methods).await;

        assert!(result.is_ok());

        let response = result.unwrap();

        assert!(Uuid::from_str(&response.id).is_ok());
    }

    #[tokio::test]
    async fn test_create_did_twice_by_id_and_value() {
        let data_layer = setup_test_data_provider_and_connection().await.unwrap();
        let did_methods = get_did_methods();

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();

        let missing_organisation = Uuid::new_v4().to_string();

        let did1 = "did:key:123".to_owned();
        let did2 = "did:key:456".to_owned();

        let mut request = CreateDidRequest {
            name: "Name".to_string(),
            organisation_id,
            did: did1.clone(),
            did_type: DidType::Local,
            method: "KEY".to_string(),
        };

        let result = data_layer.create_did(request.clone(), &did_methods).await;
        assert!(result.is_ok());

        // DID value stays the same
        request.did = did1.clone();
        let result = data_layer.create_did(request.clone(), &did_methods).await;
        assert!(matches!(result, Err(DataLayerError::AlreadyExists)));

        // DID and ID are new. Organisation is incorrect.
        request.did = did2.clone();
        request.organisation_id = missing_organisation;
        let result = data_layer.create_did(request.clone(), &did_methods).await;
        assert!(matches!(result, Err(DataLayerError::IncorrectParameters)));
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
            method: Set("KEY".to_string()),
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
            method: Set("KEY".to_string()),
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


#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use uuid::Uuid;

    use one_core::repository::{
        data_provider::{CreateDidRequest, DidType},
        error::DataLayerError,
    };

    use crate::test_utilities::*;

    #[tokio::test]
    async fn test_create_did_simple() {
        let data_layer = setup_test_data_provider_and_connection().await.unwrap();
        let did_methods = get_did_methods();

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();

        let did = "did:key:123".to_owned();

        let request = CreateDidRequest {
            name: "Name".to_string(),
            organisation_id,
            did: did.clone(),
            did_type: DidType::Local,
            method: "KEY".to_string(),
        };

        let result = data_layer.create_did(request, &did_methods).await;

        assert!(result.is_ok());

        let response = result.unwrap();

        assert!(Uuid::from_str(&response.id).is_ok());
    }

    #[tokio::test]
    async fn test_create_did_twice_by_id_and_value() {
        let data_layer = setup_test_data_provider_and_connection().await.unwrap();
        let did_methods = get_did_methods();

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();

        let missing_organisation = Uuid::new_v4().to_string();

        let did1 = "did:key:123".to_owned();
        let did2 = "did:key:456".to_owned();

        let mut request = CreateDidRequest {
            name: "Name".to_string(),
            organisation_id,
            did: did1.clone(),
            did_type: DidType::Local,
            method: "KEY".to_string(),
        };

        let result = data_layer.create_did(request.clone(), &did_methods).await;
        assert!(result.is_ok());

        // DID value stays the same
        request.did = did1.clone();
        let result = data_layer.create_did(request.clone(), &did_methods).await;
        assert!(matches!(result, Err(DataLayerError::AlreadyExists)));

        // DID and ID are new. Organisation is incorrect.
        request.did = did2.clone();
        request.organisation_id = missing_organisation;
        let result = data_layer.create_did(request.clone(), &did_methods).await;
        assert!(matches!(result, Err(DataLayerError::IncorrectParameters)));
    }
}



*/
