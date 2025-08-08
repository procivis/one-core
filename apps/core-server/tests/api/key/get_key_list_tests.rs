use reqwest::StatusCode;
use shared_types::KeyId;
use similar_asserts::assert_eq;
use time::{Duration, OffsetDateTime};

use crate::fixtures::TestingKeyParams;
use crate::utils::api_clients::keys::KeyFilters;
use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_get_keys_ok() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let key1 = context
        .db
        .keys
        .create(
            &organisation,
            TestingKeyParams {
                name: Some("name123".to_string()),
                ..Default::default()
            },
        )
        .await;

    let key2 = context
        .db
        .keys
        .create(
            &organisation,
            TestingKeyParams {
                name: Some("name321".to_string()),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .keys
        .create(
            &organisation,
            TestingKeyParams {
                name: Some("test123".to_string()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .keys
        .list(KeyFilters {
            page: 0,
            page_size: 10,
            organisation_id: organisation.id,
            name: Some("name".to_string()),
            key_types: None,
            key_storages: None,
            ids: None,
            is_remote: None,
            created_date_after: None,
            created_date_before: None,
            last_modified_after: None,
            last_modified_before: None,
        })
        .await;

    // THEN
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = resp.json_value().await;
    let values = resp["values"].as_array().unwrap();

    assert_eq!(2, values.len());
    let key2_id: KeyId = values[0]["id"].parse();
    let key1_id: KeyId = values[1]["id"].parse();
    assert_eq!(key1.id, key1_id);
    assert_eq!(key2.id, key2_id);
}

#[tokio::test]
async fn test_get_keys_filter_by_key_type() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let key = context
        .db
        .keys
        .create(
            &organisation,
            TestingKeyParams {
                key_type: Some("EDDSA".to_string()),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .keys
        .create(
            &organisation,
            TestingKeyParams {
                key_type: Some("ECDSA".to_string()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .keys
        .list(KeyFilters {
            page: 0,
            page_size: 10,
            organisation_id: organisation.id,
            name: None,
            key_types: Some(vec!["EDDSA".to_string()]),
            key_storages: None,
            ids: None,
            is_remote: None,
            created_date_after: None,
            created_date_before: None,
            last_modified_after: None,
            last_modified_before: None,
        })
        .await;

    // THEN
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = resp.json_value().await;
    let values = resp["values"].as_array().unwrap();

    assert_eq!(1, values.len());
    let key_id: KeyId = values[0]["id"].parse();
    assert_eq!(key.id, key_id);
}

#[tokio::test]
async fn test_get_keys_filter_by_key_storage() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let key = context
        .db
        .keys
        .create(
            &organisation,
            TestingKeyParams {
                storage_type: Some("INTERNAL".to_string()),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .keys
        .create(
            &organisation,
            TestingKeyParams {
                storage_type: Some("SOMETHING_ELSE".to_string()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .keys
        .list(KeyFilters {
            page: 0,
            page_size: 10,
            organisation_id: organisation.id,
            name: None,
            key_types: None,
            key_storages: Some(vec!["INTERNAL".to_string()]),
            ids: None,
            is_remote: None,
            created_date_after: None,
            created_date_before: None,
            last_modified_after: None,
            last_modified_before: None,
        })
        .await;

    // THEN
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = resp.json_value().await;
    let values = resp["values"].as_array().unwrap();

    assert_eq!(1, values.len());
    let key_id: KeyId = values[0]["id"].parse();
    assert_eq!(key.id, key_id);
}

#[tokio::test]
async fn test_get_keys_filter_by_is_remote() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let key1 = context
        .db
        .keys
        .create(
            &organisation,
            TestingKeyParams {
                key_reference: None,
                ..Default::default()
            },
        )
        .await;

    let key2 = context
        .db
        .keys
        .create(
            &organisation,
            TestingKeyParams {
                key_reference: Some(b"testKey2".to_vec()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .keys
        .list(KeyFilters {
            page: 0,
            page_size: 10,
            organisation_id: organisation.id,
            name: None,
            key_types: None,
            key_storages: None,
            ids: None,
            is_remote: Some(true),
            created_date_after: None,
            created_date_before: None,
            last_modified_after: None,
            last_modified_before: None,
        })
        .await;

    // THEN
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = resp.json_value().await;
    let values = resp["values"].as_array().unwrap();

    assert_eq!(1, values.len());
    let key_id: KeyId = values[0]["id"].parse();
    assert_eq!(key1.id, key_id);
    assert_eq!(true, values[0]["isRemote"]);

    // WHEN
    let resp = context
        .api
        .keys
        .list(KeyFilters {
            page: 0,
            page_size: 10,
            organisation_id: organisation.id,
            name: None,
            key_types: None,
            key_storages: None,
            ids: None,
            is_remote: Some(false),
            created_date_after: None,
            created_date_before: None,
            last_modified_after: None,
            last_modified_before: None,
        })
        .await;

    // THEN
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = resp.json_value().await;
    let values = resp["values"].as_array().unwrap();

    assert_eq!(1, values.len());
    let key_id: KeyId = values[0]["id"].parse();
    assert_eq!(key2.id, key_id);
    assert_eq!(false, values[0]["isRemote"]);
}

#[tokio::test]
async fn test_get_keys_filter_by_date() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let time_1 = OffsetDateTime::now_utc() - Duration::hours(2);
    let time_2 = OffsetDateTime::now_utc() - Duration::hours(1);
    let time_3 = OffsetDateTime::now_utc();

    let key_time_1 = context
        .db
        .keys
        .create(
            &organisation,
            TestingKeyParams {
                created_date: Some(time_1),
                last_modified: Some(time_1),
                ..Default::default()
            },
        )
        .await;

    let key_time_2 = context
        .db
        .keys
        .create(
            &organisation,
            TestingKeyParams {
                created_date: Some(time_2),
                last_modified: Some(time_2),
                ..Default::default()
            },
        )
        .await;

    // time 1
    let resp = context
        .api
        .keys
        .list(KeyFilters {
            page: 0,
            page_size: 10,
            organisation_id: organisation.id,
            name: None,
            key_types: None,
            key_storages: None,
            ids: None,
            is_remote: None,
            created_date_after: Some(time_1 - Duration::seconds(20)),
            created_date_before: Some(time_1 + Duration::seconds(20)),
            last_modified_after: Some(time_1 - Duration::seconds(20)),
            last_modified_before: Some(time_1 + Duration::seconds(20)),
        })
        .await;

    assert_eq!(resp.status(), StatusCode::OK);
    let resp = resp.json_value().await;
    let values = resp["values"].as_array().unwrap();
    assert_eq!(1, values.len());
    let key_id: KeyId = values[0]["id"].parse();
    assert_eq!(key_time_1.id, key_id);

    // time 2
    let resp = context
        .api
        .keys
        .list(KeyFilters {
            page: 0,
            page_size: 10,
            organisation_id: organisation.id,
            name: None,
            key_types: None,
            key_storages: None,
            ids: None,
            is_remote: None,
            created_date_after: Some(time_2 - Duration::seconds(20)),
            created_date_before: Some(time_2 + Duration::seconds(20)),
            last_modified_after: Some(time_2 - Duration::seconds(20)),
            last_modified_before: Some(time_2 + Duration::seconds(20)),
        })
        .await;

    assert_eq!(resp.status(), StatusCode::OK);
    let resp = resp.json_value().await;
    let values = resp["values"].as_array().unwrap();
    assert_eq!(1, values.len());
    let key_id: KeyId = values[0]["id"].parse();
    assert_eq!(key_time_2.id, key_id);

    // time 3
    let resp = context
        .api
        .keys
        .list(KeyFilters {
            page: 0,
            page_size: 10,
            organisation_id: organisation.id,
            name: None,
            key_types: None,
            key_storages: None,
            ids: None,
            is_remote: None,
            created_date_after: Some(time_3 - Duration::seconds(20)),
            created_date_before: Some(time_3 + Duration::seconds(20)),
            last_modified_after: Some(time_3 - Duration::seconds(20)),
            last_modified_before: Some(time_3 + Duration::seconds(20)),
        })
        .await;

    assert_eq!(resp.status(), StatusCode::OK);
    let resp = resp.json_value().await;
    let values = resp["values"].as_array().unwrap();
    assert_eq!(0, values.len());
}
