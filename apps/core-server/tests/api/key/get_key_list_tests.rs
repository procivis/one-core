use reqwest::StatusCode;
use shared_types::KeyId;

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
            key_type: None,
            key_storage: None,
            ids: None,
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
            key_type: Some("EDDSA".to_string()),
            key_storage: None,
            ids: None,
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
            key_type: None,
            key_storage: Some("INTERNAL".to_string()),
            ids: None,
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
