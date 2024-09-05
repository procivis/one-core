use one_core::model::did::{KeyRole, RelatedKey};

use crate::fixtures::{TestingDidParams, TestingKeyParams};
use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_get_did_list_filters_deactivated_dids() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    let expected_did = context
        .db
        .dids
        .create(
            &organisation,
            TestingDidParams {
                deactivated: Some(false),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .dids
        .create(
            &organisation,
            TestingDidParams {
                deactivated: Some(true),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .dids
        .list(0, 10, &organisation.id, false, None, None, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);

    let resp = resp.json_value().await;
    let values = resp["values"].as_array().unwrap();
    assert_eq!(1, values.len());
    values[0]["id"].assert_eq(&expected_did.id);
}

#[tokio::test]
async fn test_get_did_list_filters_with_key_filtering() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

    let key1 = context
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

    let key2 = context
        .db
        .keys
        .create(
            &organisation,
            TestingKeyParams {
                key_type: Some("ES256".to_string()),
                ..Default::default()
            },
        )
        .await;

    let key3 = context
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

    let expected_did = context
        .db
        .dids
        .create(
            &organisation,
            TestingDidParams {
                deactivated: Some(false),
                keys: Some(vec![
                    RelatedKey {
                        role: KeyRole::Authentication,
                        key: key1.clone(),
                    },
                    RelatedKey {
                        role: KeyRole::AssertionMethod,
                        key: key1,
                    },
                ]),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .dids
        .create(
            &organisation,
            TestingDidParams {
                deactivated: Some(false),
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key: key3,
                }]),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .dids
        .create(
            &organisation,
            TestingDidParams {
                deactivated: Some(false),
                keys: Some(vec![
                    RelatedKey {
                        role: KeyRole::Authentication,
                        key: key2.clone(),
                    },
                    RelatedKey {
                        role: KeyRole::AssertionMethod,
                        key: key2,
                    },
                ]),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .dids
        .list(
            0,
            10,
            &organisation.id,
            false,
            Some("EDDSA".to_string()),
            Some("ASSERTION_METHOD".to_string()),
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);

    let resp = resp.json_value().await;
    let values = resp["values"].as_array().unwrap();
    assert_eq!(1, values.len());
    values[0]["id"].assert_eq(&expected_did.id);
}

#[tokio::test]
async fn test_get_did_list_filters_with_did_method_filtering() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

    let expected_did = context
        .db
        .dids
        .create(
            &organisation,
            TestingDidParams {
                did_method: Some("FOO".into()),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .dids
        .create(
            &organisation,
            TestingDidParams {
                did_method: Some("BAR".into()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .dids
        .list(
            0,
            10,
            &organisation.id,
            false,
            None,
            None,
            Some("FOO".into()),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);

    let resp = resp.json_value().await;
    let values = resp["values"].as_array().unwrap();
    assert_eq!(1, values.len());
    values[0]["id"].assert_eq(&expected_did.id);
}
