use one_core::model::trust_entity::{TrustEntityRole, TrustEntityState};

use crate::fixtures::TestingDidParams;
use crate::utils::api_clients::trust_anchors::ListFilters;
use crate::utils::context::TestContext;
use crate::utils::db_clients::trust_anchors::TestingTrustAnchorParams;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_list_trust_anchors() {
    // GIVEN
    let context = TestContext::new(None).await;
    context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams {
            name: "name1".to_string(),
            ..Default::default()
        })
        .await;
    context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams {
            name: "name2".to_string(),
            ..Default::default()
        })
        .await;

    // WHEN
    let resp = context
        .api
        .trust_anchors
        .list(
            0,
            ListFilters {
                is_publisher: Some(true),
                name: None,
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);

    let body = resp.json_value().await;
    assert_eq!(body["totalItems"], 2);
    assert_eq!(body["values"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn test_list_trust_anchors_with_entities() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    for id in 0..2 {
        let anchor = context
            .db
            .trust_anchors
            .create(TestingTrustAnchorParams {
                name: format!("name{id}"),
                ..Default::default()
            })
            .await;

        let did1 = context
            .db
            .dids
            .create(&organisation, TestingDidParams::default())
            .await;
        let did2 = context
            .db
            .dids
            .create(&organisation, TestingDidParams::default())
            .await;

        context
            .db
            .trust_entities
            .create(
                &format!("name{id}-1"),
                TrustEntityRole::Both,
                TrustEntityState::Active,
                anchor.clone(),
                did1.clone(),
            )
            .await;

        context
            .db
            .trust_entities
            .create(
                &format!("name{id}-2"),
                TrustEntityRole::Both,
                TrustEntityState::Active,
                anchor.clone(),
                did2.clone(),
            )
            .await;
    }

    // WHEN
    let resp = context
        .api
        .trust_anchors
        .list(
            0,
            ListFilters {
                is_publisher: Some(true),
                name: None,
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);

    let body = resp.json_value().await;
    assert_eq!(body["totalItems"], 2);
    assert_eq!(body["values"][0]["entities"], 2);
    assert_eq!(body["values"][1]["entities"], 2);
}

#[tokio::test]
async fn test_filter_trust_anchor_by_name() {
    // GIVEN
    let context = TestContext::new(None).await;

    let anchor = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams {
            name: "foo".to_string(),
            ..Default::default()
        })
        .await;

    context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams {
            name: "bar".to_string(),
            ..Default::default()
        })
        .await;

    // WHEN
    let resp = context
        .api
        .trust_anchors
        .list(
            0,
            ListFilters {
                name: Some("foo".to_string()),
                is_publisher: None,
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);

    let body = resp.json_value().await;
    assert_eq!(body["totalItems"], 1);
    body["values"][0]["id"].assert_eq(&anchor.id);
}
