use core_server::endpoint::trust_anchor::dto::TrustAnchorRoleRest;
use one_core::model::trust_anchor::TrustAnchorRole;
use one_core::model::trust_entity::{TrustEntityRole, TrustEntityState};

use crate::utils::api_clients::trust_anchors::ListFilters;
use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_list_trust_anchors() {
    // GIVEN
    let context = TestContext::new().await;
    context
        .db
        .trust_anchors
        .create("name1", "SIMPLE_TRUST_LIST", TrustAnchorRole::Publisher)
        .await;
    context
        .db
        .trust_anchors
        .create("name2", "SIMPLE_TRUST_LIST", TrustAnchorRole::Publisher)
        .await;

    // WHEN
    let resp = context
        .api
        .trust_anchors
        .list(
            0,
            ListFilters {
                role: Some(TrustAnchorRoleRest::Publisher),
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
    let (context, _, did, _) = TestContext::new_with_did().await;

    for id in 0..2 {
        let anchor = context
            .db
            .trust_anchors
            .create(
                &format!("name{id}"),
                "SIMPLE_TRUST_LIST",
                TrustAnchorRole::Publisher,
            )
            .await;

        context
            .db
            .trust_entities
            .create(
                &format!("name{id}-1"),
                TrustEntityRole::Both,
                TrustEntityState::Active,
                anchor.clone(),
                did.clone(),
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
                did.clone(),
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
                role: Some(TrustAnchorRoleRest::Publisher),
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
    let context = TestContext::new().await;

    let anchor = context
        .db
        .trust_anchors
        .create("foo", "SIMPLE_TRUST_LIST", TrustAnchorRole::Publisher)
        .await;

    context
        .db
        .trust_anchors
        .create("bar", "SIMPLE_TRUST_LIST", TrustAnchorRole::Publisher)
        .await;

    // WHEN
    let resp = context
        .api
        .trust_anchors
        .list(
            0,
            ListFilters {
                name: Some("foo".to_string()),
                role: None,
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);

    let body = resp.json_value().await;
    assert_eq!(body["totalItems"], 1);
    body["values"][0]["id"].assert_eq(&anchor.id);
}
