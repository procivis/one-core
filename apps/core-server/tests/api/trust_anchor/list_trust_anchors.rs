use one_core::model::trust_anchor::TrustAnchorRole;
use one_core::model::trust_entity::TrustEntityRole;

use crate::utils::api_clients::trust_anchors::ListFilters;
use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_list_trust_anchors() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    context
        .db
        .trust_anchors
        .create(
            "name1",
            organisation.clone(),
            "SIMPLE_TRUST_LIST",
            TrustAnchorRole::Publisher,
        )
        .await;
    context
        .db
        .trust_anchors
        .create(
            "name2",
            organisation.clone(),
            "SIMPLE_TRUST_LIST",
            TrustAnchorRole::Publisher,
        )
        .await;

    // WHEN
    let resp = context
        .api
        .trust_anchors
        .list(
            0,
            ListFilters {
                organisation_id: organisation.id,
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
    let (context, organisation) = TestContext::new_with_organisation().await;
    for id in 0..2 {
        let anchor = context
            .db
            .trust_anchors
            .create(
                &format!("name{id}"),
                organisation.clone(),
                "SIMPLE_TRUST_LIST",
                TrustAnchorRole::Publisher,
            )
            .await;

        context
            .db
            .trust_entities
            .create(
                &format!("entity_id{id}-1"),
                &format!("name{id}-1"),
                TrustEntityRole::Both,
                anchor.clone(),
            )
            .await;

        context
            .db
            .trust_entities
            .create(
                &format!("entity_id{id}-2"),
                &format!("name{id}-2"),
                TrustEntityRole::Both,
                anchor.clone(),
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
                organisation_id: organisation.id,
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
    let (context, organisation) = TestContext::new_with_organisation().await;
    let anchor = context
        .db
        .trust_anchors
        .create(
            "foo",
            organisation.clone(),
            "SIMPLE_TRUST_LIST",
            TrustAnchorRole::Publisher,
        )
        .await;

    context
        .db
        .trust_anchors
        .create(
            "bar",
            organisation.clone(),
            "SIMPLE_TRUST_LIST",
            TrustAnchorRole::Publisher,
        )
        .await;

    // WHEN
    let resp = context
        .api
        .trust_anchors
        .list(
            0,
            ListFilters {
                organisation_id: organisation.id,
                name: Some("foo".into()),
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);

    let body = resp.json_value().await;
    assert_eq!(body["totalItems"], 1);
    body["values"][0]["id"].assert_eq(&anchor.id);
}
