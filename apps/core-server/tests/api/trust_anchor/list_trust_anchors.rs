use one_core::model::trust_entity::{TrustEntityRole, TrustEntityState, TrustEntityType};
use similar_asserts::assert_eq;
use time::{Duration, OffsetDateTime};

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
                ..Default::default()
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
            .create(Some(organisation.clone()), TestingDidParams::default())
            .await;
        let did2 = context
            .db
            .dids
            .create(Some(organisation.clone()), TestingDidParams::default())
            .await;

        context
            .db
            .trust_entities
            .create(
                &format!("name{id}-1"),
                TrustEntityRole::Both,
                TrustEntityState::Active,
                anchor.clone(),
                TrustEntityType::Did,
                did1.did.into(),
                None,
                did1.organisation,
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
                TrustEntityType::Did,
                did2.did.into(),
                None,
                did2.organisation,
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
                ..Default::default()
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
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);

    let body = resp.json_value().await;
    assert_eq!(body["totalItems"], 1);
    body["values"][0]["id"].assert_eq(&anchor.id);
}

#[tokio::test]
async fn test_filter_trust_anchor_by_date() {
    // GIVEN
    let context = TestContext::new(None).await;

    let time_1 = OffsetDateTime::now_utc() - Duration::hours(2);
    let time_2 = OffsetDateTime::now_utc() - Duration::hours(1);
    let time_3 = OffsetDateTime::now_utc();

    let anchor_time_1 = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams {
            created_date: time_1,
            last_modified: time_1,
            name: "time1".to_string(),
            ..Default::default()
        })
        .await;

    let anchor_time_2 = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams {
            created_date: time_2,
            last_modified: time_2,
            name: "time2".to_string(),
            ..Default::default()
        })
        .await;

    // time 1
    let resp = context
        .api
        .trust_anchors
        .list(
            0,
            ListFilters {
                created_date_after: Some(time_1 - Duration::seconds(20)),
                created_date_before: Some(time_1 + Duration::seconds(20)),
                last_modified_after: Some(time_1 - Duration::seconds(20)),
                last_modified_before: Some(time_1 + Duration::seconds(20)),
                ..Default::default()
            },
        )
        .await;

    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    assert_eq!(body["totalItems"], 1);
    body["values"][0]["id"].assert_eq(&anchor_time_1.id);

    // time 2
    let resp = context
        .api
        .trust_anchors
        .list(
            0,
            ListFilters {
                created_date_after: Some(time_2 - Duration::seconds(20)),
                created_date_before: Some(time_2 + Duration::seconds(20)),
                last_modified_after: Some(time_2 - Duration::seconds(20)),
                last_modified_before: Some(time_2 + Duration::seconds(20)),
                ..Default::default()
            },
        )
        .await;

    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    assert_eq!(body["totalItems"], 1);
    body["values"][0]["id"].assert_eq(&anchor_time_2.id);

    // time 3
    let resp = context
        .api
        .trust_anchors
        .list(
            0,
            ListFilters {
                created_date_after: Some(time_3 - Duration::seconds(20)),
                created_date_before: Some(time_3 + Duration::seconds(20)),
                ..Default::default()
            },
        )
        .await;

    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    assert_eq!(body["totalItems"], 0);
}
