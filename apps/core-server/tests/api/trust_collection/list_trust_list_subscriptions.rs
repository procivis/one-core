use one_core::model::trust_list_role::TrustListRoleEnum;
use one_core::model::trust_list_subscription::TrustListSubscriptionState;
use similar_asserts::assert_eq;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_list_trust_list_subscriptions() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let trust_collection = context
        .db
        .trust_collections
        .create(organisation.clone(), Default::default())
        .await;

    context
        .db
        .trust_list_subscriptions
        .create(
            "subscription 1",
            TrustListRoleEnum::PidProvider,
            "LOTE_SUBSCRIBER",
            "reference1",
            TrustListSubscriptionState::Active,
            trust_collection.id,
        )
        .await;
    context
        .db
        .trust_list_subscriptions
        .create(
            "subscription 2",
            TrustListRoleEnum::PidProvider,
            "LOTE_SUBSCRIBER",
            "reference2",
            TrustListSubscriptionState::Active,
            trust_collection.id,
        )
        .await;

    // WHEN
    let resp = context
        .api
        .trust_collections
        .list_subscriptions(trust_collection.id, Some(organisation.id))
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    assert_eq!(body["totalItems"], 2);
    let names: Vec<String> = body["values"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["name"].as_str().unwrap().to_string())
        .collect();
    assert!(names.contains(&"subscription 1".to_string()));
    assert!(names.contains(&"subscription 2".to_string()));
}

#[tokio::test]
async fn test_list_trust_list_subscriptions_wrong_organisation() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let (other_context, other_organisation) = TestContext::new_with_organisation(None).await;

    let trust_collection = context
        .db
        .trust_collections
        .create(organisation.clone(), Default::default())
        .await;

    context
        .db
        .trust_list_subscriptions
        .create(
            "subscription 1",
            TrustListRoleEnum::PidProvider,
            "type",
            "reference",
            TrustListSubscriptionState::Active,
            trust_collection.id,
        )
        .await;

    // WHEN
    let resp = other_context
        .api
        .trust_collections
        .list_subscriptions(trust_collection.id, Some(other_organisation.id))
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    assert_eq!(body["totalItems"], 0);
}
