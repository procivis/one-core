use one_core::model::trust_list_role::TrustListRoleEnum;
use one_core::model::trust_list_subscription::TrustListSubscriptionState;
use similar_asserts::assert_eq;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_delete_trust_list_subscription() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let trust_collection = context
        .db
        .trust_collections
        .create(organisation.clone(), Default::default())
        .await;

    let subscription = context
        .db
        .trust_list_subscriptions
        .create(
            "subscription",
            TrustListRoleEnum::PidProvider,
            "type",
            "reference",
            TrustListSubscriptionState::Active,
            trust_collection.id,
        )
        .await;

    // WHEN
    let resp = context
        .api
        .trust_collections
        .delete_subscription(trust_collection.id, subscription.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 204);

    let list_resp = context
        .api
        .trust_collections
        .list_subscriptions(trust_collection.id)
        .await;
    assert_eq!(list_resp.status(), 200);
    let list_body = list_resp.json_value().await;
    assert_eq!(list_body["totalItems"], 0);
}

#[tokio::test]
async fn test_delete_trust_list_subscription_not_found() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let trust_collection = context
        .db
        .trust_collections
        .create(organisation.clone(), Default::default())
        .await;

    let random_id = uuid::Uuid::new_v4();

    // WHEN
    let resp = context
        .api
        .trust_collections
        .delete_subscription(trust_collection.id, random_id)
        .await;

    // THEN
    assert_eq!(resp.status(), 404);
}
