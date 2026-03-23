use one_core::model::trust_list_role::TrustListRoleEnum;
use one_core::model::trust_list_subscription::TrustListSubscriptionState;
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_get_trust_collection_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let collection = context
        .db
        .trust_collections
        .create(organisation, Default::default())
        .await;

    let list = context
        .db
        .trust_list_subscriptions
        .create(
            "subscription",
            TrustListRoleEnum::PidProvider,
            "type",
            "reference",
            TrustListSubscriptionState::Active,
            collection.id,
        )
        .await;

    // WHEN
    let resp = context.api.ssi.get_trust_collection(collection.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp["name"].assert_eq(&collection.name);

    let trust_lists = &resp["trustLists"];
    assert_eq!(trust_lists.as_array().unwrap().len(), 1);
    assert_eq!(trust_lists[0]["id"], list.id.to_string());
    assert_eq!(trust_lists[0]["name"], "subscription");
}

#[tokio::test]
async fn test_get_trust_collection_not_found() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context.api.ssi.get_trust_collection(Uuid::new_v4()).await;

    // THEN
    assert_eq!(resp.status(), 404);
}
