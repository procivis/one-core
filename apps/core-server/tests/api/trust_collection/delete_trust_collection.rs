use shared_types::TrustListSubscriptionId;
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::utils::api_clients::trust_list_publication::CreateTrustListPublicationTestParams;
use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_delete_trust_collection() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let tc = context
        .db
        .trust_collections
        .create(organisation, Default::default())
        .await;

    // WHEN
    let resp = context.api.trust_collections.delete(tc.id).await;

    // THEN
    assert_eq!(resp.status(), 204);

    let resp = context.api.trust_collections.get(tc.id).await;
    assert_eq!(resp.status(), 404);

    let history_entries = context.db.histories.get_by_entity_id(&tc.id.into()).await;
    let contains_history_entry = history_entries.values.iter().any(|entry| {
        entry.entity_type == one_core::model::history::HistoryEntityType::TrustCollection
            && entry.action == one_core::model::history::HistoryAction::Deleted
    });
    assert!(contains_history_entry);
}

#[tokio::test]
async fn test_delete_trust_collection_not_found() {
    // GIVEN
    let (context, _) = TestContext::new_with_organisation(None).await;
    let non_existent_id = uuid::Uuid::new_v4();

    // WHEN
    let resp = context.api.trust_collections.delete(non_existent_id).await;

    // THEN
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_delete_trust_collection_twice() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let tc = context
        .db
        .trust_collections
        .create(organisation, Default::default())
        .await;

    // WHEN
    let resp1 = context.api.trust_collections.delete(tc.id).await;
    let resp2 = context.api.trust_collections.delete(tc.id).await;

    // THEN
    assert_eq!(resp1.status(), 204);
    assert_eq!(resp2.status(), 404);
}

#[tokio::test]
async fn test_delete_trust_collection_with_trust_list_subscriptions() {
    // GIVEN
    let (context, organisation, identifier, ..) =
        TestContext::new_with_certificate_identifier(None).await;
    let trust_collection = context
        .db
        .trust_collections
        .create(organisation.clone(), Default::default())
        .await;

    let resp = context
        .api
        .trust_list_publication
        .create_trust_list_publication(CreateTrustListPublicationTestParams {
            identifier_id: identifier.id,
            organisation_id: organisation.id,
            name: "test_trust_list_publication",
            role: core_server::endpoint::trust_list_publication::dto::TrustListRoleRestEnum::PidProvider,
            r#type: "LOTE_PUBLISHER".into(),
            key_id: None,
            certificate_id: None,
            params: None,
        })
        .await;
    assert_eq!(resp.status(), 201);
    let publication_id = resp.json_value().await["id"].parse::<Uuid>().into();

    let resp = context
        .api
        .trust_list_publication
        .create_trust_entry(publication_id, identifier.id, None)
        .await;
    assert_eq!(resp.status(), 201);

    let reference = format!(
        "{}/ssi/trust-list/v1/{}",
        context.api.base_url, publication_id
    );

    let resp = context
        .api
        .trust_collections
        .create_subscription(
            trust_collection.id,
            "new subscription",
            None,
            reference.as_str(),
            "LOTE_SUBSCRIBER",
        )
        .await;
    assert_eq!(resp.status(), 201);
    let body = resp.json_value().await;
    let trust_list_subscription_id: TrustListSubscriptionId = body["id"].parse::<Uuid>().into();

    // WHEN
    let resp = context
        .api
        .trust_collections
        .delete(trust_collection.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 204);

    let resp = context.api.trust_collections.get(trust_collection.id).await;
    assert_eq!(resp.status(), 404);

    let history_entries = context
        .db
        .histories
        .get_by_entity_id(&trust_collection.id.into())
        .await;
    let contains_history_entry = history_entries.values.iter().any(|entry| {
        entry.entity_type == one_core::model::history::HistoryEntityType::TrustCollection
            && entry.action == one_core::model::history::HistoryAction::Deleted
    });
    assert!(contains_history_entry);

    let history_entries = context
        .db
        .histories
        .get_by_entity_id(&trust_list_subscription_id.into())
        .await;
    let contains_history_entry = history_entries.values.iter().any(|entry| {
        entry.entity_type == one_core::model::history::HistoryEntityType::TrustListSubscription
            && entry.action == one_core::model::history::HistoryAction::Deleted
    });
    assert!(contains_history_entry);
}
