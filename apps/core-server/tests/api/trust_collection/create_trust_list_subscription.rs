use one_core::model::trust_list_role::TrustListRoleEnum;
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::utils::api_clients::trust_list_publication::CreateTrustListPublicationTestParams;
use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_post_trust_list_subscription() {
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

    // WHEN
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

    // THEN
    assert_eq!(resp.status(), 201);
    let body = resp.json_value().await;
    let trust_list_subscription_id = body["id"].parse::<Uuid>().into();
    let trust_list_subscription = context
        .db
        .trust_list_subscriptions
        .get(&trust_list_subscription_id)
        .await
        .unwrap();
    assert_eq!(trust_list_subscription.role, TrustListRoleEnum::PidProvider);
}

#[tokio::test]
async fn test_post_trust_list_unsupported_role() {
    // GIVEN
    let (context, organisation, ..) = TestContext::new_with_certificate_identifier(None).await;
    let trust_collection = context
        .db
        .trust_collections
        .create(organisation.clone(), Default::default())
        .await;
    let reference = format!("{}/some_very_invalid_endpoint", context.api.base_url);

    // WHEN
    let resp = context
        .api
        .trust_collections
        .create_subscription(
            trust_collection.id,
            "new subscription",
            Some("UNSUPPORTED_ROLE"),
            reference.as_str(),
            "LOTE_SUBSCRIBER",
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0084", resp.error_code().await);
}

#[tokio::test]
async fn test_post_trust_list_invalid_reference() {
    // GIVEN
    let (context, organisation, ..) = TestContext::new_with_certificate_identifier(None).await;
    let trust_collection = context
        .db
        .trust_collections
        .create(organisation.clone(), Default::default())
        .await;
    let reference = format!("{}/some_very_invalid_endpoint", context.api.base_url);

    // WHEN
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

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0395", resp.error_code().await);
}

#[tokio::test]
async fn test_post_trust_list_subscription_collection_not_found() {
    // GIVEN
    let context = TestContext::new(None).await;
    let random_id = Uuid::new_v4();
    let reference = format!("{}/some_very_invalid_endpoint", context.api.base_url);

    // WHEN
    let resp = context
        .api
        .trust_collections
        .create_subscription(
            random_id,
            "new subscription",
            Some("PID_PROVIDER"),
            reference.as_str(),
            "LOTE_SUBSCRIBER",
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 404);
    assert_eq!("BR_0391", resp.error_code().await);
}

#[tokio::test]
async fn test_post_trust_list_subscription_already_exists() {
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

    // WHEN
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

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0403", resp.error_code().await);
}
