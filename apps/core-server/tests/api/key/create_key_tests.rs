use reqwest::StatusCode;
use uuid::Uuid;

use crate::utils::{
    context::TestContext, db_clients::keys::eddsa_testing_params, field_match::FieldHelpers,
};

#[tokio::test]
async fn test_create_key_es256() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

    // WHEN
    let resp = context
        .api
        .keys
        .create(organisation.id, "ES256", "ESTEST")
        .await;

    // THEN
    assert_eq!(resp.status(), StatusCode::CREATED);

    let resp = resp.json_value().await;
    let key = context.db.keys.get(&resp["id"].parse()).await;

    assert_eq!(key.name, "ESTEST");
    assert_eq!(key.key_type, "ES256");
    assert!(!key.public_key.is_empty());
    assert_eq!(key.organisation.unwrap().id, organisation.id);
}

#[tokio::test]
async fn test_create_key_eddsa() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

    // WHEN
    let resp = context
        .api
        .keys
        .create(organisation.id, "EDDSA", "EDDSATEST")
        .await;

    // THEN
    assert_eq!(resp.status(), StatusCode::CREATED);

    let resp = resp.json_value().await;
    let key = context.db.keys.get(&resp["id"].parse()).await;

    assert_eq!(key.name, "EDDSATEST");
    assert_eq!(key.key_type, "EDDSA");
    assert!(!key.public_key.is_empty());
    assert_eq!(key.organisation.unwrap().id, organisation.id);
}

#[tokio::test]
async fn test_create_invalid_type() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

    // WHEN
    let resp = context
        .api
        .keys
        .create(organisation.id, "INVALID", "TEST")
        .await;

    // THEN
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_create_invalid_organisation() {
    // GIVEN
    let context = TestContext::new().await;

    // WHEN
    let resp = context
        .api
        .keys
        .create(Uuid::new_v4(), "EDDSA", "TEST")
        .await;

    // THEN
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_create_key_with_same_name_in_different_organisations() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    let key = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
        .await;

    let organisation1 = context.db.organisations.create().await;

    // WHEN
    let resp = context
        .api
        .keys
        .create(organisation1.id, "EDDSA", &key.name)
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
}

#[tokio::test]
async fn test_fail_to_create_key_with_same_name_in_same_organisation() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    let key = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
        .await;

    // WHEN
    let resp = context
        .api
        .keys
        .create(organisation.id, "EDDSA", &key.name)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
}
