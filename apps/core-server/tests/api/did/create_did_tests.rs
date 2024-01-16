use one_core::model::did::DidType;

use crate::fixtures::TestingKeyParams;
use crate::utils::context::TestContext;
use crate::utils::db_clients::keys::{eddsa_testing_params, es256_testing_params};
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_create_did_key_es256_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    let key = context
        .db
        .keys
        .create(&organisation, es256_testing_params())
        .await;
    // WHEN
    let resp = context
        .api
        .dids
        .create(organisation.id, key.id, "KEY", "test")
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;
    let did = context.db.dids.get(&resp["id"].parse()).await;
    assert_eq!(did.did_method, "KEY");
    assert_eq!(did.did_type, DidType::Local);
    assert!(did.did.as_str().starts_with("did:key:zDn"));
    let keys = did.keys.unwrap();
    assert_eq!(keys.len(), 5);
    for k in keys {
        assert_eq!(k.key.id, key.id);
    }
}

#[tokio::test]
async fn test_create_did_key_dilithium_failure_incapable() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

    let test_params = TestingKeyParams {
        key_type: Some("Dilithium".to_owned()), // Not capable
        storage_type: Some("INTERNAL".to_string()),
        ..Default::default()
    };

    let key = context.db.keys.create(&organisation, test_params).await;

    // WHEN
    let resp = context
        .api
        .dids
        .create(organisation.id, key.id, "KEY", "test")
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_create_did_key_eddsa_success() {
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
        .dids
        .create(organisation.id, key.id, "KEY", "test")
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;
    let did = context.db.dids.get(&resp["id"].parse()).await;
    assert_eq!(did.did_method, "KEY");
    assert_eq!(did.did_type, DidType::Local);
    assert!(did.did.as_str().starts_with("did:key:z6Mk"));
    let keys = did.keys.unwrap();
    assert_eq!(keys.len(), 5);
    for k in keys {
        assert_eq!(k.key.id, key.id);
    }
}

#[tokio::test]
async fn test_create_did_web_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    let key = context
        .db
        .keys
        .create(&organisation, es256_testing_params())
        .await;

    // WHEN
    let resp = context
        .api
        .dids
        .create(organisation.id, key.id, "WEB", "test")
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;
    let did = context.db.dids.get(&resp["id"].parse()).await;
    assert_eq!(did.did_method, "WEB");
    assert_eq!(did.did_type, DidType::Local);
    assert!(did.did.as_str().starts_with("did:web"));
    let keys = did.keys.unwrap();
    assert_eq!(keys.len(), 5);
    for k in keys {
        assert_eq!(k.key.id, key.id);
    }
}

#[tokio::test]
async fn test_create_did_jwk_success() {
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
        .dids
        .create(organisation.id, key.id, "JWK", "test")
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;
    let did = context.db.dids.get(&resp["id"].parse()).await;
    assert_eq!(did.did_method, "JWK");
    assert_eq!(did.did_type, DidType::Local);
    assert!(did.did.as_str().starts_with("did:jwk"));
    let keys = did.keys.unwrap();
    assert_eq!(keys.len(), 5);
    for k in keys {
        assert_eq!(k.key.id, key.id);
    }
}

#[tokio::test]
async fn test_create_did_with_same_name_in_different_organisations() {
    // GIVEN
    let (context, _, did) = TestContext::new_with_did().await;

    let organisation1 = context.db.organisations.create().await;
    let key1 = context
        .db
        .keys
        .create(&organisation1, eddsa_testing_params())
        .await;

    // WHEN
    let resp = context
        .api
        .dids
        .create(organisation1.id, key1.id, "JWK", &did.name)
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
}

#[tokio::test]
async fn test_fail_to_create_did_with_same_name_in_same_organisation() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    let key1 = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
        .await;

    let key2 = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
        .await;

    let resp = context
        .api
        .dids
        .create(organisation.id, key1.id, "JWK", "test")
        .await;
    assert_eq!(resp.status(), 201);

    // WHEN
    let resp = context
        .api
        .dids
        .create(organisation.id, key2.id, "JWK", "test")
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
}
