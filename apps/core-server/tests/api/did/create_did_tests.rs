use std::str::FromStr;

use one_core::model::did::DidType;

use crate::fixtures::TestingKeyParams;
use crate::utils::api_clients::dids::DidKeys;
use crate::utils::context::TestContext;
use crate::utils::db_clients::keys::{ecdsa_testing_params, eddsa_testing_params};
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_create_did_key_ecdsa_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;

    // WHEN
    let resp = context
        .api
        .dids
        .create(
            organisation.id,
            DidKeys::single(key.id),
            "KEY",
            "test",
            None,
        )
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
    let (context, organisation) = TestContext::new_with_organisation(None).await;

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
        .create(
            organisation.id,
            DidKeys::single(key.id),
            "KEY",
            "test",
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_create_did_key_eddsa_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let key = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
        .await;

    // WHEN
    let resp = context
        .api
        .dids
        .create(
            organisation.id,
            DidKeys::single(key.id),
            "KEY",
            "test",
            None,
        )
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
async fn test_fail_to_create_did_key_to_much_keys() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let key1 = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;
    let key2 = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;

    // WHEN
    let resp = context
        .api
        .dids
        .create(
            organisation.id,
            DidKeys::all(vec![key1.id, key2.id]),
            "KEY",
            "test",
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0030", resp.error_code().await);
}

#[tokio::test]
async fn test_create_did_web_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;

    // WHEN
    let resp = context
        .api
        .dids
        .create(
            organisation.id,
            DidKeys::single(key.id),
            "WEB",
            "test",
            None,
        )
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
async fn test_create_did_web_mixed_keys() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let key1 = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;

    let key2 = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;

    // WHEN
    let resp = context
        .api
        .dids
        .create(
            organisation.id,
            DidKeys {
                assertion_method: vec![key1.id, key2.id],
                authentication: vec![key1.id, key2.id],
                capability_delegation: vec![key1.id],
                capability_invocation: vec![key1.id],
                key_agreement: vec![key1.id],
            },
            "WEB",
            "test",
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;
    let did = context.db.dids.get(&resp["id"].parse()).await;
    assert_eq!(did.did_method, "WEB");
    assert_eq!(did.did_type, DidType::Local);
    assert!(did.did.as_str().starts_with("did:web"));
    let keys = did.keys.unwrap();
    assert_eq!(keys.len(), 7);
}

#[tokio::test]
async fn test_create_did_jwk_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let key = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
        .await;

    // WHEN
    let resp = context
        .api
        .dids
        .create(
            organisation.id,
            DidKeys::single(key.id),
            "JWK",
            "test",
            None,
        )
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
    let (context, _, did, ..) = TestContext::new_with_did(None).await;

    let organisation1 = context.db.organisations.create().await;
    let key = context
        .db
        .keys
        .create(&organisation1, eddsa_testing_params())
        .await;

    // WHEN
    let resp = context
        .api
        .dids
        .create(
            organisation1.id,
            DidKeys::single(key.id),
            "JWK",
            &did.name,
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
}

#[tokio::test]
async fn test_fail_to_create_did_with_same_name_in_same_organisation() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
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
        .create(
            organisation.id,
            DidKeys::single(key1.id),
            "JWK",
            "test",
            None,
        )
        .await;
    assert_eq!(resp.status(), 201);

    // WHEN
    let resp = context
        .api
        .dids
        .create(
            organisation.id,
            DidKeys::single(key2.id),
            "JWK",
            "test",
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_fail_to_create_did_with_same_value_in_same_organisation() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let key = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
        .await;

    let resp = context
        .api
        .dids
        .create(
            organisation.id,
            DidKeys::single(key.id),
            "JWK",
            "test 1",
            None,
        )
        .await;
    assert_eq!(resp.status(), 201);

    // WHEN
    let resp = context
        .api
        .dids
        .create(
            organisation.id,
            DidKeys::single(key.id),
            "JWK",
            "test 2",
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_create_did_with_same_value_in_different_organisations() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let organisation1 = context.db.organisations.create().await;
    let key = context
        .db
        .keys
        .create(&organisation1, eddsa_testing_params())
        .await;

    // WHEN
    let resp1 = context
        .api
        .dids
        .create(
            organisation1.id,
            DidKeys::single(key.id),
            "JWK",
            "test 1",
            None,
        )
        .await;

    let resp2 = context
        .api
        .dids
        .create(
            organisation.id,
            DidKeys::single(key.id),
            "JWK",
            "test 2",
            None,
        )
        .await;

    // THEN
    assert_eq!(resp1.status(), 201);
    assert_eq!(resp2.status(), 201);
}

#[tokio::test]
async fn test_create_did_webvh_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;

    // WHEN
    let resp = context
        .api
        .dids
        .create(
            organisation.id,
            DidKeys::single(key.id),
            "WEBVH",
            "test",
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;

    let did = context.db.dids.get(&resp["id"].parse()).await;
    assert_eq!(did.did_method, "WEBVH");
    assert_eq!(did.did_type, DidType::Local);

    assert!(did.did.as_str().starts_with("did:tdw:"));
    assert!(
        did.did
            .as_str()
            .ends_with(&format!(":ssi:did-webvh:v1:{}", did.id))
    );

    let log = did.log.unwrap();
    assert_eq!(log.lines().count(), 1);
    assert!(serde_json::Value::from_str(&log).unwrap().is_array());
}

#[tokio::test]
async fn test_fail_to_create_did_deactivated_organisation() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    context.db.organisations.deactivate(&organisation.id).await;
    let key = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
        .await;

    // WHEN
    let resp = context
        .api
        .dids
        .create(
            organisation.id,
            DidKeys::single(key.id),
            "JWK",
            "test",
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0241", resp.error_code().await);
}
