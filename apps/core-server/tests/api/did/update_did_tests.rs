use one_core::model::did::DidType;
use serde_json::Value;
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::fixtures::{TestingDidParams, TestingIdentifierParams};
use crate::utils::api_clients::dids::DidKeys;
use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_update_did_cannot_deactivate_did_key() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                did_method: Some("KEY".into()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.dids.deactivate(&did.id).await;

    // THEN
    assert_eq!(resp.status(), 400)
}

#[tokio::test]
async fn test_update_did_deactivates_local_did_web() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                did_method: Some("WEB".into()),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(did.clone()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.dids.deactivate(&did.id).await;

    // THEN
    assert_eq!(resp.status(), 204)
}

#[tokio::test]
async fn test_update_did_cannot_deactivate_remote_did_web() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                did_method: Some("WEB".into()),
                did_type: Some(DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.dids.deactivate(&did.id).await;

    // THEN
    assert_eq!(resp.status(), 400)
}

#[tokio::test]
async fn test_update_did_same_deactivated_status_as_requested() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                did_method: Some("WEB".into()),
                deactivated: Some(true),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.dids.deactivate(&did.id).await;

    // THEN
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_update_did_not_found() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context.api.dids.deactivate(&Uuid::new_v4()).await;

    // THEN
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_update_did_tdw_success() {
    let (context, org) = TestContext::new_with_organisation(None).await;

    let response = context.api.keys.create(org.id, "ECDSA", "test key").await;
    assert_eq!(response.status(), 201);
    let body_json = response.json_value().await;
    let key_id = Uuid::parse_str(body_json["id"].as_str().unwrap())
        .unwrap()
        .into();

    let response = context
        .api
        .dids
        .create(
            org.id,
            DidKeys {
                assertion_method: vec![key_id],
                authentication: vec![key_id],
                capability_delegation: vec![],
                capability_invocation: vec![],
                key_agreement: vec![],
            },
            "TDW",
            "test did:tdw",
            None,
        )
        .await;
    assert_eq!(response.status(), 201);
    let body_json = response.json_value().await;
    let did_id = Uuid::parse_str(body_json["id"].as_str().unwrap()).unwrap();

    let response = context.api.dids.get_did_webvh(&did_id).await;
    assert_eq!(response.status(), 200);

    let response = context.api.dids.deactivate(&did_id).await;
    assert_eq!(response.status(), 204);

    let response = context.api.dids.get(&did_id).await;
    assert_eq!(response.status(), 200);
    let body_json = response.json_value().await;
    body_json["deactivated"].assert_eq(&Value::Bool(true));
}

#[tokio::test]
async fn test_create_and_deactivate_webvh_at_existing_log_endpoint() {
    let (context, org) = TestContext::new_with_organisation(None).await;
    let response = context
        .api
        .keys
        .create(org.id, "ECDSA", "webvh document key")
        .await;
    assert_eq!(response.status(), 201);
    let key_id = Uuid::parse_str(response.json_value().await["id"].as_str().unwrap())
        .unwrap()
        .into();

    let response = context
        .api
        .dids
        .create(
            org.id,
            DidKeys {
                assertion_method: vec![key_id],
                authentication: vec![key_id],
                capability_delegation: vec![],
                capability_invocation: vec![],
                key_agreement: vec![],
            },
            "WEBVH",
            "test did:webvh",
            Some(serde_json::json!({"externalHostingUrl": "https://example.com/issuer"})),
        )
        .await;
    assert_eq!(response.status(), 201);
    let did_id = Uuid::parse_str(response.json_value().await["id"].as_str().unwrap()).unwrap();

    let response = context.api.dids.get_did_webvh(&did_id).await;
    assert_eq!(response.status(), 200);
    let log = response.text().await;
    let first: Value = serde_json::from_str(&log).unwrap();
    assert_eq!(first["parameters"]["method"], "did:webvh:1.0");
    assert_eq!(first["parameters"]["portable"], false);
    assert!(first["parameters"].get("witness").is_none());
    assert_eq!(first["parameters"]["watchers"], serde_json::json!([]));
    assert_eq!(first["parameters"]["nextKeyHashes"], serde_json::json!([]));
    assert_eq!(
        first["state"]["profile_version"],
        "swiss-profile-anchor:1.0.0"
    );
    let verification_method = &first["state"]["verificationMethod"][0];
    let key_id = verification_method["id"]
        .as_str()
        .unwrap()
        .rsplit_once('#')
        .unwrap()
        .1;
    assert_eq!(verification_method["publicKeyJwk"]["kid"], key_id);

    let response = context.api.dids.deactivate(&did_id).await;
    assert_eq!(response.status(), 204);
    let response = context.api.dids.get_did_webvh(&did_id).await;
    assert_eq!(response.status(), 200);
    let log = response.text().await;
    let entries: Vec<Value> = log
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[1]["parameters"]["deactivated"], true);
    assert_eq!(
        entries[1]["parameters"]["updateKeys"],
        serde_json::json!([])
    );
    assert_eq!(entries[0]["state"], entries[1]["state"]);
}
