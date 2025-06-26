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
            Some(organisation.clone()),
            TestingDidParams {
                did_method: Some("KEY".to_string()),
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
            Some(organisation.clone()),
            TestingDidParams {
                did_method: Some("WEB".to_string()),
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
            Some(organisation.clone()),
            TestingDidParams {
                did_method: Some("WEB".to_string()),
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
            Some(organisation.clone()),
            TestingDidParams {
                did_method: Some("WEB".to_string()),
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
async fn test_update_did_webvh_success() {
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
            "WEBVH",
            "test did:webvh",
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
