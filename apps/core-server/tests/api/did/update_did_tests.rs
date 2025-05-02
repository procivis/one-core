use one_core::model::did::DidType;
use uuid::Uuid;

use crate::fixtures::{TestingDidParams, TestingIdentifierParams};
use crate::utils::context::TestContext;

#[tokio::test]
async fn test_update_did_cannot_deactivate_did_key() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let did = context
        .db
        .dids
        .create(
            &organisation,
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
            &organisation,
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
            &organisation,
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
            &organisation,
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
