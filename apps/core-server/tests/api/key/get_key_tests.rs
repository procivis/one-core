use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use reqwest::StatusCode;
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::fixtures::TestingKeyParams;
use crate::utils::context::TestContext;

#[tokio::test]
async fn test_get_key_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let key = context
        .db
        .keys
        .create(
            &organisation,
            TestingKeyParams {
                public_key: Some(b"test_public_key".to_vec()),
                key_reference: Some(b"test_key_reference".to_vec()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.keys.get(key.id).await;

    // THEN
    assert_eq!(resp.status(), StatusCode::OK);
    let resp_key = resp.json_value().await;

    assert_eq!(resp_key["id"], key.id.to_string());
    assert_eq!(
        resp_key["publicKey"],
        Base64UrlSafeNoPadding::encode_to_string("test_public_key").unwrap()
    );
    assert_eq!(resp_key["isRemote"], false);
}

#[tokio::test]
async fn test_get_key_not_found() {
    // GIVEN
    let (context, _) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context.api.keys.get(Uuid::new_v4().into()).await;

    // THEN
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_get_remote_key_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let key = context
        .db
        .keys
        .create(
            &organisation,
            TestingKeyParams {
                public_key: Some(b"test_public_key".to_vec()),
                key_reference: None,
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.keys.get(key.id).await;

    // THEN
    assert_eq!(resp.status(), StatusCode::OK);
    let resp_key = resp.json_value().await;

    assert_eq!(resp_key["id"], key.id.to_string());
    assert_eq!(
        resp_key["publicKey"],
        Base64UrlSafeNoPadding::encode_to_string("test_public_key").unwrap()
    );
    assert_eq!(resp_key["isRemote"], true);
}
