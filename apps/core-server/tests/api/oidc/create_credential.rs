use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use one_core::model::{
    credential::CredentialStateEnum,
    did::{KeyRole, RelatedKey},
};
use serde_json::json;
use shared_types::CredentialId;
use time::{macros::format_description, OffsetDateTime};
use uuid::Uuid;

use crate::{
    fixtures::{TestingCredentialParams, TestingDidParams},
    utils::{context::TestContext, db_clients::keys::eddsa_testing_params},
};

#[tokio::test]
async fn test_post_issuer_credential() {
    test_post_issuer_credential_with("NONE").await;
}

#[tokio::test]
async fn test_post_issuer_credential_with_bitstring_revocation_method() {
    test_post_issuer_credential_with("BITSTRINGSTATUSLIST").await;
}

#[tokio::test]
async fn test_post_issuer_credential_with_lvvc_revocation_method() {
    let (context, credential_id) = test_post_issuer_credential_with("LVVC").await;

    let lvvcs = context
        .db
        .lvvcs
        .get_all_by_credential_id(credential_id)
        .await;

    assert_eq!(1, lvvcs.len());
    assert_eq!(credential_id, lvvcs[0].linked_credential_id);
}

async fn test_post_issuer_credential_with(revocation_method: &str) -> (TestContext, CredentialId) {
    let interaction_id = Uuid::new_v4();
    let access_token = format!("{interaction_id}.test");

    let context = TestContext::new_with_token(&access_token).await;

    let organisation = context.db.organisations.create().await;

    let key = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
        .await;

    let issuer_did = context
        .db
        .dids
        .create(
            &organisation,
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: key.clone(),
                }]),
                ..Default::default()
            },
        )
        .await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("schema-1", &organisation, revocation_method)
        .await;

    let date_format =
        format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond]Z");
    let data = serde_json::to_vec(&json!({
        "pre_authorized_code_used": true,
        "access_token": access_token,
        "access_token_expires_at": (OffsetDateTime::now_utc() + time::Duration::seconds(20)).format(&date_format).unwrap(),
    })).unwrap();

    let base_url = &context.config.app.core_base_url;
    let interaction = context
        .db
        .interactions
        .create(Some(interaction_id), base_url, &data)
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Offered,
            &issuer_did,
            "OPENID4VC",
            TestingCredentialParams {
                interaction: Some(interaction),
                key: Some(key),
                ..Default::default()
            },
        )
        .await;

    let jwt = [
        r#"{"alg":"EDDSA","typ":"JWT","kid":"did:key:20927216-8144-474C-B249-0C048D2BFD51"}"#,
        r#"{"aud":"test"}"#,
        "MissingSignature",
    ]
    .map(|s| Base64UrlSafeNoPadding::encode_to_string(s).unwrap())
    .join(".");

    let resp = context
        .api
        .ssi
        .issuer_create_credential(credential_schema.id, &jwt)
        .await;

    assert_eq!(200, resp.status());

    (context, credential.id)
}
