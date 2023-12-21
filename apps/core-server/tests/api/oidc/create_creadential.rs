use core_server::router::start_server;
use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use one_core::model::{
    credential::CredentialStateEnum,
    did::{KeyRole, RelatedKey},
};
use serde_json::json;
use time::{macros::format_description, OffsetDateTime};
use uuid::Uuid;

use crate::{
    fixtures::{self, TestingCredentialParams, TestingDidParams},
    utils,
};

#[tokio::test]
async fn test_post_issuer_credential() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url);
    let db_conn = fixtures::create_db(&config).await;

    let organisation = fixtures::create_organisation(&db_conn).await;

    let key = fixtures::create_eddsa_key(&db_conn, &organisation).await;
    let issuer_did = fixtures::create_did(
        &db_conn,
        &organisation,
        Some(TestingDidParams {
            did_method: Some("WEB".to_string()),
            keys: Some(vec![RelatedKey {
                role: KeyRole::AssertionMethod,
                key,
            }]),
            ..Default::default()
        }),
    )
    .await;

    let credential_schema =
        fixtures::create_credential_schema(&db_conn, "test", &organisation, "NONE").await;

    let interaction_id = Uuid::new_v4();
    let access_token = format!("{interaction_id}.test");
    let date_format =
        format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond]Z");
    let data = serde_json::to_vec(&json!({
        "pre_authorized_code_used": true,
        "access_token": access_token,
        "access_token_expires_at": (OffsetDateTime::now_utc() + time::Duration::seconds(20)).format(&date_format).unwrap(),
    })).unwrap();
    let interaction =
        fixtures::create_interaction_with_id(interaction_id, &db_conn, &base_url, &data).await;
    fixtures::create_credential(
        &db_conn,
        &credential_schema,
        CredentialStateEnum::Offered,
        &issuer_did,
        "OPENID4VC",
        TestingCredentialParams {
            interaction: Some(interaction),
            ..Default::default()
        },
    )
    .await;

    // WHEN
    let _handle = tokio::spawn(async move { start_server(listener, config, db_conn).await });

    let url = format!(
        "{base_url}/ssi/oidc-issuer/v1/{}/credential",
        credential_schema.id
    );

    let jwt = [
        r#"{"alg":"EDDSA","typ":"JWT","kid":"did:key:20927216-8144-474C-B249-0C048D2BFD51"}"#,
        r#"{"aud":"test"}"#,
        "MissingSignature",
    ]
    .map(|s| Base64UrlSafeNoPadding::encode_to_string(s).unwrap())
    .join(".");

    let resp = utils::client()
        .post(url)
        .bearer_auth(access_token)
        .json(&json!({
            "format": "jwt_vc_json",
            "credential_definition": {
                "type": ["VerifiableCredential"]
            },
            "proof": {
                "proof_type": "jwt",
                "jwt": jwt
            },
        }))
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 200);
}
