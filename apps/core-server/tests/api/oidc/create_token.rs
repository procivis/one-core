use core_server::router::start_server;
use one_core::model::credential::CredentialStateEnum;
use serde_json::json;
use time::{macros::format_description, OffsetDateTime};

use crate::{
    fixtures::{self, TestingCredentialParams},
    utils,
};

#[tokio::test]
async fn test_post_issuer_token() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url);
    let db_conn = fixtures::create_db(&config).await;

    let organisation = fixtures::create_organisation(&db_conn).await;
    let did = fixtures::create_did(&db_conn, &organisation, None).await;
    let credential_schema =
        fixtures::create_credential_schema(&db_conn, "test", &organisation, "NONE").await;

    let format = format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond]Z");
    let data = json!({
        "pre_authorized_code_used": false,
        "access_token": "access_token",
        "access_token_expires_at": (OffsetDateTime::now_utc() + time::Duration::seconds(20)).format(&format).unwrap(),
    });
    let data = serde_json::to_vec(&data).unwrap();
    let interaction = fixtures::create_interaction(&db_conn, &base_url, &data).await;
    let interaction_id = interaction.id;
    fixtures::create_credential(
        &db_conn,
        &credential_schema,
        CredentialStateEnum::Pending,
        &did,
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
        "{base_url}/ssi/oidc-issuer/v1/{}/token",
        credential_schema.id
    );

    let resp = utils::client()
        .post(url)
        .form(&[
            ("pre-authorized_code", interaction_id.to_string()),
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
            ),
        ])
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 200);
}
