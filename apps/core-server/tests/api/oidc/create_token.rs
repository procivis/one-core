use one_core::model::credential::CredentialStateEnum;
use one_core::model::credential_schema::CredentialSchemaType;
use one_core::model::interaction::InteractionType;
use serde_json::json;
use similar_asserts::assert_eq;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::fixtures::TestingCredentialParams;
use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;

#[tokio::test]
async fn test_oidc_issuer_create_token() {
    // GIVEN

    let (context, org, _, identifier, ..) = TestContext::new_with_did(None).await;

    let interaction_id = Uuid::new_v4();
    let data = json!({
        "pre_authorized_code_used": false,
        "access_token_hash": [],
    });
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test-schema",
            &org,
            "NONE",
            TestingCreateSchemaParams::default(),
        )
        .await;

    let interaction = context
        .db
        .interactions
        .create(
            Some(interaction_id),
            &context.config.app.core_base_url,
            &serde_json::to_vec(&data).unwrap(),
            &org,
            InteractionType::Issuance,
        )
        .await;

    context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                interaction: Some(interaction),
                ..TestingCredentialParams::default()
            },
        )
        .await;

    let pre_authorized_code = interaction_id.to_string();
    let resp = context
        .api
        .ssi
        .create_token(credential_schema.id, Some(&pre_authorized_code), None)
        .await;

    assert_eq!(200, resp.status());

    let resp = resp.json_value().await;

    assert_eq!(json!("bearer"), resp["token_type"]);
    assert!(resp.get("access_token").is_some());
    assert!(resp.get("expires_in").is_some());
    assert!(resp.get("refresh_token").is_none());
    assert!(resp.get("refresh_token_expires_in").is_none());
}

#[tokio::test]
async fn test_oidc_issuer_create_token_for_mdoc_creates_refresh_token() {
    // GIVEN

    let (context, org, _, identifier, ..) = TestContext::new_with_did(None).await;

    let interaction_id = Uuid::new_v4();
    let data = json!({
        "pre_authorized_code_used": false,
        "access_token_hash": [],
    });
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test-schema",
            &org,
            "NONE",
            TestingCreateSchemaParams {
                format: Some("MDOC".to_string()),
                schema_type: Some(CredentialSchemaType::Mdoc),
                ..Default::default()
            },
        )
        .await;

    let interaction = context
        .db
        .interactions
        .create(
            Some(interaction_id),
            &context.config.app.core_base_url,
            &serde_json::to_vec(&data).unwrap(),
            &org,
            InteractionType::Issuance,
        )
        .await;

    context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                interaction: Some(interaction),
                ..TestingCredentialParams::default()
            },
        )
        .await;

    let pre_authorized_code = interaction_id.to_string();
    let resp = context
        .api
        .ssi
        .create_token(credential_schema.id, Some(&pre_authorized_code), None)
        .await;

    assert_eq!(200, resp.status());

    let resp = resp.json_value().await;

    assert_eq!(json!("bearer"), resp["token_type"]);
    assert!(resp.get("access_token").is_some());
    assert!(resp.get("expires_in").is_some());
    assert!(resp.get("refresh_token").is_some());
    assert!(resp.get("refresh_token_expires_in").is_some());
}

#[tokio::test]
async fn test_oidc_issuer_create_token_for_refresh_token_grant_updates_both_access_and_refresh_tokens()
 {
    // GIVEN
    let (context, org, _, identifier, ..) = TestContext::new_with_did(None).await;

    let interaction_id = Uuid::new_v4();

    let refresh_token_expires_at = OffsetDateTime::now_utc() + time::Duration::seconds(60);

    let access_token_expires_at = OffsetDateTime::now_utc() + time::Duration::seconds(20);

    let data = json!({
        "pre_authorized_code_used": false,
        "access_token_hash": [],
    });
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test-schema",
            &org,
            "NONE",
            TestingCreateSchemaParams {
                format: Some("MDOC".to_string()),
                schema_type: Some(CredentialSchemaType::Mdoc),
                ..Default::default()
            },
        )
        .await;

    let interaction = context
        .db
        .interactions
        .create(
            Some(interaction_id),
            &context.config.app.core_base_url,
            &serde_json::to_vec(&data).unwrap(),
            &org,
            InteractionType::Issuance,
        )
        .await;

    context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                interaction: Some(interaction),
                ..TestingCredentialParams::default()
            },
        )
        .await;

    let pre_authorized_code = interaction_id.to_string();
    let resp = context
        .api
        .ssi
        .create_token(credential_schema.id, Some(&pre_authorized_code), None)
        .await;

    assert_eq!(200, resp.status());

    let resp = resp.json_value().await;

    assert_eq!(json!("bearer"), resp["token_type"]);

    assert!(resp.get("access_token").is_some());
    assert!(resp["expires_in"].as_i64().unwrap() > access_token_expires_at.unix_timestamp());

    assert!(resp.get("refresh_token").is_some());
    assert!(
        resp["refresh_token_expires_in"].as_i64().unwrap()
            > refresh_token_expires_at.unix_timestamp()
    );
}
