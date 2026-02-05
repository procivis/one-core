use futures::future::join_all;
use one_core::model::credential::CredentialStateEnum;
use one_core::model::credential_schema::{TransactionCode, TransactionCodeType};
use one_core::model::interaction::InteractionType;
use serde_json::json;
use similar_asserts::assert_eq;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::fixtures::TestingCredentialParams;
use crate::utils::api_clients::ssi::TokenRequest;
use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_oidc_issuer_create_token() {
    // GIVEN

    let (context, org, _, identifier, ..) = TestContext::new_with_did(None).await;

    let interaction_id = Uuid::new_v4().into();
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
            None,
            TestingCreateSchemaParams::default(),
        )
        .await;

    let interaction = context
        .db
        .interactions
        .create(
            Some(interaction_id),
            &serde_json::to_vec(&data).unwrap(),
            &org,
            InteractionType::Issuance,
            None,
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
        .create_token(
            credential_schema.id,
            "draft-13",
            TokenRequest::PreAuthorizedCode {
                code: pre_authorized_code,
                tx_code: None,
            },
        )
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
async fn test_oidc_issuer_create_token_parallel_collision() {
    // GIVEN
    let (context, org, _, identifier, ..) = TestContext::new_with_did(None).await;

    let interaction_id = Uuid::new_v4().into();
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
            None,
            TestingCreateSchemaParams::default(),
        )
        .await;

    let interaction = context
        .db
        .interactions
        .create(
            Some(interaction_id),
            &serde_json::to_vec(&data).unwrap(),
            &org,
            InteractionType::Issuance,
            None,
        )
        .await;

    context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &identifier,
            "OPENID4VCI_FINAL1",
            TestingCredentialParams {
                interaction: Some(interaction),
                ..TestingCredentialParams::default()
            },
        )
        .await;

    let pre_authorized_code = interaction_id.to_string();
    let mut multiple_attempts = vec![];
    for _ in 0..2 {
        multiple_attempts.push(context.api.ssi.create_token(
            credential_schema.id,
            "final-1.0",
            TokenRequest::PreAuthorizedCode {
                code: pre_authorized_code.to_owned(),
                tx_code: None,
            },
        ));
    }
    let results = join_all(multiple_attempts).await;
    // one attempt must succeed
    assert!(results.iter().any(|resp| resp.status() == 200));
    // one attempt must fail
    assert!(results.iter().any(|resp| resp.status() == 400));
}

#[tokio::test]
async fn test_oidc_issuer_create_token_for_mdoc_creates_refresh_token() {
    // GIVEN

    let (context, org, _, identifier, ..) = TestContext::new_with_did(None).await;

    let interaction_id = Uuid::new_v4().into();
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
            None,
            TestingCreateSchemaParams {
                format: Some("MDOC".into()),
                ..Default::default()
            },
        )
        .await;

    let interaction = context
        .db
        .interactions
        .create(
            Some(interaction_id),
            &serde_json::to_vec(&data).unwrap(),
            &org,
            InteractionType::Issuance,
            None,
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
        .create_token(
            credential_schema.id,
            "draft-13",
            TokenRequest::PreAuthorizedCode {
                code: pre_authorized_code,
                tx_code: None,
            },
        )
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

    let interaction_id = Uuid::new_v4().into();

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
            None,
            TestingCreateSchemaParams {
                format: Some("MDOC".into()),
                ..Default::default()
            },
        )
        .await;

    let interaction = context
        .db
        .interactions
        .create(
            Some(interaction_id),
            &serde_json::to_vec(&data).unwrap(),
            &org,
            InteractionType::Issuance,
            None,
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
        .create_token(
            credential_schema.id,
            "draft-13",
            TokenRequest::PreAuthorizedCode {
                code: pre_authorized_code,
                tx_code: None,
            },
        )
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

#[tokio::test]
async fn test_oidc_issuer_create_token_with_tx_code_success() {
    // GIVEN
    let (context, org, _, identifier, ..) = TestContext::new_with_did(None).await;

    let interaction_id = Uuid::new_v4().into();

    let data = json!({
        "pre_authorized_code_used": false,
        "access_token_hash": [],
        "transaction_code": "correct"
    });
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test-schema",
            &org,
            None,
            TestingCreateSchemaParams {
                transaction_code: Some(TransactionCode {
                    r#type: TransactionCodeType::Alphanumeric,
                    length: 7,
                    description: None,
                }),
                ..Default::default()
            },
        )
        .await;

    let interaction = context
        .db
        .interactions
        .create(
            Some(interaction_id),
            &serde_json::to_vec(&data).unwrap(),
            &org,
            InteractionType::Issuance,
            None,
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
        .create_token(
            credential_schema.id,
            "draft-13",
            TokenRequest::PreAuthorizedCode {
                code: pre_authorized_code,
                tx_code: Some("correct".to_string()),
            },
        )
        .await;

    assert_eq!(200, resp.status());

    let resp = resp.json_value().await;
    resp["token_type"].assert_eq(&"bearer".to_string());
    assert!(resp.get("access_token").is_some());
    assert!(resp.get("expires_in").is_some());
}

#[tokio::test]
async fn test_oidc_issuer_create_token_wrong_tx_code() {
    // GIVEN
    let (context, org, _, identifier, ..) = TestContext::new_with_did(None).await;

    let interaction_id = Uuid::new_v4().into();

    let data = json!({
        "pre_authorized_code_used": false,
        "access_token_hash": [],
        "transaction_code": "correct"
    });
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test-schema",
            &org,
            None,
            TestingCreateSchemaParams {
                transaction_code: Some(TransactionCode {
                    r#type: TransactionCodeType::Alphanumeric,
                    length: 7,
                    description: None,
                }),
                ..Default::default()
            },
        )
        .await;

    let interaction = context
        .db
        .interactions
        .create(
            Some(interaction_id),
            &serde_json::to_vec(&data).unwrap(),
            &org,
            InteractionType::Issuance,
            None,
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
        .create_token(
            credential_schema.id,
            "draft-13",
            TokenRequest::PreAuthorizedCode {
                code: pre_authorized_code,
                tx_code: Some("wrong".to_string()),
            },
        )
        .await;

    assert_eq!(400, resp.status());

    let resp = resp.json_value().await;
    resp["error"].assert_eq(&"invalid_grant".to_string());
}

#[tokio::test]
async fn test_oidc_issuer_create_token_tx_code_missing() {
    // GIVEN
    let (context, org, _, identifier, ..) = TestContext::new_with_did(None).await;

    let interaction_id = Uuid::new_v4().into();

    let data = json!({
        "pre_authorized_code_used": false,
        "access_token_hash": [],
        "transaction_code": "correct"
    });
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test-schema",
            &org,
            None,
            TestingCreateSchemaParams {
                transaction_code: Some(TransactionCode {
                    r#type: TransactionCodeType::Alphanumeric,
                    length: 7,
                    description: None,
                }),
                ..Default::default()
            },
        )
        .await;

    let interaction = context
        .db
        .interactions
        .create(
            Some(interaction_id),
            &serde_json::to_vec(&data).unwrap(),
            &org,
            InteractionType::Issuance,
            None,
        )
        .await;

    context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &identifier,
            "OPENID4VCI_FINAL1",
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
        .create_token(
            credential_schema.id,
            "final-1.0",
            TokenRequest::PreAuthorizedCode {
                code: pre_authorized_code,
                tx_code: None,
            },
        )
        .await;

    assert_eq!(400, resp.status());

    let resp = resp.json_value().await;
    resp["error"].assert_eq(&"invalid_request".to_string());
}
