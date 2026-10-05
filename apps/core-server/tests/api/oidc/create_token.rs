use assert2::let_assert;
use futures::future::join_all;
use one_core::error::ErrorCode;
use one_core::model::credential::{CredentialStateEnum, CredentialType, UpdateCredentialRequest};
use one_core::model::credential_schema::{TransactionCode, TransactionCodeType};
use one_core::model::history::{HistoryAction, HistoryMetadata};
use one_core::model::interaction::InteractionType;
use serde_json::json;
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::fixtures::TestingCredentialParams;
use crate::utils::api_clients::ssi::TokenRequest;
use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;
use crate::utils::db_clients::interactions::TestingInteractionParams;
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
        .create("test-schema", &org, TestingCreateSchemaParams::default())
        .await;

    let interaction = context
        .db
        .interactions
        .create(
            &org,
            InteractionType::Issuance,
            TestingInteractionParams {
                id: Some(interaction_id),
                data: Some(serde_json::to_vec(&data).unwrap()),
                ..Default::default()
            },
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
            TokenRequest::PreAuthorizedCode {
                code: pre_authorized_code,
                tx_code: None,
            },
        )
        .await;

    assert_eq!(200, resp.status());

    let resp = resp.json_value().await;

    assert_eq!(json!("Bearer"), resp["token_type"]);
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
        .create("test-schema", &org, TestingCreateSchemaParams::default())
        .await;

    let interaction = context
        .db
        .interactions
        .create(
            &org,
            InteractionType::Issuance,
            TestingInteractionParams {
                id: Some(interaction_id),
                data: Some(serde_json::to_vec(&data).unwrap()),
                ..Default::default()
            },
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
            &org,
            InteractionType::Issuance,
            TestingInteractionParams {
                id: Some(interaction_id),
                data: Some(serde_json::to_vec(&data).unwrap()),
                ..Default::default()
            },
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
            TokenRequest::PreAuthorizedCode {
                code: pre_authorized_code,
                tx_code: None,
            },
        )
        .await;

    assert_eq!(200, resp.status());

    let resp = resp.json_value().await;

    assert_eq!(json!("Bearer"), resp["token_type"]);
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

    let refresh_token_expires_at = one_core::clock::now_utc() + time::Duration::seconds(60);

    let access_token_expires_at = one_core::clock::now_utc() + time::Duration::seconds(20);

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
            &org,
            InteractionType::Issuance,
            TestingInteractionParams {
                id: Some(interaction_id),
                data: Some(serde_json::to_vec(&data).unwrap()),
                ..Default::default()
            },
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
            TokenRequest::PreAuthorizedCode {
                code: pre_authorized_code,
                tx_code: None,
            },
        )
        .await;

    assert_eq!(200, resp.status());

    let resp = resp.json_value().await;

    assert_eq!(json!("Bearer"), resp["token_type"]);

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
            &org,
            InteractionType::Issuance,
            TestingInteractionParams {
                id: Some(interaction_id),
                data: Some(serde_json::to_vec(&data).unwrap()),
                ..Default::default()
            },
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
            TokenRequest::PreAuthorizedCode {
                code: pre_authorized_code,
                tx_code: Some("correct".to_string()),
            },
        )
        .await;

    assert_eq!(200, resp.status());

    let resp = resp.json_value().await;
    resp["token_type"].assert_eq(&"Bearer".to_string());
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
            &org,
            InteractionType::Issuance,
            TestingInteractionParams {
                id: Some(interaction_id),
                data: Some(serde_json::to_vec(&data).unwrap()),
                ..Default::default()
            },
        )
        .await;

    let credential = context
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
            TokenRequest::PreAuthorizedCode {
                code: pre_authorized_code,
                tx_code: Some("wrong".to_string()),
            },
        )
        .await;

    assert_eq!(400, resp.status());

    let resp = resp.json_value().await;
    resp["error"].assert_eq(&"invalid_grant".to_string());

    // invalid tx_code means the issuance failed
    let credential = context.db.credentials.get(&credential.common().id).await;
    assert_eq!(credential.common().state, CredentialStateEnum::Error);

    let history = context
        .db
        .histories
        .get_by_entity_id(&credential.common().id.into())
        .await;
    let errors: Vec<_> = history
        .values
        .into_iter()
        .filter(|entry| entry.action == HistoryAction::Errored)
        .collect();
    let_assert!([entry] = errors.as_slice());
    let_assert!(Some(HistoryMetadata::ErrorMetadata(error)) = &entry.metadata);
    assert_eq!(error.error_code, ErrorCode::BR_0048);
    assert!(error.message.contains("transaction code"));
    assert!(error.message.contains("invalid_grant"));
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
            &org,
            InteractionType::Issuance,
            TestingInteractionParams {
                id: Some(interaction_id),
                data: Some(serde_json::to_vec(&data).unwrap()),
                ..Default::default()
            },
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

#[tokio::test]
async fn test_oidc_issuer_create_token_fails_when_credential_is_expiring() {
    // GIVEN a batch-parent credential that has already transitioned to EXPIRING - fetching (or
    // refreshing) a token for its interaction must be rejected upfront, since none of the
    // credentials tied to that interaction can be (re)issued once one of them is expiring
    let (context, org, _, identifier, ..) = TestContext::new_with_did(None).await;

    let interaction_id = Uuid::new_v4().into();
    let data = json!({
        "pre_authorized_code_used": false,
        "access_token_hash": [],
    });
    let credential_schema = context
        .db
        .credential_schemas
        .create("test-schema", &org, TestingCreateSchemaParams::default())
        .await;

    let interaction = context
        .db
        .interactions
        .create(
            &org,
            InteractionType::Issuance,
            TestingInteractionParams {
                id: Some(interaction_id),
                data: Some(serde_json::to_vec(&data).unwrap()),
                ..Default::default()
            },
        )
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_FINAL1",
            TestingCredentialParams {
                interaction: Some(interaction),
                r#type: Some(CredentialType::BatchParent),
                ..TestingCredentialParams::default()
            },
        )
        .await;

    context
        .db
        .credentials
        .update(
            credential.common().id,
            UpdateCredentialRequest {
                state: Some(CredentialStateEnum::Expiring),
                ..Default::default()
            },
        )
        .await;

    let pre_authorized_code = interaction_id.to_string();
    let resp = context
        .api
        .ssi
        .create_token(
            credential_schema.id,
            TokenRequest::PreAuthorizedCode {
                code: pre_authorized_code,
                tx_code: None,
            },
        )
        .await;

    // THEN
    assert_eq!(400, resp.status());

    let resp = resp.json_value().await;
    assert!(
        resp["error_description"]
            .as_str()
            .is_some_and(|desc| desc.contains("BR_0002")),
        "expected error_description to carry the BR code, got: {resp}"
    );

    let credential = context.db.credentials.get(&credential.common().id).await;
    assert_eq!(credential.common().state, CredentialStateEnum::Expiring);
}
