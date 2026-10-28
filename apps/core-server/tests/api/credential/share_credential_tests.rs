use one_core::model::credential::CredentialStateEnum;
use one_core::model::credential_schema::{TransactionCode, TransactionCodeType};
use one_core::model::interaction::InteractionType;
use serde_json::json;
use similar_asserts::assert_eq;

use crate::fixtures::TestingCredentialParams;
use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;
use crate::utils::db_clients::interactions::TestingInteractionParams;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_share_credential_success() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;
    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Created,
            &identifier,
            "OPENID4VCI_FINAL1",
            TestingCredentialParams::default(),
        )
        .await;

    // WHEN
    let resp = context.api.credentials.share(&credential.common().id).await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;

    assert!(resp.get("url").is_some());
    let url: String = resp["url"].parse();
    assert!(url.starts_with("openid-credential-offer"));

    assert!(resp.get("transactionCode").is_none());

    let credential = context.db.credentials.get(&credential.common().id).await;
    assert_eq!(CredentialStateEnum::Pending, credential.common().state);
}

#[tokio::test]
async fn test_share_credential_replaces_interaction_with_used_nonces() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;
    let interaction = context
        .db
        .interactions
        .create(
            &organisation,
            InteractionType::Issuance,
            TestingInteractionParams {
                data: Some(
                    serde_json::to_vec(&json!({
                        "pre_authorized_code_used": true,
                        "access_token_hash": [],
                    }))
                    .unwrap(),
                ),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .interactions
        .mark_nonce_as_used(&interaction.id)
        .await;
    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::InteractionExpired,
            &identifier,
            "OPENID4VCI_FINAL1",
            TestingCredentialParams {
                interaction: Some(interaction.clone()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.credentials.share(&credential.common().id).await;

    // THEN
    assert_eq!(resp.status(), 201);
    assert!(context.db.interactions.get(interaction.id).await.is_none());
    let credential = context.db.credentials.get(&credential.common().id).await;
    assert_eq!(CredentialStateEnum::Pending, credential.common().state);
}

#[tokio::test]
async fn test_share_credential_failed_deleted_credential() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;
    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Created,
            &identifier,
            "OPENID4VCI_FINAL1",
            TestingCredentialParams {
                deleted_at: Some(one_core::clock::now_utc()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.credentials.share(&credential.common().id).await;

    // THEN
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_share_credential_fails_when_expired() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;
    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Expired,
            &identifier,
            "OPENID4VCI_FINAL1",
            TestingCredentialParams::default(),
        )
        .await;

    // WHEN
    let resp = context.api.credentials.share(&credential.common().id).await;

    // THEN - same error as sharing an already REVOKED credential (invalid state)
    assert_eq!(resp.status(), 400);
    let resp = resp.json_value().await;
    assert_eq!(resp["code"], "BR_0002");
}

#[tokio::test]
async fn test_share_credential_with_tx_code() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            TestingCreateSchemaParams {
                transaction_code: Some(TransactionCode {
                    r#type: TransactionCodeType::Numeric,
                    length: 4,
                    description: None,
                }),
                ..Default::default()
            },
        )
        .await;
    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Created,
            &identifier,
            "OPENID4VCI_FINAL1",
            TestingCredentialParams::default(),
        )
        .await;

    // WHEN
    let resp = context.api.credentials.share(&credential.common().id).await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;

    assert!(resp.get("url").is_some());
    let url: String = resp["url"].parse();
    assert!(url.starts_with("openid-credential-offer"));

    assert!(resp.get("transactionCode").is_some());
    let tx_code: String = resp["transactionCode"].parse();
    assert_eq!(tx_code.len(), 4);

    let credential = context.db.credentials.get(&credential.common().id).await;
    assert_eq!(CredentialStateEnum::Pending, credential.common().state);
}
