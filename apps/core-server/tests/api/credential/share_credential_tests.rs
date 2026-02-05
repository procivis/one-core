use one_core::model::credential::CredentialStateEnum;
use one_core::model::credential_schema::{TransactionCode, TransactionCodeType};
use similar_asserts::assert_eq;
use time::OffsetDateTime;

use crate::fixtures::TestingCredentialParams;
use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_share_credential_success() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, None, Default::default())
        .await;
    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Created,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams::default(),
        )
        .await;

    // WHEN
    let resp = context.api.credentials.share(&credential.id).await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;

    assert!(resp.get("url").is_some());
    let url: String = resp["url"].parse();
    assert!(url.starts_with("openid-credential-offer"));

    assert!(resp.get("transactionCode").is_none());

    let credential = context.db.credentials.get(&credential.id).await;
    assert_eq!(CredentialStateEnum::Pending, credential.state);
}

#[tokio::test]
async fn test_share_credential_failed_deleted_credential() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, None, Default::default())
        .await;
    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Created,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                deleted_at: Some(OffsetDateTime::now_utc()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.credentials.share(&credential.id).await;

    // THEN
    assert_eq!(resp.status(), 404);
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
            None,
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
    let resp = context.api.credentials.share(&credential.id).await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;

    assert!(resp.get("url").is_some());
    let url: String = resp["url"].parse();
    assert!(url.starts_with("openid-credential-offer"));

    assert!(resp.get("transactionCode").is_some());
    let tx_code: String = resp["transactionCode"].parse();
    assert_eq!(tx_code.len(), 4);

    let credential = context.db.credentials.get(&credential.id).await;
    assert_eq!(CredentialStateEnum::Pending, credential.state);
}
