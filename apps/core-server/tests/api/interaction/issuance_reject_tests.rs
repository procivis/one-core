use one_core::model::credential::CredentialStateEnum;
use one_core::model::interaction::InteractionType;
use serde_json::json;
use similar_asserts::assert_eq;

use crate::fixtures::{TestingCredentialParams, encrypted_token};
use crate::utils::context::TestContext;

#[tokio::test]
async fn test_issuance_reject_openid4vci_draft13_notification_not_supported_by_issuer() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;

    let interaction_data = serde_json::to_vec(&json!({
        "issuer_url": "http://127.0.0.1",
        "credential_endpoint": format!("{}/credential", context.server_mock.uri()),
        "access_token": encrypted_token("123"),
        "access_token_expires_at": null,
    }))
    .unwrap();

    let interaction = context
        .db
        .interactions
        .create(
            None,
            &interaction_data,
            &organisation,
            InteractionType::Issuance,
        )
        .await;
    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                interaction: Some(interaction.to_owned()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_reject(interaction.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 204);

    let credential = context.db.credentials.get(&credential.id).await;
    assert_eq!(CredentialStateEnum::Rejected, credential.state);
}

#[tokio::test]
async fn test_issuance_reject_openid4vci_draft13_with_notification() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;

    let interaction_data = serde_json::to_vec(&json!({
        "issuer_url": "http://127.0.0.1",
        "credential_endpoint": format!("{}/ssi/openid4vci/draft-13/{}/credential", context.server_mock.uri(), credential_schema.id),
        "access_token": encrypted_token("123"),
        "access_token_expires_at": null,
        "token_endpoint": format!("{}/ssi/openid4vci/draft-13/{}/token", context.server_mock.uri(), credential_schema.id),
        "grants":{
            "urn:ietf:params:oauth:grant-type:pre-authorized_code":{
                "pre-authorized_code":"76f2355d-c9cb-4db6-8779-2f3b81062f8e"
            }
        },
        "notification_endpoint": format!("{}/ssi/openid4vci/draft-13/{}/notification", context.server_mock.uri(), credential_schema.id),
        "notification_id": "notification_id"
    }))
    .unwrap();

    let interaction = context
        .db
        .interactions
        .create(
            None,
            &interaction_data,
            &organisation,
            InteractionType::Issuance,
        )
        .await;
    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                interaction: Some(interaction.to_owned()),
                ..Default::default()
            },
        )
        .await;

    context
        .server_mock
        .token_endpoint(credential_schema.schema_id, "123")
        .await;

    context
        .server_mock
        .ssi_notification_endpoint(credential_schema.id, "notification_id", "123", 1)
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_reject(interaction.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 204);

    let credential = context.db.credentials.get(&credential.id).await;
    assert_eq!(CredentialStateEnum::Rejected, credential.state);
}
