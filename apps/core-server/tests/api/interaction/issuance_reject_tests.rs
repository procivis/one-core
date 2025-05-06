use one_core::model::credential::CredentialStateEnum;
use serde_json::json;

use crate::fixtures::{encrypted_token, TestingCredentialParams};
use crate::utils::context::TestContext;

#[tokio::test]
async fn test_issuance_reject_openid4vc() {
    // GIVEN
    let (context, organisation, did, identifier, ..) = TestContext::new_with_did(None).await;

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
            &context.server_mock.uri(),
            &interaction_data,
            &organisation,
        )
        .await;
    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &did,
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
    assert_eq!(resp.status(), 500);

    assert_eq!(CredentialStateEnum::Pending, credential.state);
}
