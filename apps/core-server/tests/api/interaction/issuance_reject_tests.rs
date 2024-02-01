use one_core::model::credential::CredentialStateEnum;
use serde_json::json;

use crate::fixtures::TestingCredentialParams;
use crate::utils::context::TestContext;

#[tokio::test]
async fn test_issuance_reject_procivis_temp() {
    // GIVEN
    let (context, organisation, did) = TestContext::new_with_did().await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE")
        .await;
    let interaction = context
        .db
        .interactions
        .create(None, &context.server_mock.uri(), "".as_bytes())
        .await;
    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &did,
            "PROCIVIS_TEMPORARY",
            TestingCredentialParams {
                interaction: Some(interaction.to_owned()),
                ..Default::default()
            },
        )
        .await;

    context.server_mock.ssi_reject().await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_reject(interaction.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 204);

    let states = context
        .db
        .credentials
        .get(&credential.id)
        .await
        .state
        .unwrap();
    assert_eq!(2, states.len());
    assert_eq!(CredentialStateEnum::Rejected, states[0].state);
}

#[tokio::test]
async fn test_issuance_reject_openid4vc() {
    // GIVEN
    let (context, organisation, did) = TestContext::new_with_did().await;
    let holder_did = context
        .db
        .dids
        .create(&organisation, Default::default())
        .await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE")
        .await;

    let interaction_data = serde_json::to_vec(&json!({
        "issuer_url": "http://127.0.0.1",
        "credential_endpoint": format!("{}/credential", context.server_mock.uri()),
        "access_token": "123",
        "access_token_expires_at": null,
    }))
    .unwrap();

    let interaction = context
        .db
        .interactions
        .create(None, &context.server_mock.uri(), &interaction_data)
        .await;
    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &did,
            "OPENID4VC",
            TestingCredentialParams {
                holder_did: Some(holder_did),
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

    let states = context
        .db
        .credentials
        .get(&credential.id)
        .await
        .state
        .unwrap();
    assert_eq!(1, states.len());
    assert_eq!(CredentialStateEnum::Pending, states[0].state);
}
