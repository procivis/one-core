use one_core::model::credential::CredentialStateEnum;
use uuid::Uuid;

use crate::{
    fixtures::TestingCredentialParams,
    utils::{context::TestContext, field_match::FieldHelpers},
};

#[tokio::test]
async fn test_get_credential_offer_success() {
    // GIVEN
    let (context, organisation, did, _) = TestContext::new_with_did().await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;

    let interaction = context
        .db
        .interactions
        .create(None, "http://test.com", "NONE".as_bytes())
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
                interaction: Some(interaction.to_owned()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .ssi
        .get_credential_offer(credential_schema.id, credential.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let offer = resp.json_value().await;

    assert_eq!(
        offer["credential_issuer"],
        format!(
            "{}/ssi/oidc-issuer/v1/{}",
            context.config.app.core_base_url, credential_schema.id
        )
    );
    offer["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"]
        .assert_eq(&interaction.id);

    let offer_credential = &offer["credentials"][0];
    assert_eq!(offer_credential["format"], "jwt_vc_json");
    assert_eq!(offer_credential["wallet_storage_type"], "SOFTWARE");

    let credential = context.db.credentials.get(&credential.id).await;
    assert_eq!(
        CredentialStateEnum::Pending,
        credential.state.unwrap()[0].state
    );
}

#[tokio::test]
async fn test_get_credential_offer_not_found() {
    // GIVEN
    let context = TestContext::new().await;

    // WHEN
    let resp = context
        .api
        .ssi
        .get_credential_offer(Uuid::new_v4(), Uuid::new_v4())
        .await;

    // THEN
    assert_eq!(resp.status(), 404);
}
