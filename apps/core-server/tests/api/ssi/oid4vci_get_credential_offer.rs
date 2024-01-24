use one_core::{
    model::credential::CredentialStateEnum,
    provider::transport_protocol::openid4vc::dto::OpenID4VCICredentialOfferDTO,
};
use uuid::Uuid;

use crate::{fixtures::TestingCredentialParams, utils::context::TestContext};

#[tokio::test]
async fn test_get_credential_offer_success() {
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
        .create("http://test.com", "NONE".as_bytes())
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
    let offer: OpenID4VCICredentialOfferDTO = resp.json().await;

    assert_eq!(
        offer.credential_issuer,
        format!(
            "{}/ssi/oidc-issuer/v1/{}",
            context.config.app.core_base_url, credential_schema.id
        )
    );
    assert_eq!(
        offer.grants.code.pre_authorized_code,
        interaction.id.to_string()
    );
    let offer_credential = &offer.credentials[0];
    assert_eq!(offer_credential.format, "jwt_vc_json");

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
