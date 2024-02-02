use one_core::model::credential::CredentialStateEnum;

use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;
use ct_codecs::{Base64UrlSafeNoPadding, Encoder};

#[tokio::test]
async fn test_create_credential_success() {
    // GIVEN
    let (context, organisation, did) = TestContext::new_with_did().await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE")
        .await;
    let claim_id = credential_schema.claim_schemas.unwrap()[0].schema.id;

    // WHEN
    let resp = context
        .api
        .credentials
        .create(credential_schema.id, "OPENID4VC", did.id, claim_id, "foo")
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;

    let credential = context.db.credentials.get(&resp["id"].parse()).await;
    assert_eq!(
        CredentialStateEnum::Created,
        credential.state.unwrap()[0].state
    );
    assert_eq!(1, credential.claims.unwrap().len());
    assert_eq!("OPENID4VC", credential.transport);
}

#[tokio::test]
async fn test_create_credential_with_big_picture_success() {
    // GIVEN
    let (context, organisation, did) = TestContext::new_with_did().await;
    let credential_schema = context
        .db
        .credential_schemas
        .create_with_picture_claim("test", &organisation)
        .await;

    let claim_id = credential_schema.claim_schemas.unwrap()[0].schema.id;

    let data = Base64UrlSafeNoPadding::encode_to_string(vec![0; 4 * 1024 * 1024]).unwrap();

    // WHEN
    let resp = context
        .api
        .credentials
        .create(
            credential_schema.id,
            "OPENID4VC",
            did.id,
            claim_id,
            format!("data:image/png;base64,{data}"),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;

    let credential = context.db.credentials.get(&resp["id"].parse()).await;
    assert_eq!(
        CredentialStateEnum::Created,
        credential.state.unwrap()[0].state
    );
    assert_eq!(1, credential.claims.unwrap().len());
    assert_eq!("OPENID4VC", credential.transport);
}
