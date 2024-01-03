use one_core::model::credential::CredentialStateEnum;

use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;

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
        .create(credential_schema.id, "OPENID4VC", did.id, claim_id)
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
