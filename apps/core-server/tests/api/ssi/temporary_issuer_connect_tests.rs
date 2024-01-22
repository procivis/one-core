use one_core::model::credential::CredentialStateEnum;

use crate::{
    fixtures::TestingCredentialParams,
    utils::{context::TestContext, field_match::FieldHelpers},
};

#[tokio::test]
async fn test_temporary_issuer_connect_success() {
    // GIVEN
    let (context, organisation, did) = TestContext::new_with_did().await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE")
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &did,
            "PROCIVIS_TEMPORARY",
            TestingCredentialParams::default(),
        )
        .await;

    // WHEN
    let resp = context.api.ssi.temporary_connect(credential.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp["id"].assert_eq(&credential.id);
    resp["schema"]["id"].assert_eq(&credential_schema.id);
    assert_eq!("PENDING", resp["state"]);
    assert_eq!("test", resp["claims"][0]["value"]);
    assert_eq!("ISSUER", resp["role"]);

    let credential = context.db.credentials.get(&credential.id).await;
    assert_eq!(
        CredentialStateEnum::Offered,
        credential.state.unwrap()[0].state
    );
}
