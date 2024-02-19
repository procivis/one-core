use one_core::model::credential::CredentialStateEnum;

use crate::fixtures::TestingCredentialParams;
use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_share_credential_success() {
    // GIVEN
    let (context, organisation, did, _) = TestContext::new_with_did().await;
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
            CredentialStateEnum::Created,
            &did,
            "PROCIVIS_TEMPORARY",
            TestingCredentialParams::default(),
        )
        .await;

    // WHEN
    let resp = context.api.credentials.share(&credential.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert!(resp.get("url").is_some());

    let url: String = resp["url"].parse();
    assert!(url.ends_with(
        format!(
            "/ssi/temporary-issuer/v1/connect?protocol={}&credential={}",
            "PROCIVIS_TEMPORARY", credential.id
        )
        .as_str()
    ));

    let credential = context.db.credentials.get(&credential.id).await;
    assert_eq!(
        CredentialStateEnum::Pending,
        credential.state.unwrap()[0].state
    );
}
