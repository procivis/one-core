use one_core::model::credential::CredentialStateEnum;

use crate::{fixtures::TestingCredentialParams, utils::context::TestContext};

#[tokio::test]
async fn test_delete_credential_success() {
    // GIVEN
    let context = TestContext::new().await;

    let organisation = context.db.create_organisation().await;
    let did = context.db.create_did(&organisation, None).await;
    let credential_schema = context
        .db
        .create_credential_schema("test", &organisation, "NONE")
        .await;
    let credential = context
        .db
        .create_credential(
            &credential_schema,
            CredentialStateEnum::Created,
            &did,
            "PROCIVIS_TEMPORARY",
            TestingCredentialParams::default(),
        )
        .await;

    let deleted_at = context.db.get_credential(&credential.id).await.deleted_at;
    assert_eq!(None, deleted_at);

    // WHEN
    let resp = context.api_client.delete_credential(credential.id).await;

    // THEN
    assert_eq!(204, resp.status());
    let deleted_at = context.db.get_credential(&credential.id).await.deleted_at;
    assert!(deleted_at.is_some());
}
