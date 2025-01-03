use one_core::model::credential::CredentialStateEnum;

use crate::fixtures::TestingCredentialParams;
use crate::utils::context::TestContext;

#[tokio::test]
async fn test_delete_credential_success() {
    // GIVEN
    let (context, organisation, did, _) = TestContext::new_with_did().await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;
    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Created,
            &did,
            "OPENID4VC",
            TestingCredentialParams::default(),
        )
        .await;

    let deleted_at = context.db.credentials.get(&credential.id).await.deleted_at;
    assert_eq!(None, deleted_at);

    // WHEN
    let resp = context.api.credentials.delete(&credential.id).await;

    // THEN
    assert_eq!(204, resp.status());
    let deleted_at = context.db.credentials.get(&credential.id).await.deleted_at;
    assert!(deleted_at.is_some());
}
