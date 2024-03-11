use crate::fixtures::{TestingCredentialParams, TestingDidParams};
use crate::utils::context::TestContext;
use crate::utils::db_clients::keys::eddsa_testing_params;
use one_core::model::credential::CredentialStateEnum;
use one_core::model::did::{KeyRole, RelatedKey};

#[tokio::test]
async fn test_reactivate_credential_with_bitstring_status_list_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    let key = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
        .await;
    let issuer_did = context
        .db
        .dids
        .create(
            &organisation,
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key,
                }]),
                ..Default::default()
            },
        )
        .await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "BITSTRINGSTATUSLIST")
        .await;
    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Suspended,
            &issuer_did,
            "PROCIVIS_TEMPORARY",
            TestingCredentialParams::default(),
        )
        .await;
    // WHEN
    let resp = context.api.credentials.reactivate(&credential.id).await;

    // THEN
    assert_eq!(resp.status(), 204);

    let credential = context.db.credentials.get(&credential.id).await;

    assert_eq!(
        CredentialStateEnum::Accepted,
        credential.state.unwrap()[0].state
    );
}
