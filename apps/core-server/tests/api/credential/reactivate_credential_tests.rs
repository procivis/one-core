use one_core::model::credential::CredentialStateEnum;
use one_core::model::revocation_list::{RevocationListEntryState, RevocationListPurpose};
use similar_asserts::assert_eq;

use crate::fixtures::TestingCredentialParams;
use crate::utils::context::TestContext;
use crate::utils::db_clients::revocation_lists::TestingRevocationListParams;

#[tokio::test]
async fn test_reactivate_credential_with_bitstring_status_list_success() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;
    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Suspended,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams::default(),
        )
        .await;

    let revocation_list = context
        .db
        .revocation_lists
        .create(
            identifier,
            Some(TestingRevocationListParams {
                r#type: Some("BITSTRINGSTATUSLIST".into()),
                purpose: Some(RevocationListPurpose::Suspension),
                ..Default::default()
            }),
        )
        .await;

    context
        .db
        .revocation_lists
        .create_credential_entry(revocation_list.id, credential.common.id, 0)
        .await;

    context
        .db
        .revocation_lists
        .update_entry(
            revocation_list.id,
            0,
            Some(RevocationListEntryState::Revoked),
        )
        .await;

    // WHEN
    let resp = context
        .api
        .credentials
        .reactivate(&credential.common.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 204);

    let credential = context.db.credentials.get(&credential.common.id).await;

    assert_eq!(CredentialStateEnum::Accepted, credential.common.state);

    let revocation_list_entry = context
        .db
        .revocation_lists
        .get_entries(revocation_list.id)
        .await;
    assert_eq!(revocation_list_entry.len(), 1);
    assert_eq!(
        revocation_list_entry[0].state,
        RevocationListEntryState::Active
    );
}

#[tokio::test]
async fn test_reactivate_credential_fails_when_expired() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;
    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Expired,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams::default(),
        )
        .await;

    // WHEN
    let resp = context
        .api
        .credentials
        .reactivate(&credential.common.id)
        .await;

    // THEN - same error as reactivating a REVOKED credential (invalid state transition)
    assert_eq!(resp.status(), 400);
    let resp = resp.json_value().await;
    assert_eq!(resp["code"], "BR_0366");

    let credential = context.db.credentials.get(&credential.common.id).await;
    assert_eq!(CredentialStateEnum::Expired, credential.common.state);
}
