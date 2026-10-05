use one_core::model::credential::CredentialStateEnum;
use one_core::model::history::HistoryAction;
use one_core::model::revocation_list::{RevocationListEntryState, RevocationListPurpose};
use similar_asserts::assert_eq;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::fixtures::{TestingCredentialParams, assert_history_count};
use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;
use crate::utils::db_clients::revocation_lists::TestingRevocationListParams;

#[tokio::test]
async fn test_suspend_credential_with_bitstring_status_list_success() {
    // GIVEN
    let (context, organisation, _issuer_did, identifier, ..) =
        TestContext::new_with_did(None).await;
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
            CredentialStateEnum::Accepted,
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

    let suspend_end_date_str = "2023-06-09T14:19:57.000Z";
    let suspend_end_date = OffsetDateTime::parse(suspend_end_date_str, &Rfc3339).unwrap();
    // WHEN
    let resp = context
        .api
        .credentials
        .suspend(
            &credential.common.id,
            Some(suspend_end_date_str.to_string()),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 204);

    let credential = context.db.credentials.get(&credential.common.id).await;

    assert_eq!(
        CredentialStateEnum::Suspended,
        credential.common.state.clone()
    );

    assert_eq!(suspend_end_date, credential.suspend_end_date.unwrap());
    assert_history_count(
        &context,
        &credential.common.id.into(),
        HistoryAction::Suspended,
        1,
    )
    .await;

    let revocation_list_entry = context
        .db
        .revocation_lists
        .get_entries(revocation_list.id)
        .await;
    assert_eq!(revocation_list_entry.len(), 1);
    assert_eq!(
        revocation_list_entry[0].state,
        RevocationListEntryState::Suspended
    );
}

#[tokio::test]
async fn test_suspend_credential_with_none_fails() {
    // GIVEN
    let (context, organisation, _issuer_did, identifier, ..) =
        TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            TestingCreateSchemaParams {
                allow_suspension: Some(false),
                ..Default::default()
            },
        )
        .await;
    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams::default(),
        )
        .await;
    context.db.revocation_lists.create(identifier, None).await;
    // WHEN
    let resp = context
        .api
        .credentials
        .suspend(&credential.common.id, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0162", resp.error_code().await);
}

#[tokio::test]
async fn test_suspend_credential_fails_credential_deleted() {
    // GIVEN
    let (context, organisation, _issuer_did, identifier, ..) =
        TestContext::new_with_did(None).await;
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
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                deleted_at: Some(one_core::clock::now_utc()),
                ..Default::default()
            },
        )
        .await;
    context.db.revocation_lists.create(identifier, None).await;
    let suspend_end_date_str = "2023-06-09T14:19:57.000Z";
    // WHEN
    let resp = context
        .api
        .credentials
        .suspend(
            &credential.common.id,
            Some(suspend_end_date_str.to_string()),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_suspend_credential_fails_when_expired() {
    // GIVEN
    let (context, organisation, _issuer_did, identifier, ..) =
        TestContext::new_with_did(None).await;
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
        .suspend(&credential.common.id, None)
        .await;

    // THEN - same error as suspending an already REVOKED credential (invalid state transition)
    assert_eq!(resp.status(), 400);
    let resp = resp.json_value().await;
    assert_eq!(resp["code"], "BR_0366");

    let credential = context.db.credentials.get(&credential.common.id).await;
    assert_eq!(CredentialStateEnum::Expired, credential.common.state);
}
