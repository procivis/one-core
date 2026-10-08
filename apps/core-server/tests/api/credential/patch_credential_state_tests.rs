use std::time::Duration;

use one_core::model::credential::{CredentialStateEnum, CredentialType};
use one_core::model::history::HistoryAction;
use one_core::model::revocation_list::{RevocationListEntryState, RevocationListPurpose};
use one_core::proto::transaction_manager::IsolationLevel;
use one_core::repository::DataRepository;
use serde_json::json;
use similar_asserts::assert_eq;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::fixtures::sts::{StsSetup, setup_sts};
use crate::fixtures::{TestingCredentialParams, assert_history_count};
use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;
use crate::utils::db_clients::revocation_lists::TestingRevocationListParams;

fn random_credential_id() -> Uuid {
    Uuid::new_v4()
}

// ---------------------------------------------------------------------------
// Deserialization
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_patch_credential_state_deserializes_all_known_states() {
    // GIVEN a caller with full permissions and a credential id that does not exist
    let context = TestContext::new(None).await;
    let id = random_credential_id();

    for body in [
        json!({"state": "ACCEPTED"}),
        json!({"state": "REVOKED"}),
        json!({"state": "SUSPENDED"}),
        json!({"state": "SUSPENDED", "suspendEndDate": "2023-06-09T14:19:57.000Z"}),
        json!({"state": "EXPIRING"}),
    ] {
        // WHEN
        let resp = context
            .api
            .credentials
            .patch_state(&id, body.clone(), None)
            .await;

        // THEN deserialization succeeded and the request reached the service layer,
        // which reports the (non-existent) credential as not found
        assert_eq!(
            resp.status(),
            404,
            "body {body} should deserialize correctly"
        );
    }
}

#[tokio::test]
async fn test_patch_credential_state_fails_on_unknown_state_value() {
    let context = TestContext::new(None).await;
    let id = random_credential_id();

    let resp = context
        .api
        .credentials
        .patch_state(&id, json!({"state": "NOT_A_REAL_STATE"}), None)
        .await;

    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_patch_credential_state_fails_on_missing_state_tag() {
    let context = TestContext::new(None).await;
    let id = random_credential_id();

    let resp = context
        .api
        .credentials
        .patch_state(&id, json!({}), None)
        .await;

    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_patch_credential_state_fails_on_unknown_field() {
    let context = TestContext::new(None).await;
    let id = random_credential_id();

    // NOTE: deny_unknown_fields only takes effect for the struct-shaped `Suspended` variant here;
    // serde's internally-tagged enum support does not enforce it for unit variants like
    // `Accepted` (see https://github.com/serde-rs/serde/issues/1358) - extra fields sent
    // alongside e.g. `"state": "ACCEPTED"` are currently silently ignored.
    let resp = context
        .api
        .credentials
        .patch_state(
            &id,
            json!({"state": "SUSPENDED", "unexpected": "field"}),
            None,
        )
        .await;

    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_patch_credential_state_fails_on_invalid_suspend_end_date() {
    let context = TestContext::new(None).await;
    let id = random_credential_id();

    let resp = context
        .api
        .credentials
        .patch_state(
            &id,
            json!({"state": "SUSPENDED", "suspendEndDate": "not-a-date"}),
            None,
        )
        .await;

    assert_eq!(resp.status(), 400);
}

// ---------------------------------------------------------------------------
// Permission gate
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_patch_credential_state_fails_forbidden_without_any_state_permission() {
    // GIVEN a caller with a permission unrelated to any credential state transition
    let StsSetup {
        config,
        token,
        mock_server: _mock_server,
    } = setup_sts(vec!["CREDENTIAL_DETAIL"], None).await;
    let context = TestContext::new(Some(config)).await;
    let id = random_credential_id();

    let resp = context
        .api
        .credentials
        .patch_state(&id, json!({"state": "ACCEPTED"}), Some(token))
        .await;

    // THEN the coarse-grained endpoint permission check rejects the request outright
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_patch_credential_state_fails_unauthorized_on_mismatched_permission() {
    // GIVEN a caller who may suspend credentials, but is requesting a state that requires
    // reactivation permission instead
    let StsSetup {
        config,
        token,
        mock_server: _mock_server,
    } = setup_sts(vec!["CREDENTIAL_SUSPEND"], None).await;
    let context = TestContext::new(Some(config)).await;
    let id = random_credential_id();

    let resp = context
        .api
        .credentials
        .patch_state(&id, json!({"state": "ACCEPTED"}), Some(token))
        .await;

    // THEN the caller has a permission from the endpoint's permission list (so the coarse
    // check passes) but not the specific one required for this state (fine-grained check fails)
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_patch_credential_state_allows_accepted_with_reactivate_permission() {
    let StsSetup {
        config,
        token,
        mock_server: _mock_server,
    } = setup_sts(vec!["CREDENTIAL_REACTIVATE"], None).await;
    let context = TestContext::new(Some(config)).await;
    let id = random_credential_id();

    let resp = context
        .api
        .credentials
        .patch_state(&id, json!({"state": "ACCEPTED"}), Some(token))
        .await;

    // THEN the permission gate let the request through to the service, which reports the
    // (non-existent) credential as not found
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_patch_credential_state_allows_suspended_with_suspend_permission() {
    let StsSetup {
        config,
        token,
        mock_server: _mock_server,
    } = setup_sts(vec!["CREDENTIAL_SUSPEND"], None).await;
    let context = TestContext::new(Some(config)).await;
    let id = random_credential_id();

    let resp = context
        .api
        .credentials
        .patch_state(
            &id,
            json!({"state": "SUSPENDED", "suspendEndDate": "2023-06-09T14:19:57.000Z"}),
            Some(token),
        )
        .await;

    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_patch_credential_state_allows_revoked_with_revoke_permission() {
    let StsSetup {
        config,
        token,
        mock_server: _mock_server,
    } = setup_sts(vec!["CREDENTIAL_REVOKE"], None).await;
    let context = TestContext::new(Some(config)).await;
    let id = random_credential_id();

    let resp = context
        .api
        .credentials
        .patch_state(&id, json!({"state": "REVOKED"}), Some(token))
        .await;

    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_patch_credential_state_allows_expiring_with_expire_permission() {
    let StsSetup {
        config,
        token,
        mock_server: _mock_server,
    } = setup_sts(vec!["CREDENTIAL_EXPIRE"], None).await;
    let context = TestContext::new(Some(config)).await;
    let id = random_credential_id();

    let resp = context
        .api
        .credentials
        .patch_state(&id, json!({"state": "EXPIRING"}), Some(token))
        .await;

    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_patch_credential_state_all_permissions_bypasses_fine_grained_check() {
    // GIVEN the default test context, which authenticates via a static token granting
    // every permission (Permissions::All), independent of the endpoint's specific list
    let context = TestContext::new(None).await;
    let id = random_credential_id();

    let resp = context
        .api
        .credentials
        .patch_state(&id, json!({"state": "SUSPENDED"}), None)
        .await;

    assert_eq!(resp.status(), 404);
}

// ---------------------------------------------------------------------------
// state = SUSPENDED
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_patch_credential_state_suspended_with_bitstring_status_list_success() {
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
        .create_credential_entry(revocation_list.id, credential.common().id, 0)
        .await;

    let suspend_end_date_str = "2023-06-09T14:19:57.000Z";
    let suspend_end_date = OffsetDateTime::parse(suspend_end_date_str, &Rfc3339).unwrap();

    // WHEN
    let resp = context
        .api
        .credentials
        .patch_state(
            &credential.common().id,
            json!({"state": "SUSPENDED", "suspendEndDate": suspend_end_date_str}),
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 204);

    let credential = context.db.credentials.get(&credential.common().id).await;
    assert_eq!(
        CredentialStateEnum::Suspended {
            suspend_end_date: Some(suspend_end_date)
        },
        credential.common().state.clone()
    );
    assert_eq!(
        suspend_end_date,
        credential.common().state.suspend_end_date().unwrap()
    );
    assert_history_count(
        &context,
        &credential.common().id.into(),
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
async fn test_patch_credential_state_suspended_fails_when_not_allowed() {
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
        .patch_state(&credential.common().id, json!({"state": "SUSPENDED"}), None)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0162", resp.error_code().await);
}

#[tokio::test]
async fn test_patch_credential_state_suspended_fails_when_expired() {
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
        .patch_state(&credential.common().id, json!({"state": "SUSPENDED"}), None)
        .await;

    // THEN - invalid state transition
    assert_eq!(resp.status(), 400);
    let resp = resp.json_value().await;
    assert_eq!(resp["code"], "BR_0366");

    let credential = context.db.credentials.get(&credential.common().id).await;
    assert_eq!(CredentialStateEnum::Expired, credential.common().state);
}

// ---------------------------------------------------------------------------
// state = ACCEPTED
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_patch_credential_state_accepted_with_bitstring_status_list_success() {
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
            CredentialStateEnum::Suspended {
                suspend_end_date: None,
            },
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
        .create_credential_entry(revocation_list.id, credential.common().id, 0)
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
        .patch_state(&credential.common().id, json!({"state": "ACCEPTED"}), None)
        .await;

    // THEN
    assert_eq!(resp.status(), 204);

    let credential = context.db.credentials.get(&credential.common().id).await;
    assert_eq!(CredentialStateEnum::Accepted, credential.common().state);

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
async fn test_patch_credential_state_accepted_fails_when_expired() {
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
        .patch_state(&credential.common().id, json!({"state": "ACCEPTED"}), None)
        .await;

    // THEN - same error as reactivating a REVOKED credential (invalid state transition)
    assert_eq!(resp.status(), 400);
    let resp = resp.json_value().await;
    assert_eq!(resp["code"], "BR_0366");

    let credential = context.db.credentials.get(&credential.common().id).await;
    assert_eq!(CredentialStateEnum::Expired, credential.common().state);
}

// ---------------------------------------------------------------------------
// state = REVOKED
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_patch_credential_state_revoked_with_bitstring_status_list_success() {
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
    context.db.revocation_lists.create(identifier, None).await;

    // WHEN
    let resp = context
        .api
        .credentials
        .patch_state(&credential.common().id, json!({"state": "REVOKED"}), None)
        .await;

    // THEN
    assert_eq!(resp.status(), 204);

    let credential = context.db.credentials.get(&credential.common().id).await;
    assert_eq!(CredentialStateEnum::Revoked, credential.common().state);
    assert_history_count(
        &context,
        &credential.common().id.into(),
        HistoryAction::Revoked,
        1,
    )
    .await;
}

#[rstest::rstest]
#[tokio::test]
async fn test_patch_credential_state_revoked_with_webhook(
    #[values(false, true)] outer_transaction: bool,
) {
    // GIVEN
    let (context, organisation, _issuer_did, identifier, ..) =
        TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;

    let webhook_url = format!("{}/webhook", context.server_mock.uri());
    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_FINAL1",
            TestingCredentialParams {
                webhook_url: Some(webhook_url.to_string()),
                ..Default::default()
            },
        )
        .await;
    context.db.revocation_lists.create(identifier, None).await;

    let webhook = context
        .server_mock
        .webhook(json!({
            "credentialId": credential.common().id,
            "status": "REVOKED"
        }))
        .await;

    // WHEN
    if outer_transaction {
        let core = core_server::init::initialize_core(&context.config, context.db.db_conn.clone())
            .await
            .unwrap();
        let data = sql_data_provider::DataLayer::build(context.db.db_conn.clone(), vec![]);
        data.get_tx_manager()
            .transaction_with_config(
                Box::pin(async {
                    core.credential_service
                        .patch_credential_state(
                            &credential.common().id,
                            one_core::service::credential::dto::ChangeCredentialStateDTO::Revoked,
                        )
                        .await?;
                    // Keep the outer transaction open after the state update's
                    // nested transaction has finished. Delivery must wait.
                    assert!(
                        tokio::time::timeout(
                            Duration::from_millis(100),
                            webhook.wait_until_satisfied(),
                        )
                        .await
                        .is_err()
                    );
                    assert_eq!(
                        context.db.notifications.list("WEBHOOK_NOTIFY").await.len(),
                        1
                    );
                    Ok(())
                }),
                Some(IsolationLevel::ReadCommitted),
                None,
            )
            .await
            .unwrap()
            .unwrap();
    } else {
        let resp = context
            .api
            .credentials
            .patch_state(&credential.common().id, json!({"state": "REVOKED"}), None)
            .await;
        assert_eq!(resp.status(), 204);
    }

    // THEN: delivered automatically, without running WEBHOOK_NOTIFY.
    tokio::time::timeout(Duration::from_secs(5), webhook.wait_until_satisfied())
        .await
        .expect("Expected REVOKED webhook within 5 seconds");
}

#[tokio::test]
async fn test_patch_credential_state_revoked_fails_when_expired() {
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
        .patch_state(&credential.common().id, json!({"state": "REVOKED"}), None)
        .await;

    // THEN - same error as revoking an already REVOKED credential (invalid state transition)
    assert_eq!(resp.status(), 400);
    let resp = resp.json_value().await;
    assert_eq!(resp["code"], "BR_0366");

    let credential = context.db.credentials.get(&credential.common().id).await;
    assert_eq!(CredentialStateEnum::Expired, credential.common().state);
}

// ---------------------------------------------------------------------------
// Deleted credential (shared across target states: the check happens before
// the state-specific branching, so one representative target state is enough)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_patch_credential_state_fails_credential_deleted() {
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

    // WHEN
    let resp = context
        .api
        .credentials
        .patch_state(&credential.common().id, json!({"state": "REVOKED"}), None)
        .await;

    // THEN
    assert_eq!(resp.status(), 404);
}

// ---------------------------------------------------------------------------
// state = EXPIRING
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_patch_credential_state_expiring_from_accepted_success() {
    // GIVEN a normally valid batch-parent credential - moving to EXPIRING never touches the
    // revocation method (it's a pure state-flag transition), so no revocation list is needed
    // here. Only batch-parent credentials can transition to EXPIRING; for any other type the
    // transition is rejected as an unsupported credential type.
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
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                r#type: Some(CredentialType::BatchParent),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .credentials
        .patch_state(&credential.common().id, json!({"state": "EXPIRING"}), None)
        .await;

    // THEN
    assert_eq!(resp.status(), 204);

    let credential = context.db.credentials.get(&credential.common().id).await;
    assert_eq!(CredentialStateEnum::Expiring, credential.common().state);
    assert_history_count(
        &context,
        &credential.common().id.into(),
        HistoryAction::Expiring,
        1,
    )
    .await;
}

#[tokio::test]
async fn test_patch_credential_state_expiring_from_suspended_success() {
    // GIVEN a batch-parent credential - see test above for why that type is required
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
            CredentialStateEnum::Suspended {
                suspend_end_date: None,
            },
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                r#type: Some(CredentialType::BatchParent),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .credentials
        .patch_state(&credential.common().id, json!({"state": "EXPIRING"}), None)
        .await;

    // THEN
    assert_eq!(resp.status(), 204);

    let credential = context.db.credentials.get(&credential.common().id).await;
    assert_eq!(CredentialStateEnum::Expiring, credential.common().state);
}

#[tokio::test]
async fn test_patch_credential_state_accepted_from_expiring_success() {
    // GIVEN a batch-parent credential already flagged as EXPIRING - moving back to ACCEPTED
    // from this specific state is also a pure state-flag transition (bypasses revocation
    // infra), unlike ACCEPTED from SUSPENDED which goes through the revocation method
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
            CredentialStateEnum::Expiring,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                r#type: Some(CredentialType::BatchParent),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .credentials
        .patch_state(&credential.common().id, json!({"state": "ACCEPTED"}), None)
        .await;

    // THEN
    assert_eq!(resp.status(), 204);

    let credential = context.db.credentials.get(&credential.common().id).await;
    assert_eq!(CredentialStateEnum::Accepted, credential.common().state);
}

#[tokio::test]
async fn test_patch_credential_state_expiring_fails_from_revoked() {
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
            CredentialStateEnum::Revoked,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams::default(),
        )
        .await;

    // WHEN
    let resp = context
        .api
        .credentials
        .patch_state(&credential.common().id, json!({"state": "EXPIRING"}), None)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    let resp = resp.json_value().await;
    assert_eq!(resp["code"], "BR_0366");

    let credential = context.db.credentials.get(&credential.common().id).await;
    assert_eq!(CredentialStateEnum::Revoked, credential.common().state);
}

#[tokio::test]
async fn test_patch_credential_state_revoke_from_expiring_success() {
    // GIVEN an EXPIRING batch parent - EXPIRING is not terminal, so the batch can still be
    // revoked, and its items follow
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;
    let parent = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Expiring,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                r#type: Some(CredentialType::BatchParent),
                ..Default::default()
            },
        )
        .await;
    let item = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                r#type: Some(CredentialType::BatchItem),
                parent_id: Some(parent.common().id),
                ..Default::default()
            },
        )
        .await;
    context.db.revocation_lists.create(identifier, None).await;

    // WHEN
    let resp = context
        .api
        .credentials
        .patch_state(&parent.common().id, json!({"state": "REVOKED"}), None)
        .await;

    // THEN
    assert_eq!(resp.status(), 204);
    assert_eq!(
        CredentialStateEnum::Revoked,
        context
            .db
            .credentials
            .get(&parent.common().id)
            .await
            .common()
            .state
    );
    assert_eq!(
        CredentialStateEnum::Revoked,
        context
            .db
            .credentials
            .get(&item.common().id)
            .await
            .common()
            .state
    );
}

#[tokio::test]
async fn test_patch_credential_state_suspend_from_expiring_success() {
    // GIVEN an EXPIRING batch parent - it can be suspended directly, without first being moved
    // back to ACCEPTED
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;
    let parent = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Expiring,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                r#type: Some(CredentialType::BatchParent),
                ..Default::default()
            },
        )
        .await;
    let item = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                r#type: Some(CredentialType::BatchItem),
                parent_id: Some(parent.common().id),
                ..Default::default()
            },
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
        .create_credential_entry(revocation_list.id, item.common().id, 0)
        .await;

    // WHEN
    let resp = context
        .api
        .credentials
        .patch_state(&parent.common().id, json!({"state": "SUSPENDED"}), None)
        .await;

    // THEN
    assert_eq!(resp.status(), 204);
    assert_eq!(
        CredentialStateEnum::Suspended {
            suspend_end_date: None
        },
        context
            .db
            .credentials
            .get(&parent.common().id)
            .await
            .common()
            .state
    );
    assert_eq!(
        CredentialStateEnum::Suspended {
            suspend_end_date: None
        },
        context
            .db
            .credentials
            .get(&item.common().id)
            .await
            .common()
            .state
    );
}

#[tokio::test]
async fn test_patch_credential_state_suspend_batch_parent_with_already_suspended_item() {
    // GIVEN a batch parent whose items disagree: the parent aggregates its items optimistically,
    // so one suspended item leaves it ACCEPTED. Suspending the batch must re-suspend that item
    // with the new end date rather than fail on it.
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;
    let parent = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                r#type: Some(CredentialType::BatchParent),
                ..Default::default()
            },
        )
        .await;
    let accepted_item = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                r#type: Some(CredentialType::BatchItem),
                parent_id: Some(parent.common().id),
                ..Default::default()
            },
        )
        .await;
    let suspended_item = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Suspended {
                suspend_end_date: Some(
                    OffsetDateTime::parse("2023-06-09T14:19:57.000Z", &Rfc3339).unwrap(),
                ),
            },
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                r#type: Some(CredentialType::BatchItem),
                parent_id: Some(parent.common().id),
                ..Default::default()
            },
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
        .create_credential_entry(revocation_list.id, accepted_item.common().id, 0)
        .await;
    context
        .db
        .revocation_lists
        .create_credential_entry(revocation_list.id, suspended_item.common().id, 1)
        .await;

    let new_end_date_str = "2024-06-09T14:19:57.000Z";
    let new_end_date = OffsetDateTime::parse(new_end_date_str, &Rfc3339).unwrap();

    // WHEN
    let resp = context
        .api
        .credentials
        .patch_state(
            &parent.common().id,
            json!({"state": "SUSPENDED", "suspendEndDate": new_end_date_str}),
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 204);
    for credential_id in [
        parent.common().id,
        accepted_item.common().id,
        suspended_item.common().id,
    ] {
        let credential = context.db.credentials.get(&credential_id).await;
        assert_eq!(
            CredentialStateEnum::Suspended {
                suspend_end_date: Some(new_end_date)
            },
            credential.common().state
        );
        assert_eq!(
            Some(new_end_date),
            credential.common().state.suspend_end_date()
        );
    }
}

#[tokio::test]
async fn test_patch_credential_state_reapplying_the_current_state_is_a_noop() {
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
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams::default(),
        )
        .await;

    // WHEN
    let resp = context
        .api
        .credentials
        .patch_state(&credential.common().id, json!({"state": "ACCEPTED"}), None)
        .await;

    // THEN the call succeeds without moving the credential or recording anything
    assert_eq!(resp.status(), 204);

    let credential = context.db.credentials.get(&credential.common().id).await;
    assert_eq!(CredentialStateEnum::Accepted, credential.common().state);
    assert_history_count(
        &context,
        &credential.common().id.into(),
        HistoryAction::Accepted,
        0,
    )
    .await;
}
