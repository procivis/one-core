use std::ops::Sub;

use axum::http::Method;
use one_core::model::blob::BlobType;
use one_core::model::certificate::CertificateState;
use one_core::model::credential::{CredentialRole, CredentialStateEnum};
use one_core::model::did::{DidType, KeyRole, RelatedKey};
use one_core::model::history::{HistoryAction, HistoryEntityType};
use one_core::model::identifier::{IdentifierState, IdentifierType};
use one_core::model::interaction::InteractionType;
use one_core::model::proof::ProofStateEnum;
use one_core::model::revocation_list::RevocationListPurpose;
use one_core::proto::jwt::mapper::{bin_to_b64url_string, string_to_b64url_string};
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::eddsa::Eddsa;
use one_core::provider::task::certificate_check::dto::CertificateCheckResultDTO;
use one_crypto::Signer;
use one_crypto::signer::eddsa::{EDDSASigner, KeyPair};
use serde_json::json;
use similar_asserts::assert_eq;
use sql_data_provider::test_utilities::get_dummy_date;
use time::Duration;
use uuid::Uuid;
use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::fixtures::interaction::{InteractionDataParams, dummy_interaction_data};
use crate::fixtures::{TestingCredentialParams, TestingDidParams, TestingIdentifierParams};
use crate::utils::context::TestContext;
use crate::utils::db_clients::blobs::TestingBlobParams;
use crate::utils::db_clients::certificates::TestingCertificateParams;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;
use crate::utils::db_clients::histories::TestingHistoryParams;
use crate::utils::db_clients::keys::eddsa_testing_params;
use crate::utils::db_clients::notifications::TestingNotificationParams;
use crate::utils::db_clients::proof_schemas::{CreateProofClaim, CreateProofInputSchema};
use crate::utils::db_clients::revocation_lists::TestingRevocationListParams;

#[tokio::test]
async fn test_run_task_lifecycle_check_no_update() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context.api.tasks.run("LIFECYCLE_CHECK").await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["totalReactivationChecks"], 0);
    assert_eq!(
        resp["reactivatedCredentialIds"].as_array().unwrap().len(),
        0
    );
    assert_eq!(resp["totalExpirationChecks"], 0);
    assert_eq!(resp["expiredCredentialIds"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_run_task_lifecycle_check_reactivates_suspended() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;

    let a_while_ago = one_core::clock::now_utc().sub(Duration::seconds(1));

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Suspended,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                suspend_end_date: Some(a_while_ago),
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
                purpose: Some(RevocationListPurpose::Suspension),
                r#type: Some("BITSTRINGSTATUSLIST".into()),
                ..Default::default()
            }),
        )
        .await;

    context
        .db
        .revocation_lists
        .create_credential_entry(revocation_list.id, credential.id, 0)
        .await;

    // WHEN
    let resp = context.api.tasks.run("LIFECYCLE_CHECK").await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["totalReactivationChecks"], 1);
    let credentials = resp["reactivatedCredentialIds"]
        .as_array()
        .unwrap()
        .to_owned();
    assert_eq!(credentials.len(), 1);
    assert_eq!(
        credentials.first().unwrap().as_str().unwrap(),
        credential.id.to_string()
    );

    let credential = context.db.credentials.get(&credential.id).await;
    assert_eq!(credential.state, CredentialStateEnum::Accepted);
    assert_eq!(credential.suspend_end_date, None);
}

#[tokio::test]
async fn test_run_task_lifecycle_check_expires_single_credential_both_roles() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;

    let a_while_ago = one_core::clock::now_utc().sub(Duration::seconds(1));

    let issuer_credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                role: Some(CredentialRole::Issuer),
                expires_at: Some(a_while_ago),
                ..Default::default()
            },
        )
        .await;

    let holder_credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                role: Some(CredentialRole::Holder),
                expires_at: Some(a_while_ago),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.tasks.run("LIFECYCLE_CHECK").await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    let expired_ids: Vec<String> = resp["expiredCredentialIds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(expired_ids.contains(&issuer_credential.id.to_string()));
    assert!(expired_ids.contains(&holder_credential.id.to_string()));

    let issuer_credential = context.db.credentials.get(&issuer_credential.id).await;
    assert_eq!(issuer_credential.state, CredentialStateEnum::Expired);
    let holder_credential = context.db.credentials.get(&holder_credential.id).await;
    assert_eq!(holder_credential.state, CredentialStateEnum::Expired);
}

/// Non-terminal states beyond `Accepted`/`Suspended` (e.g. `Offered`, still awaiting the holder's
/// acceptance) are eligible for expiry too, per `CredentialStateEnum::non_terminal_states`.
#[tokio::test]
async fn test_run_task_lifecycle_check_expires_non_accepted_non_terminal_credential() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;

    let a_while_ago = one_core::clock::now_utc().sub(Duration::seconds(1));

    let offered_credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Offered,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                role: Some(CredentialRole::Holder),
                expires_at: Some(a_while_ago),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.tasks.run("LIFECYCLE_CHECK").await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    let expired_ids: Vec<String> = resp["expiredCredentialIds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(expired_ids.contains(&offered_credential.id.to_string()));

    let offered_credential = context.db.credentials.get(&offered_credential.id).await;
    assert_eq!(offered_credential.state, CredentialStateEnum::Expired);
}

/// Terminal states (e.g. `Revoked`) are never touched by the lifecycle check, even with a past
/// `expires_at`.
#[tokio::test]
async fn test_run_task_lifecycle_check_does_not_expire_terminal_state_credential() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;

    let a_while_ago = one_core::clock::now_utc().sub(Duration::seconds(1));

    let revoked_credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Revoked,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                role: Some(CredentialRole::Holder),
                expires_at: Some(a_while_ago),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.tasks.run("LIFECYCLE_CHECK").await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    let expired_ids: Vec<String> = resp["expiredCredentialIds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(!expired_ids.contains(&revoked_credential.id.to_string()));

    let revoked_credential = context.db.credentials.get(&revoked_credential.id).await;
    assert_eq!(revoked_credential.state, CredentialStateEnum::Revoked);
}

#[tokio::test]
async fn test_run_task_lifecycle_check_does_not_expire_mdoc() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            TestingCreateSchemaParams {
                format: Some("MDOC".into()),
                ..Default::default()
            },
        )
        .await;

    let a_while_ago = one_core::clock::now_utc().sub(Duration::seconds(1));

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_FINAL1",
            TestingCredentialParams {
                role: Some(CredentialRole::Holder),
                expires_at: Some(a_while_ago),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.tasks.run("LIFECYCLE_CHECK").await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    let expired_ids: Vec<String> = resp["expiredCredentialIds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(!expired_ids.contains(&credential.id.to_string()));

    let credential = context.db.credentials.get(&credential.id).await;
    assert_eq!(credential.state, CredentialStateEnum::Accepted);
}

/// A batch parent's own items no longer decide its fate: as long as its own `expires_at` is in
/// the future and the shared refresh token is still valid, it stays valid - even once every
/// item has individually expired.
#[tokio::test]
async fn test_run_task_lifecycle_check_batch_parent_stays_valid_when_refresh_token_valid() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            TestingCreateSchemaParams {
                batch_size: Some(2),
                ..Default::default()
            },
        )
        .await;

    let a_while_ago = one_core::clock::now_utc().sub(Duration::seconds(1));
    let far_in_the_future = one_core::clock::now_utc() + Duration::days(365);

    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams {
            refresh_token_expired: false,
            ..Default::default()
        },
    );
    let interaction = context
        .db
        .interactions
        .create(
            None,
            &interaction_data,
            &organisation,
            InteractionType::Issuance,
            None,
        )
        .await;

    let parent_credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                r#type: Some(one_core::model::credential::CredentialType::BatchParent),
                role: Some(CredentialRole::Holder),
                expires_at: Some(far_in_the_future),
                interaction: Some(interaction.clone()),
                ..Default::default()
            },
        )
        .await;

    let expired_item = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                r#type: Some(one_core::model::credential::CredentialType::BatchItem),
                parent_id: Some(parent_credential.id),
                role: Some(CredentialRole::Holder),
                expires_at: Some(a_while_ago),
                interaction: Some(interaction.clone()),
                ..Default::default()
            },
        )
        .await;

    let other_item = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                r#type: Some(one_core::model::credential::CredentialType::BatchItem),
                parent_id: Some(parent_credential.id),
                role: Some(CredentialRole::Holder),
                expires_at: Some(a_while_ago),
                interaction: Some(interaction.clone()),
                ..Default::default()
            },
        )
        .await;

    // WHEN - every item is individually expired, but the parent's own `expires_at` is still in
    // the future and the shared refresh token is still valid
    let resp = context.api.tasks.run("LIFECYCLE_CHECK").await;

    // THEN - the items transition to EXPIRED, but the parent stays ACCEPTED (still renewable)
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    let expired_ids: Vec<String> = resp["expiredCredentialIds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(expired_ids.contains(&expired_item.id.to_string()));
    assert!(expired_ids.contains(&other_item.id.to_string()));
    assert!(!expired_ids.contains(&parent_credential.id.to_string()));

    let updated_parent = context.db.credentials.get(&parent_credential.id).await;
    assert_eq!(updated_parent.state, CredentialStateEnum::Accepted);
}

/// The parent's own business-level `expires_at` is authoritative once every item has also
/// individually expired: it's EXPIRED regardless of the refresh token still being valid.
#[tokio::test]
async fn test_run_task_lifecycle_check_batch_parent_expires_when_own_expires_at_passed() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            TestingCreateSchemaParams {
                batch_size: Some(2),
                ..Default::default()
            },
        )
        .await;

    let a_while_ago = one_core::clock::now_utc().sub(Duration::seconds(1));

    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams {
            refresh_token_expired: false,
            ..Default::default()
        },
    );
    let interaction = context
        .db
        .interactions
        .create(
            None,
            &interaction_data,
            &organisation,
            InteractionType::Issuance,
            None,
        )
        .await;

    let parent_credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                r#type: Some(one_core::model::credential::CredentialType::BatchParent),
                role: Some(CredentialRole::Holder),
                expires_at: Some(a_while_ago),
                interaction: Some(interaction.clone()),
                ..Default::default()
            },
        )
        .await;

    let expired_item = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                r#type: Some(one_core::model::credential::CredentialType::BatchItem),
                parent_id: Some(parent_credential.id),
                role: Some(CredentialRole::Holder),
                expires_at: Some(a_while_ago),
                interaction: Some(interaction.clone()),
                ..Default::default()
            },
        )
        .await;

    // WHEN - the item, and the parent's own `expires_at`, have both passed, even though the
    // refresh token is still valid
    let resp = context.api.tasks.run("LIFECYCLE_CHECK").await;

    // THEN - the parent becomes EXPIRED
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    let expired_ids: Vec<String> = resp["expiredCredentialIds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(expired_ids.contains(&parent_credential.id.to_string()));
    assert!(expired_ids.contains(&expired_item.id.to_string()));

    let updated_parent = context.db.credentials.get(&parent_credential.id).await;
    assert_eq!(updated_parent.state, CredentialStateEnum::Expired);
    let updated_expired_item = context.db.credentials.get(&expired_item.id).await;
    assert_eq!(updated_expired_item.state, CredentialStateEnum::Expired);
}

/// A batch parent with no items at all (e.g. all items were deleted, or it was never populated)
/// must still be able to expire based on its own `expires_at`/refresh token - "all items expired"
/// is vacuously true when there are no items to block it.
#[tokio::test]
async fn test_run_task_lifecycle_check_batch_parent_expires_with_no_items() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            TestingCreateSchemaParams {
                batch_size: Some(2),
                ..Default::default()
            },
        )
        .await;

    let a_while_ago = one_core::clock::now_utc().sub(Duration::seconds(1));

    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams {
            refresh_token_expired: false,
            ..Default::default()
        },
    );
    let interaction = context
        .db
        .interactions
        .create(
            None,
            &interaction_data,
            &organisation,
            InteractionType::Issuance,
            None,
        )
        .await;

    let parent_credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                r#type: Some(one_core::model::credential::CredentialType::BatchParent),
                role: Some(CredentialRole::Holder),
                expires_at: Some(a_while_ago),
                interaction: Some(interaction.clone()),
                ..Default::default()
            },
        )
        .await;
    // deliberately no batch items created for this parent

    // WHEN
    let resp = context.api.tasks.run("LIFECYCLE_CHECK").await;

    // THEN - the parent still expires based on its own `expires_at`
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    let expired_ids: Vec<String> = resp["expiredCredentialIds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(expired_ids.contains(&parent_credential.id.to_string()));

    let updated_parent = context.db.credentials.get(&parent_credential.id).await;
    assert_eq!(updated_parent.state, CredentialStateEnum::Expired);
}

/// The shared refresh token can expire the parent sooner than its own `expires_at`, as long as
/// every item has also individually expired: a batch is dead the moment it can no longer be
/// renewed, even if the business expiry hasn't been reached.
#[tokio::test]
async fn test_run_task_lifecycle_check_batch_parent_expires_when_refresh_token_expired_before_own_expires_at()
 {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            TestingCreateSchemaParams {
                batch_size: Some(2),
                ..Default::default()
            },
        )
        .await;

    let a_while_ago = one_core::clock::now_utc().sub(Duration::seconds(1));
    let far_in_the_future = one_core::clock::now_utc() + Duration::days(365);

    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams {
            refresh_token_expired: true,
            ..Default::default()
        },
    );
    let interaction = context
        .db
        .interactions
        .create(
            None,
            &interaction_data,
            &organisation,
            InteractionType::Issuance,
            None,
        )
        .await;

    let parent_credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                r#type: Some(one_core::model::credential::CredentialType::BatchParent),
                role: Some(CredentialRole::Holder),
                expires_at: Some(far_in_the_future),
                interaction: Some(interaction.clone()),
                ..Default::default()
            },
        )
        .await;

    let expired_item = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                r#type: Some(one_core::model::credential::CredentialType::BatchItem),
                parent_id: Some(parent_credential.id),
                role: Some(CredentialRole::Holder),
                expires_at: Some(a_while_ago),
                interaction: Some(interaction.clone()),
                ..Default::default()
            },
        )
        .await;

    // WHEN - the item is individually expired, the parent's own `expires_at` is still far away,
    // but the shared refresh token has already expired
    let resp = context.api.tasks.run("LIFECYCLE_CHECK").await;

    // THEN - the parent becomes EXPIRED anyway (it can no longer be renewed)
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    let expired_ids: Vec<String> = resp["expiredCredentialIds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(expired_ids.contains(&parent_credential.id.to_string()));
    assert!(expired_ids.contains(&expired_item.id.to_string()));

    let updated_parent = context.db.credentials.get(&parent_credential.id).await;
    assert_eq!(updated_parent.state, CredentialStateEnum::Expired);
    let updated_expired_item = context.db.credentials.get(&expired_item.id).await;
    assert_eq!(updated_expired_item.state, CredentialStateEnum::Expired);
}

/// The parent is never expired while any item is still individually valid, even once its own
/// `expires_at` has passed and the refresh token has expired.
#[tokio::test]
async fn test_run_task_lifecycle_check_batch_parent_stays_valid_when_not_all_items_expired() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            TestingCreateSchemaParams {
                batch_size: Some(2),
                ..Default::default()
            },
        )
        .await;

    let a_while_ago = one_core::clock::now_utc().sub(Duration::seconds(1));

    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams {
            refresh_token_expired: true,
            ..Default::default()
        },
    );
    let interaction = context
        .db
        .interactions
        .create(
            None,
            &interaction_data,
            &organisation,
            InteractionType::Issuance,
            None,
        )
        .await;

    let parent_credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                r#type: Some(one_core::model::credential::CredentialType::BatchParent),
                role: Some(CredentialRole::Holder),
                expires_at: Some(a_while_ago),
                interaction: Some(interaction.clone()),
                ..Default::default()
            },
        )
        .await;

    let expired_item = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                r#type: Some(one_core::model::credential::CredentialType::BatchItem),
                parent_id: Some(parent_credential.id),
                role: Some(CredentialRole::Holder),
                expires_at: Some(a_while_ago),
                interaction: Some(interaction.clone()),
                ..Default::default()
            },
        )
        .await;

    let valid_item = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                r#type: Some(one_core::model::credential::CredentialType::BatchItem),
                parent_id: Some(parent_credential.id),
                role: Some(CredentialRole::Holder),
                interaction: Some(interaction.clone()),
                ..Default::default()
            },
        )
        .await;

    // WHEN - the parent's own `expires_at` has passed and the refresh token has expired, but
    // one item is still individually valid
    let resp = context.api.tasks.run("LIFECYCLE_CHECK").await;

    // THEN - only the expired item transitions; the parent stays ACCEPTED
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    let expired_ids: Vec<String> = resp["expiredCredentialIds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(expired_ids.contains(&expired_item.id.to_string()));
    assert!(!expired_ids.contains(&parent_credential.id.to_string()));
    assert!(!expired_ids.contains(&valid_item.id.to_string()));

    let updated_parent = context.db.credentials.get(&parent_credential.id).await;
    assert_eq!(updated_parent.state, CredentialStateEnum::Accepted);
    let updated_valid_item = context.db.credentials.get(&valid_item.id).await;
    assert_eq!(updated_valid_item.state, CredentialStateEnum::Accepted);
}

/// Batch items for all batch parents are fetched together in one query and grouped locally by
/// parent id - this exercises that grouping across multiple parents in the same task run, making
/// sure items never get attributed to the wrong parent.
#[tokio::test]
async fn test_run_task_lifecycle_check_batch_parents_items_are_not_cross_attributed() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            TestingCreateSchemaParams {
                batch_size: Some(2),
                ..Default::default()
            },
        )
        .await;

    let a_while_ago = one_core::clock::now_utc().sub(Duration::seconds(1));
    let far_in_the_future = one_core::clock::now_utc() + Duration::days(365);

    let expiring_interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams {
            refresh_token_expired: false,
            ..Default::default()
        },
    );
    let expiring_interaction = context
        .db
        .interactions
        .create(
            None,
            &expiring_interaction_data,
            &organisation,
            InteractionType::Issuance,
            None,
        )
        .await;

    // parent A: own `expires_at` has passed, its only item has too -> both expire
    let parent_a = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                r#type: Some(one_core::model::credential::CredentialType::BatchParent),
                role: Some(CredentialRole::Holder),
                expires_at: Some(a_while_ago),
                interaction: Some(expiring_interaction.clone()),
                ..Default::default()
            },
        )
        .await;
    let parent_a_item = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                r#type: Some(one_core::model::credential::CredentialType::BatchItem),
                parent_id: Some(parent_a.id),
                role: Some(CredentialRole::Holder),
                expires_at: Some(a_while_ago),
                interaction: Some(expiring_interaction.clone()),
                ..Default::default()
            },
        )
        .await;

    let valid_interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams {
            refresh_token_expired: false,
            ..Default::default()
        },
    );
    let valid_interaction = context
        .db
        .interactions
        .create(
            None,
            &valid_interaction_data,
            &organisation,
            InteractionType::Issuance,
            None,
        )
        .await;

    // parent B: own `expires_at` is in the future and its item hasn't expired -> stays valid
    let parent_b = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                r#type: Some(one_core::model::credential::CredentialType::BatchParent),
                role: Some(CredentialRole::Holder),
                expires_at: Some(far_in_the_future),
                interaction: Some(valid_interaction.clone()),
                ..Default::default()
            },
        )
        .await;
    let parent_b_item = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                r#type: Some(one_core::model::credential::CredentialType::BatchItem),
                parent_id: Some(parent_b.id),
                role: Some(CredentialRole::Holder),
                expires_at: Some(far_in_the_future),
                interaction: Some(valid_interaction.clone()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.tasks.run("LIFECYCLE_CHECK").await;

    // THEN - parent A and its item expire, parent B and its item are untouched
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    let expired_ids: Vec<String> = resp["expiredCredentialIds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(expired_ids.contains(&parent_a.id.to_string()));
    assert!(expired_ids.contains(&parent_a_item.id.to_string()));
    assert!(!expired_ids.contains(&parent_b.id.to_string()));
    assert!(!expired_ids.contains(&parent_b_item.id.to_string()));

    let updated_parent_a = context.db.credentials.get(&parent_a.id).await;
    assert_eq!(updated_parent_a.state, CredentialStateEnum::Expired);
    let updated_parent_a_item = context.db.credentials.get(&parent_a_item.id).await;
    assert_eq!(updated_parent_a_item.state, CredentialStateEnum::Expired);

    let updated_parent_b = context.db.credentials.get(&parent_b.id).await;
    assert_eq!(updated_parent_b.state, CredentialStateEnum::Accepted);
    let updated_parent_b_item = context.db.credentials.get(&parent_b_item.id).await;
    assert_eq!(updated_parent_b_item.state, CredentialStateEnum::Accepted);
}

/// A batch item that's already in any terminal state (e.g. `Revoked`) is just as "done" as one
/// that's `Expired` - it must not permanently block the parent from expiring once every other
/// item has also finished (expired or otherwise terminated).
#[tokio::test]
async fn test_run_task_lifecycle_check_batch_parent_expires_when_item_revoked_not_just_expired() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            TestingCreateSchemaParams {
                batch_size: Some(2),
                ..Default::default()
            },
        )
        .await;

    let a_while_ago = one_core::clock::now_utc().sub(Duration::seconds(1));

    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams {
            refresh_token_expired: false,
            ..Default::default()
        },
    );
    let interaction = context
        .db
        .interactions
        .create(
            None,
            &interaction_data,
            &organisation,
            InteractionType::Issuance,
            None,
        )
        .await;

    let parent_credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                r#type: Some(one_core::model::credential::CredentialType::BatchParent),
                role: Some(CredentialRole::Holder),
                expires_at: Some(a_while_ago),
                interaction: Some(interaction.clone()),
                ..Default::default()
            },
        )
        .await;

    // already revoked - never going to become `Expired`, but is just as "done"
    let revoked_item = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Revoked,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                r#type: Some(one_core::model::credential::CredentialType::BatchItem),
                parent_id: Some(parent_credential.id),
                role: Some(CredentialRole::Holder),
                interaction: Some(interaction.clone()),
                ..Default::default()
            },
        )
        .await;

    let expired_item = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                r#type: Some(one_core::model::credential::CredentialType::BatchItem),
                parent_id: Some(parent_credential.id),
                role: Some(CredentialRole::Holder),
                expires_at: Some(a_while_ago),
                interaction: Some(interaction.clone()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.tasks.run("LIFECYCLE_CHECK").await;

    // THEN - the parent expires: the revoked item doesn't count as "still remaining"
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    let expired_ids: Vec<String> = resp["expiredCredentialIds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(expired_ids.contains(&parent_credential.id.to_string()));
    assert!(expired_ids.contains(&expired_item.id.to_string()));
    assert!(!expired_ids.contains(&revoked_item.id.to_string()));

    let updated_parent = context.db.credentials.get(&parent_credential.id).await;
    assert_eq!(updated_parent.state, CredentialStateEnum::Expired);
    let updated_expired_item = context.db.credentials.get(&expired_item.id).await;
    assert_eq!(updated_expired_item.state, CredentialStateEnum::Expired);
    // untouched - still `Revoked`, not overwritten with `Expired`
    let updated_revoked_item = context.db.credentials.get(&revoked_item.id).await;
    assert_eq!(updated_revoked_item.state, CredentialStateEnum::Revoked);
}

#[tokio::test]
async fn test_run_retain_proof_check_no_update() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context.api.tasks.run("RETAIN_PROOF_CHECK").await;

    // THEN
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_run_retain_proof_check_with_update() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;

    let claim_schema = &credential_schema.claim_schemas.as_ref().await.unwrap()[0];

    let proof_schema = context
        .db
        .proof_schemas
        .create(
            "test",
            &organisation,
            vec![CreateProofInputSchema {
                claims: vec![CreateProofClaim {
                    id: claim_schema.id,
                    key: &claim_schema.key,
                    required: true,
                    data_type: &claim_schema.data_type,
                    array: false,
                }],
                credential_schema: &credential_schema,
            }],
        )
        .await;

    let verifier_key = context
        .db
        .keys
        .create(&organisation, Default::default())
        .await;

    let did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: verifier_key.to_owned(),
                    reference: "1".to_string(),
                }]),
                ..Default::default()
            },
        )
        .await;
    let identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let credential_1_blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some(vec![1, 2, 3, 4, 5]),
            r#type: Some(BlobType::Credential),
            ..Default::default()
        })
        .await;

    let credential_2_blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some(vec![1, 2, 3, 4, 5]),
            r#type: Some(BlobType::Credential),
            ..Default::default()
        })
        .await;

    let other_blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some(vec![5, 4, 3, 2, 1]),
            r#type: Some(BlobType::Credential),
            ..Default::default()
        })
        .await;

    let credential_1 = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Created,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                credential_blob_id: Some(credential_1_blob.id),
                ..Default::default()
            },
        )
        .await;

    let credential_2 = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Created,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                credential_blob_id: Some(credential_2_blob.id),
                ..Default::default()
            },
        )
        .await;

    let proof_blob_1 = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some(vec![1, 2, 3, 4, 5]),
            r#type: Some(BlobType::Proof),
            ..Default::default()
        })
        .await;

    let proof_blob_2 = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some(vec![1, 2, 3, 4, 5]),
            r#type: Some(BlobType::Proof),
            ..Default::default()
        })
        .await;

    let proof_1 = context
        .db
        .proofs
        .create(
            None,
            &identifier,
            Some(&proof_schema),
            ProofStateEnum::Accepted,
            "OPENID4VP_DRAFT20",
            None,
            verifier_key.clone(),
            Some(proof_blob_1.id),
            None,
        )
        .await;

    let proof_2 = context
        .db
        .proofs
        .create(
            None,
            &identifier,
            Some(&proof_schema),
            ProofStateEnum::Created,
            "OPENID4VP_DRAFT20",
            None,
            verifier_key,
            Some(proof_blob_2.id),
            None,
        )
        .await;

    context
        .db
        .histories
        .create(
            &organisation,
            TestingHistoryParams {
                action: Some(HistoryAction::Accepted),
                created_date: Some(get_dummy_date()),
                entity_id: Some(proof_1.id.into()),
                entity_type: Some(HistoryEntityType::Proof),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .histories
        .create(
            &organisation,
            TestingHistoryParams {
                action: Some(HistoryAction::Created),
                created_date: Some(get_dummy_date()),
                entity_id: Some(proof_2.id.into()),
                entity_type: Some(HistoryEntityType::Proof),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .proofs
        .set_proof_claims(
            &proof_1.id,
            credential_1.claims.as_ref().await.unwrap().to_owned(),
        )
        .await;

    context
        .db
        .proofs
        .set_proof_claims(
            &proof_2.id,
            credential_2.claims.as_ref().await.unwrap().to_owned(),
        )
        .await;

    let credential_1 = context.db.credentials.get(&credential_1.id).await;
    assert!(
        !credential_1
            .claims
            .as_ref()
            .await
            .unwrap()
            .to_owned()
            .is_empty()
    );

    let credential_2 = context.db.credentials.get(&credential_2.id).await;
    assert!(
        !credential_2
            .claims
            .as_ref()
            .await
            .unwrap()
            .to_owned()
            .is_empty()
    );

    // WHEN
    let resp = context.api.tasks.run("RETAIN_PROOF_CHECK").await;

    // THEN
    assert_eq!(resp.status(), 200);

    let proof = context.db.proofs.get(&proof_1.id).await;
    assert!(proof.claims.as_ref().await.unwrap().is_empty());

    let credential = context.db.credentials.get(&credential_1.id).await;
    assert!(
        credential
            .claims
            .as_ref()
            .await
            .unwrap()
            .to_owned()
            .is_empty()
    );

    let get_credential_blob = context.db.blobs.get(&credential_1_blob.id).await;
    assert!(get_credential_blob.is_none());

    let get_proof_blob = context.db.blobs.get(&proof_blob_1.id).await;
    assert!(get_proof_blob.is_none());

    let proof = context.db.proofs.get(&proof_2.id).await;
    assert!(!proof.claims.as_ref().await.unwrap().is_empty());

    let credential = context.db.credentials.get(&credential_2.id).await;
    assert!(
        !credential
            .claims
            .as_ref()
            .await
            .unwrap()
            .to_owned()
            .is_empty()
    );

    let get_credential_blob = context.db.blobs.get(&credential_2_blob.id).await;
    assert!(get_credential_blob.is_some());

    let get_proof_blob = context.db.blobs.get(&proof_blob_2.id).await;
    assert!(get_proof_blob.is_some());

    let get_other_blob = context.db.blobs.get(&other_blob.id).await;
    assert!(get_other_blob.is_some());
}

#[tokio::test]
async fn test_run_task_certificate_check_with_update() {
    // GIVEN
    let (context, organisation, _, _, key) = TestContext::new_with_did(None).await;

    let ok_identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                r#type: Some(IdentifierType::Certificate),
                state: Some(IdentifierState::Active),
                ..Default::default()
            },
        )
        .await;

    let ok_certificate = context
        .db
        .certificates
        .create(
            ok_identifier.id,
            organisation.clone(),
            TestingCertificateParams {
                state: Some(CertificateState::Active),
                expiry_date: Some(
                    one_core::clock::now_utc()
                        .checked_add(Duration::hours(1))
                        .unwrap(),
                ),
                key: Some(key.clone()),
                ..Default::default()
            },
        )
        .await;

    let identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                r#type: Some(IdentifierType::Certificate),
                state: Some(IdentifierState::Active),
                ..Default::default()
            },
        )
        .await;

    let expired_certificate = context
        .db
        .certificates
        .create(
            identifier.id,
            organisation.clone(),
            TestingCertificateParams {
                state: Some(CertificateState::Active),
                expiry_date: Some(one_core::clock::now_utc().sub(Duration::hours(1))),
                key: Some(key),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.tasks.run("CERTIFICATE_CHECK").await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    let result: CertificateCheckResultDTO = serde_json::from_value(resp).unwrap();

    assert_eq!(result.expired_certificate_ids.len(), 1);
    assert_eq!(result.expired_certificate_ids[0], expired_certificate.id);
    assert_eq!(result.deactivated_identifier_ids.len(), 1);
    assert_eq!(result.deactivated_identifier_ids[0], identifier.id);
    assert_eq!(result.revoked_certificate_ids.len(), 0);
    assert_eq!(result.check_failures.len(), 1);
    assert_eq!(result.check_failures[0].certificate_id, ok_certificate.id);

    let expired_certificate = context.db.certificates.get(expired_certificate.id).await;
    assert_eq!(expired_certificate.state, CertificateState::Expired);

    let identifier = context.db.identifiers.get(identifier.id).await;
    assert_eq!(identifier.state, IdentifierState::Deactivated);

    let certificate_history = context
        .db
        .histories
        .get_by_entity_id(&expired_certificate.id.into())
        .await;
    assert!(
        certificate_history
            .values
            .iter()
            .any(|history| history.action == HistoryAction::Expired)
    );

    let identifier_history = context
        .db
        .histories
        .get_by_entity_id(&identifier.id.into())
        .await;
    assert!(
        identifier_history
            .values
            .iter()
            .any(|history| history.action == HistoryAction::Deactivated)
    );
}

#[tokio::test]
async fn test_run_task_holder_check_credential_status_with_params_none_existing_organisation() {
    // GIVEN
    let key_pair = EDDSASigner::generate_key_pair();
    let issuer_did = format!(
        "did:key:{}",
        Eddsa
            .reconstruct_key(&key_pair.public, None, None)
            .unwrap()
            .signature()
            .unwrap()
            .public()
            .as_multibase()
            .unwrap()
    );

    let mock_server = MockServer::builder().start().await;
    let base_url = mock_server.uri();
    let jwt_header = json!({
      "alg": "EDDSA",
      "typ": "JWT"
    });
    let credential_payload = json!({
      "iat": 1707409689,
      "exp": 1770481689,
      "nbf": 1707409629,
      "iss": issuer_did,
      "sub": "did:key:z6MkhhtucZ67S8yAvHPoJtMVx28z3BfcPN1gpjfni5DT7qSe",
      "jti": "88fb9ad2-efe0-4ade-8251-2b39786490af",
      "vc": {
        "@context": [
          "https://www.w3.org/2018/credentials/v1"
        ],
        "type": [
          "VerifiableCredential"
        ],
        "id": format!("{base_url}/api/credential/v1/2880d8dd-ce3f-4d74-b463-a2c0da07a5cf"),
        "credentialSubject": {
          "age": "55"
        }
      }
    });

    let credential_jwt = sign_jwt_helper(
        &jwt_header.to_string(),
        &credential_payload.to_string(),
        &key_pair,
    );

    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let holder_key = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
        .await;

    let holder_did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                did_method: Some("KEY".into()),
                did: Some(
                    "did:key:z6MkktrwmJpuMHHkkqY3g5xUP6KKB1eXxLo6KZDZ5LpfBhrc"
                        .parse()
                        .unwrap(),
                ),
                did_type: Some(DidType::Local),
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key: holder_key,
                    reference: "1".to_string(),
                }]),
                ..Default::default()
            },
        )
        .await;
    let holder_identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(holder_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(holder_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;
    let issuer_did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                did_method: Some("KEY".into()),
                did: Some(
                    "did:key:z6MkhhtucZ67S8yAvHPoJtMVx28z3BfcPN1gpjfni5DT7qSe"
                        .parse()
                        .unwrap(),
                ),
                did_type: Some(DidType::Remote),
                ..Default::default()
            },
        )
        .await;
    let issuer_identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(issuer_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(issuer_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;

    let blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some(credential_jwt.as_bytes().to_vec()),
            ..Default::default()
        })
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Suspended,
            &issuer_identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                credential_blob_id: Some(blob.id),
                holder_identifier: Some(holder_identifier),
                role: Some(CredentialRole::Holder),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .revocation_lists
        .create(issuer_identifier, None)
        .await;

    let history_previous = context
        .db
        .histories
        .get_by_entity_id(&credential.id.into())
        .await;

    let non_existing_organisation_id = Uuid::new_v4();
    let params = json!({ "organisationId": non_existing_organisation_id });

    // WHEN
    let resp = context
        .api
        .tasks
        .run_with_params("HOLDER_CHECK_CREDENTIAL_STATUS", params)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert_eq!(json!(0), resp["totalChecks"]);

    let history = context
        .db
        .histories
        .get_by_entity_id(&credential.id.into())
        .await;
    // no new history entry should be added
    assert_eq!(history.values.len(), history_previous.values.len());
}

fn sign_jwt_helper(jwt_header_json: &str, payload_json: &str, key_pair: &KeyPair) -> String {
    let mut token = format!(
        "{}.{}",
        string_to_b64url_string(jwt_header_json).unwrap(),
        string_to_b64url_string(payload_json).unwrap(),
    );

    let signature = EDDSASigner {}
        .sign(token.as_bytes(), &key_pair.public, &key_pair.private)
        .unwrap();
    let signature_encoded = bin_to_b64url_string(&signature).unwrap();

    token.push('.');
    token.push_str(&signature_encoded);
    token
}

#[tokio::test]
async fn test_run_interaction_expiration_check_no_update() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context.api.tasks.run("INTERACTION_EXPIRATION_CHECK").await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert_eq!(resp["updatedCredentials"].as_array().unwrap().len(), 0);
    assert_eq!(resp["updatedProofs"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_run_interaction_expiration_check_with_update() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;

    let claim_schema = &credential_schema.claim_schemas.as_ref().await.unwrap()[0];

    let proof_schema = context
        .db
        .proof_schemas
        .create(
            "test",
            &organisation,
            vec![CreateProofInputSchema {
                claims: vec![CreateProofClaim {
                    id: claim_schema.id,
                    key: &claim_schema.key,
                    required: true,
                    data_type: &claim_schema.data_type,
                    array: false,
                }],
                credential_schema: &credential_schema,
            }],
        )
        .await;

    let key = context
        .db
        .keys
        .create(&organisation, Default::default())
        .await;
    let did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: key.to_owned(),
                    reference: "1".to_string(),
                }]),
                ..Default::default()
            },
        )
        .await;
    let identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let proof_interaction = context
        .db
        .interactions
        .create(
            None,
            &[],
            &organisation,
            InteractionType::Verification,
            Some(one_core::clock::now_utc()),
        )
        .await;
    let proof = context
        .db
        .proofs
        .create(
            None,
            &identifier,
            Some(&proof_schema),
            ProofStateEnum::Pending,
            "OPENID4VP_DRAFT20",
            Some(&proof_interaction),
            key,
            None,
            None,
        )
        .await;

    let credential_interaction = context
        .db
        .interactions
        .create(
            None,
            &[],
            &organisation,
            InteractionType::Issuance,
            Some(one_core::clock::now_utc()),
        )
        .await;
    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &identifier,
            "OPENID4VCI_FINAL1",
            TestingCredentialParams {
                interaction: Some(credential_interaction),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.tasks.run("INTERACTION_EXPIRATION_CHECK").await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    let updated_credentials = resp["updatedCredentials"].as_array().unwrap();
    assert_eq!(updated_credentials.len(), 1);
    assert_eq!(updated_credentials[0], credential.id.to_string());

    let updated_proofs = resp["updatedProofs"].as_array().unwrap();
    assert_eq!(updated_proofs.len(), 1);
    assert_eq!(updated_proofs[0], proof.id.to_string());

    let credential_history = context
        .db
        .histories
        .get_by_entity_id(&credential.id.into())
        .await;
    assert_eq!(credential_history.total_items, 1);
    assert_eq!(
        credential_history.values[0].action,
        HistoryAction::InteractionExpired
    );

    let proof_history = context
        .db
        .histories
        .get_by_entity_id(&proof.id.into())
        .await;
    assert_eq!(proof_history.total_items, 1);
    assert_eq!(
        proof_history.values[0].action,
        HistoryAction::InteractionExpired
    );
}

#[tokio::test]
async fn test_run_webhook_notify_no_data() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context.api.tasks.run("WEBHOOK_NOTIFY").await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert_eq!(resp["delivered"].as_array().unwrap().len(), 0);
    assert_eq!(resp["failed"].as_array().unwrap().len(), 0);
    assert_eq!(resp["rescheduled"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_run_webhook_notify_delivery_rescheduled() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let notification = context
        .db
        .notifications
        .create(
            organisation.id,
            TestingNotificationParams {
                // not responding URL will reschedule the notification
                url: Some("https://invalid.endpoint/notify".to_string()),
                r#type: Some("WEBHOOK_NOTIFY".into()),
                next_try_date: Some(one_core::clock::now_utc()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.tasks.run("WEBHOOK_NOTIFY").await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert_eq!(resp["delivered"].as_array().unwrap().len(), 0);
    let rescheduled = resp["rescheduled"].as_array().unwrap();
    assert_eq!(rescheduled.len(), 1);
    assert_eq!(
        rescheduled[0].as_str().unwrap(),
        notification.id.to_string()
    );
    assert_eq!(resp["failed"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_run_webhook_notify_last_retry() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let notification = context
        .db
        .notifications
        .create(
            organisation.id,
            TestingNotificationParams {
                // not responding URL will cause rescheduling
                url: Some("https://invalid.endpoint/notify".to_string()),
                // maximum retries reached
                tries_count: Some(4),
                r#type: Some("WEBHOOK_NOTIFY".into()),
                next_try_date: Some(one_core::clock::now_utc()),
                history_target: Some("history-target".to_string()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.tasks.run("WEBHOOK_NOTIFY").await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert_eq!(resp["delivered"].as_array().unwrap().len(), 0);
    let failed = resp["failed"].as_array().unwrap();
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0].as_str().unwrap(), notification.id.to_string());
    assert_eq!(resp["rescheduled"].as_array().unwrap().len(), 0);

    // notification removed
    assert!(
        context
            .db
            .notifications
            .get(&notification.id)
            .await
            .is_none()
    );

    let history = context
        .db
        .histories
        .get_by_entity_id(&notification.id.into())
        .await;
    assert_eq!(history.values.len(), 1);
    let history = &history.values[0];
    assert_eq!(history.entity_type, HistoryEntityType::Notification);
    assert_eq!(history.action, HistoryAction::Errored);
    assert_eq!(history.target.as_ref().unwrap(), "history-target");
}

#[tokio::test]
async fn test_run_webhook_notify_delivered() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let mock_server = MockServer::builder().start().await;
    let url = format!("{}/notify", mock_server.uri());
    let payload = json!({ "message": "test" });

    let notification = context
        .db
        .notifications
        .create(
            organisation.id,
            TestingNotificationParams {
                r#type: Some("WEBHOOK_NOTIFY".into()),
                url: Some(url),
                payload: Some(payload.to_string().as_bytes().to_vec()),
                next_try_date: Some(one_core::clock::now_utc()),
                history_target: Some("history-target".to_string()),
                ..Default::default()
            },
        )
        .await;

    Mock::given(method(Method::POST))
        .and(path("/notify"))
        .and(body_json(payload))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    // WHEN
    let resp = context.api.tasks.run("WEBHOOK_NOTIFY").await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    let delivered = resp["delivered"].as_array().unwrap();
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].as_str().unwrap(), notification.id.to_string());
    assert_eq!(resp["failed"].as_array().unwrap().len(), 0);
    assert_eq!(resp["rescheduled"].as_array().unwrap().len(), 0);

    // notification removed
    assert!(
        context
            .db
            .notifications
            .get(&notification.id)
            .await
            .is_none()
    );

    let history = context
        .db
        .histories
        .get_by_entity_id(&notification.id.into())
        .await;
    assert_eq!(history.values.len(), 1);
    let history = &history.values[0];
    assert_eq!(history.entity_type, HistoryEntityType::Notification);
    assert_eq!(history.action, HistoryAction::Delivered);
    assert_eq!(history.target.as_ref().unwrap(), "history-target");
}

#[tokio::test]
async fn test_run_webhook_notify_failed() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let mock_server = MockServer::builder().start().await;
    let url = format!("{}/notify", mock_server.uri());
    let payload = json!({ "message": "test" });

    let notification = context
        .db
        .notifications
        .create(
            organisation.id,
            TestingNotificationParams {
                r#type: Some("WEBHOOK_NOTIFY".into()),
                url: Some(url),
                payload: Some(payload.to_string().as_bytes().to_vec()),
                next_try_date: Some(one_core::clock::now_utc()),
                history_target: Some("history-target".to_string()),
                ..Default::default()
            },
        )
        .await;

    Mock::given(method(Method::POST))
        .and(path("/notify"))
        .and(body_json(payload))
        .respond_with(ResponseTemplate::new(400))
        .expect(1)
        .mount(&mock_server)
        .await;

    // WHEN
    let resp = context.api.tasks.run("WEBHOOK_NOTIFY").await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert_eq!(resp["delivered"].as_array().unwrap().len(), 0);
    let failed = resp["failed"].as_array().unwrap();
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0].as_str().unwrap(), notification.id.to_string());
    assert_eq!(resp["rescheduled"].as_array().unwrap().len(), 0);

    // notification removed
    assert!(
        context
            .db
            .notifications
            .get(&notification.id)
            .await
            .is_none()
    );

    let history = context
        .db
        .histories
        .get_by_entity_id(&notification.id.into())
        .await;
    assert_eq!(history.values.len(), 1);
    let history = &history.values[0];
    assert_eq!(history.entity_type, HistoryEntityType::Notification);
    assert_eq!(history.action, HistoryAction::Errored);
    assert_eq!(history.target.as_ref().unwrap(), "history-target");
}
