use std::str::FromStr;
use std::time::Duration;

use one_core::model::credential::{CredentialStateEnum, CredentialType};
use one_core::model::did::{DidType, KeyRole, RelatedKey};
use one_core::model::history::HistoryAction;
use one_core::model::identifier::IdentifierType;
use serde_json::json;
use shared_types::DidValue;
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::fixtures::{
    TestingCredentialParams, TestingDidParams, TestingIdentifierParams, assert_history_count,
};
use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;
use crate::utils::db_clients::keys::eddsa_testing_params;

#[tokio::test]
async fn test_revoke_credential_with_bitstring_status_list_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let key = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
        .await;
    let issuer_did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                did: Some(
                    DidValue::from_str("did:key:zDnaetpgFTTteRE2RWG8DtbNX6WNWxxgFs627d7z2JVjboM2L")
                        .unwrap(),
                ),
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key,
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
    let resp = context.api.credentials.revoke(&credential.id).await;

    // THEN
    assert_eq!(resp.status(), 204);

    let credential = context.db.credentials.get(&credential.id).await;
    assert_eq!(CredentialStateEnum::Revoked, credential.state);
    assert_history_count(&context, &credential.id.into(), HistoryAction::Revoked, 1).await;
}

#[tokio::test]
async fn test_revoke_credential_with_webhook() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let key = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
        .await;
    let issuer_did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                did: Some(
                    DidValue::from_str("did:key:zDnaetpgFTTteRE2RWG8DtbNX6WNWxxgFs627d7z2JVjboM2L")
                        .unwrap(),
                ),
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key,
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
            "credentialId": credential.id,
            "status": "REVOKED"
        }))
        .await;

    // WHEN
    let resp = context.api.credentials.revoke(&credential.id).await;

    // THEN
    assert_eq!(resp.status(), 204);
    tokio::time::timeout(Duration::from_secs(5), webhook.wait_until_satisfied())
        .await
        .expect("Expected REVOKED webhook within 5 seconds");
}

#[tokio::test]
async fn test_revoke_credential_not_found() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context.api.credentials.revoke(&Uuid::new_v4()).await;

    // THEN
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_revoke_credential_deleted() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let key = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
        .await;
    let issuer_did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: key.clone(),
                    reference: "1".to_string(),
                }]),
                did: Some(
                    DidValue::from_str("did:key:z6MkuJnXWiLNmV3SooQ72iDYmUE1sz5HTCXWhKNhDZuqk4Rj")
                        .unwrap(),
                ),
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

    let holder_did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: key.clone(),
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
            &issuer_identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                holder_identifier: Some(holder_identifier),
                key: Some(key),
                deleted_at: Some(one_core::clock::now_utc()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.credentials.revoke(&credential.id).await;

    // THEN
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_revoke_credential_fails_when_expired() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let key = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
        .await;
    let issuer_did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                did: Some(
                    DidValue::from_str("did:key:zDnaetpgFTTteRE2RWG8DtbNX6WNWxxgFs627d7z2JVjboM2L")
                        .unwrap(),
                ),
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key,
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
    let resp = context.api.credentials.revoke(&credential.id).await;

    // THEN - same error as revoking an already REVOKED credential (invalid state transition)
    assert_eq!(resp.status(), 400);
    let resp = resp.json_value().await;
    assert_eq!(resp["code"], "BR_0366");

    let credential = context.db.credentials.get(&credential.id).await;
    assert_eq!(CredentialStateEnum::Expired, credential.state);
}

#[tokio::test]
async fn test_revoke_multi_format_batch_parent_with_rejected_format() {
    // GIVEN a multi-format batch parent where the holder rejected one format
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            TestingCreateSchemaParams {
                formats: Some(vec![
                    ("JWT".into(), "jwt-schema-id".to_string()),
                    ("SD_JWT_VC".into(), "sd-jwt-vc-schema-id".to_string()),
                ]),
                ..Default::default()
            },
        )
        .await;
    let formats = credential_schema.formats.as_ref().await.unwrap().to_owned();
    let parent = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_FINAL1",
            TestingCredentialParams {
                r#type: Some(CredentialType::BatchParent),
                ..Default::default()
            },
        )
        .await;
    let issued_item = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_FINAL1",
            TestingCredentialParams {
                r#type: Some(CredentialType::BatchItem),
                parent_id: Some(parent.id),
                format: Some(formats[0].clone()),
                ..Default::default()
            },
        )
        .await;
    let rejected_item = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Rejected,
            &identifier,
            "OPENID4VCI_FINAL1",
            TestingCredentialParams {
                r#type: Some(CredentialType::BatchItem),
                parent_id: Some(parent.id),
                format: Some(formats[1].clone()),
                ..Default::default()
            },
        )
        .await;
    context.db.revocation_lists.create(identifier, None).await;

    // WHEN
    let resp = context.api.credentials.revoke(&parent.id).await;

    // THEN
    assert_eq!(resp.status(), 204);
    let parent = context.db.credentials.get(&parent.id).await;
    assert_eq!(CredentialStateEnum::Revoked, parent.state);
    let issued_item = context.db.credentials.get(&issued_item.id).await;
    assert_eq!(CredentialStateEnum::Revoked, issued_item.state);
    let rejected_item = context.db.credentials.get(&rejected_item.id).await;
    assert_eq!(CredentialStateEnum::Rejected, rejected_item.state);
}
