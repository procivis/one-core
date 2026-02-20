use std::str::FromStr;

use one_core::model::credential::CredentialStateEnum;
use one_core::model::did::{DidType, KeyRole, RelatedKey};
use one_core::model::history::HistoryAction;
use one_core::model::identifier::IdentifierType;
use serde_json::Value;
use shared_types::DidValue;
use similar_asserts::assert_eq;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::fixtures::{
    TestingCredentialParams, TestingDidParams, TestingIdentifierParams, assert_history_count,
};
use crate::utils::context::TestContext;
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
            Some(organisation.clone()),
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
        .create(
            "test",
            &organisation,
            Some("BITSTRINGSTATUSLIST".into()),
            Default::default(),
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
            Some(organisation.clone()),
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
        .create(
            "test",
            &organisation,
            Some("BITSTRINGSTATUSLIST".into()),
            Default::default(),
        )
        .await;

    let webhook_url = "https://webhook.url";
    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                webhook_url: Some(webhook_url.to_string()),
                ..Default::default()
            },
        )
        .await;
    context.db.revocation_lists.create(identifier, None).await;

    // WHEN
    let resp = context.api.credentials.revoke(&credential.id).await;

    // THEN
    assert_eq!(resp.status(), 204);

    let notifications = context.db.notifications.list("WEBHOOK_NOTIFY").await;
    assert_eq!(notifications.len(), 1);
    let notification = &notifications[0];
    assert_eq!(notification.url, webhook_url);
    assert_eq!(notification.organisation_id, organisation.id);

    let payload: Value = serde_json::from_slice(&notification.payload).unwrap();
    assert_eq!(payload["credentialId"], credential.id.to_string());
    assert_eq!(payload["status"], "REVOKED");
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
            Some(organisation.clone()),
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
            Some(organisation.clone()),
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
        .create(
            "test",
            &organisation,
            Some("BITSTRINGSTATUSLIST".into()),
            Default::default(),
        )
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
                deleted_at: Some(OffsetDateTime::now_utc()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.credentials.revoke(&credential.id).await;

    // THEN
    assert_eq!(resp.status(), 404);
}
