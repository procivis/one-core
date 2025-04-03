use std::str::FromStr;

use one_core::model::credential::CredentialStateEnum;
use one_core::model::did::{KeyRole, RelatedKey};
use one_core::model::history::HistoryAction;
use one_core::model::revocation_list::RevocationListPurpose;
use shared_types::DidValue;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::fixtures::{assert_history_count, TestingCredentialParams, TestingDidParams};
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
            &organisation,
            TestingDidParams {
                did: Some(
                    DidValue::from_str("did:key:zDnaetpgFTTteRE2RWG8DtbNX6WNWxxgFs627d7z2JVjboM2L")
                        .unwrap(),
                ),
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
        .create(
            "test",
            &organisation,
            "BITSTRINGSTATUSLIST",
            Default::default(),
        )
        .await;
    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &issuer_did,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams::default(),
        )
        .await;
    context
        .db
        .revocation_lists
        .create(&issuer_did, RevocationListPurpose::Revocation, None, None)
        .await;

    // WHEN
    let resp = context.api.credentials.revoke(&credential.id).await;

    // THEN
    assert_eq!(resp.status(), 204);

    let credential = context.db.credentials.get(&credential.id).await;
    assert_eq!(CredentialStateEnum::Revoked, credential.state);
    assert_history_count(&context, &credential.id.into(), HistoryAction::Revoked, 1).await;
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
            &organisation,
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: key.clone(),
                }]),
                did: Some(
                    DidValue::from_str("did:key:z6MkuJnXWiLNmV3SooQ72iDYmUE1sz5HTCXWhKNhDZuqk4Rj")
                        .unwrap(),
                ),
                ..Default::default()
            },
        )
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            &organisation,
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: key.clone(),
                }]),
                ..Default::default()
            },
        )
        .await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "LVVC", Default::default())
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &issuer_did,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                holder_did: Some(holder_did),
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

#[tokio::test]
async fn test_revoke_credential_with_lvvc_success() {
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
            &organisation,
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: key.clone(),
                }]),
                did: Some(
                    DidValue::from_str("did:key:z6MkuJnXWiLNmV3SooQ72iDYmUE1sz5HTCXWhKNhDZuqk4Rj")
                        .unwrap(),
                ),
                ..Default::default()
            },
        )
        .await;
    let holder_did = context
        .db
        .dids
        .create(
            &organisation,
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: key.clone(),
                }]),
                ..Default::default()
            },
        )
        .await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "LVVC", Default::default())
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &issuer_did,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                holder_did: Some(holder_did),
                key: Some(key),
                ..Default::default()
            },
        )
        .await;

    let token = "eyJhbGciOiJFRERTQSIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3MDkxMjI5MDgsImV4cCI6MTcwOTEyNjUwOCwibmJmIjoxNzA5MTIyODQ4LCJpc3MiOiJkaWQ6a2V5Ono2TWtmWGZyTm90RndpNkRLQ0JjOUd5QlNnekV4UDI2OFlVRXFQUXVCOVBHQTNoYyIsInN1YiI6ImRpZDprZXk6ejZNa2V1R3hpQ2V6ZzQ0Q0pmU2p4TG1ZOFNzZFFxZWpBOWV1SHdVTkdWYVhuQkVNIiwianRpIjoiaHR0cHM6Ly9odHRwOi8vMC4wLjAuMDozMDAwL3NzaS9yZXZvY2F0aW9uL3YxL2x2dmMvNzAxY2UwNGUtZWU1OC00OTI4LWE3NjItOGIzNjA0NTcyOGE5IiwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCJdLCJpZCI6Imh0dHBzOi8vaHR0cDovLzAuMC4wLjA6MzAwMC9zc2kvcmV2b2NhdGlvbi92MS9sdnZjLzcwMWNlMDRlLWVlNTgtNDkyOC1hNzYyLThiMzYwNDU3MjhhOSIsImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiaHR0cHM6Ly9odHRwOi8vMC4wLjAuMDozMDAwL3NzaS9jcmVkZW50aWFsL3YxL2JkNzU1NDMyLTNjYjctNDc4Yy05ZDdiLTQ1MDAyNTFiMzkzNSIsInN0YXR1cyI6IkFDQ0VQVEVEIn19fQ.RZ912pL5Q1P4Un1byILeKXIcgVqAoF2CHcNoF5XgM9zUPjypbf5hakZ2oVZcOXFU691hO0SMVyytMEj4ZWonAg";
    let _lvvc = context
        .db
        .validity_credentials
        .create_lvvc(None, token.into(), credential.id)
        .await;

    // WHEN
    let resp = context.api.credentials.revoke(&credential.id).await;

    // THEN
    assert_eq!(resp.status(), 204);

    let credential = context.db.credentials.get(&credential.id).await;
    assert_eq!(CredentialStateEnum::Revoked, credential.state);
}
