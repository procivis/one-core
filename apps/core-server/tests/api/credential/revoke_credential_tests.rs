use std::str::FromStr;
use std::time::Duration;

use one_core::model::credential::{CredentialStateEnum, CredentialType};
use one_core::model::did::{DidType, KeyRole, RelatedKey};
use one_core::model::history::HistoryAction;
use one_core::model::identifier::{Identifier, IdentifierType};
use one_core::model::organisation::Organisation;
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
use crate::utils::db_clients::revocation_lists::TestingRevocationListParams;

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
    let resp = context
        .api
        .credentials
        .revoke(&credential.common().id)
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
            "credentialId": credential.common().id,
            "status": "REVOKED"
        }))
        .await;

    // WHEN
    let resp = context
        .api
        .credentials
        .revoke(&credential.common().id)
        .await;

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
    let resp = context
        .api
        .credentials
        .revoke(&credential.common().id)
        .await;

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
    let resp = context
        .api
        .credentials
        .revoke(&credential.common().id)
        .await;

    // THEN - same error as revoking an already REVOKED credential (invalid state transition)
    assert_eq!(resp.status(), 400);
    let resp = resp.json_value().await;
    assert_eq!(resp["code"], "BR_0366");

    let credential = context.db.credentials.get(&credential.common().id).await;
    assert_eq!(CredentialStateEnum::Expired, credential.common().state);
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
                parent_id: Some(parent.common().id),
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
                parent_id: Some(parent.common().id),
                format: Some(formats[1].clone()),
                ..Default::default()
            },
        )
        .await;
    context.db.revocation_lists.create(identifier, None).await;

    // WHEN
    let resp = context.api.credentials.revoke(&parent.common().id).await;

    // THEN
    assert_eq!(resp.status(), 204);
    let parent = context.db.credentials.get(&parent.common().id).await;
    assert_eq!(CredentialStateEnum::Revoked, parent.common().state);
    let issued_item = context.db.credentials.get(&issued_item.common().id).await;
    assert_eq!(CredentialStateEnum::Revoked, issued_item.common().state);
    let rejected_item = context.db.credentials.get(&rejected_item.common().id).await;
    assert_eq!(CredentialStateEnum::Rejected, rejected_item.common().state);
}

/// Concurrent revocations on the same list must all end up in the published list: each one
/// re-renders the whole list, so without serialization the last write can drop the others.
#[tokio::test]
async fn test_concurrent_revocations_on_same_list_are_all_published() {
    const CREDENTIAL_COUNT: usize = 10;

    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let identifier = did_issuer(&context, &organisation).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;
    let list = context
        .db
        .revocation_lists
        .create(identifier.clone(), None)
        .await;

    let mut credential_ids = vec![];
    for index in 0..CREDENTIAL_COUNT {
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
        context
            .db
            .revocation_lists
            .create_credential_entry(list.id, credential.common().id, index)
            .await;
        credential_ids.push(credential.common().id);
    }

    // WHEN
    let responses = futures::future::join_all(
        credential_ids
            .iter()
            .map(|credential_id| context.api.credentials.revoke(credential_id)),
    )
    .await;

    // THEN
    for response in responses {
        assert_eq!(response.status(), 204);
    }
    let published = context.db.revocation_lists.get(list.id).await;
    let revoked = revoked_bitstring_indices(&published.formatted_list);
    assert_eq!(revoked, (0..CREDENTIAL_COUNT).collect::<Vec<_>>());
}

/// Concurrent batch revocations whose items sit on the same lists in different orders must not
/// deadlock: every list of a transaction is locked in one statement, in a global order.
#[tokio::test]
async fn test_concurrent_batch_revocations_across_shared_lists_do_not_deadlock() {
    const BATCH_COUNT: usize = 6;

    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let identifier = did_issuer(&context, &organisation).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;
    let list_1 = context
        .db
        .revocation_lists
        .create(identifier.clone(), None)
        .await;
    let list_2 = context
        .db
        .revocation_lists
        .create(
            identifier.clone(),
            Some(TestingRevocationListParams {
                sequence_number: Some(1),
                ..Default::default()
            }),
        )
        .await;

    let mut parent_ids = vec![];
    for batch in 0..BATCH_COUNT {
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
        // half of the batches have their first item on the first list, the others on the
        // second one, so that per-item locking would lock the lists in opposite orders
        let lists = if batch % 2 == 0 {
            [list_1.id, list_2.id]
        } else {
            [list_2.id, list_1.id]
        };
        for list_id in lists {
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
            context
                .db
                .revocation_lists
                .create_credential_entry(list_id, item.common().id, batch)
                .await;
        }
        parent_ids.push(parent.common().id);
    }

    // WHEN
    let responses = futures::future::join_all(
        parent_ids
            .iter()
            .map(|parent_id| context.api.credentials.revoke(parent_id)),
    )
    .await;

    // THEN
    for response in responses {
        assert_eq!(response.status(), 204);
    }
    for list_id in [list_1.id, list_2.id] {
        let published = context.db.revocation_lists.get(list_id).await;
        assert_eq!(
            revoked_bitstring_indices(&published.formatted_list),
            (0..BATCH_COUNT).collect::<Vec<_>>()
        );
    }
}

/// An issuer identifier with a `did:key` that can sign status list credentials.
async fn did_issuer(context: &TestContext, organisation: &Organisation) -> Identifier {
    let key = context
        .db
        .keys
        .create(organisation, eddsa_testing_params())
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
    context
        .db
        .identifiers
        .create(
            organisation,
            TestingIdentifierParams {
                did: Some(issuer_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(issuer_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await
}

/// Decodes the `encodedList` of a JWT bitstring status list credential into the set indices.
fn revoked_bitstring_indices(formatted_list: &[u8]) -> Vec<usize> {
    use std::io::Read;

    use ct_codecs::{Base64UrlSafeNoPadding, Decoder};

    let jwt = std::str::from_utf8(formatted_list).unwrap();
    let payload = jwt.split('.').nth(1).unwrap();
    let payload: serde_json::Value =
        serde_json::from_slice(&Base64UrlSafeNoPadding::decode_to_vec(payload, None).unwrap())
            .unwrap();
    let encoded_list = serde_json_path::JsonPath::parse("$..encodedList")
        .unwrap()
        .query(&payload)
        .exactly_one()
        .unwrap()
        .as_str()
        .unwrap()
        .strip_prefix('u')
        .unwrap()
        .to_owned();

    let compressed = Base64UrlSafeNoPadding::decode_to_vec(encoded_list, None).unwrap();
    let mut bytes = vec![];
    flate2::read::GzDecoder::new(compressed.as_slice())
        .read_to_end(&mut bytes)
        .unwrap();

    (0..bytes.len() * 8)
        .filter(|index| bytes[index / 8] & (0x80 >> (index % 8)) != 0)
        .collect()
}
