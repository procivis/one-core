use std::str::FromStr;

use one_core::model::credential::CredentialStateEnum;
use one_core::model::did::{DidType, KeyRole, RelatedKey};
use one_core::model::identifier::IdentifierType;
use one_core::model::revocation_list::{
    RevocationListEntryStatus, RevocationListPurpose, StatusListType,
};
use shared_types::DidValue;
use similar_asserts::assert_eq;

use crate::fixtures::{TestingCredentialParams, TestingDidParams, TestingIdentifierParams};
use crate::utils::context::TestContext;
use crate::utils::db_clients::keys::eddsa_testing_params;

#[tokio::test]
async fn test_reactivate_credential_with_bitstring_status_list_success() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
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
            RevocationListPurpose::Suspension,
            None,
            Some(StatusListType::BitstringStatusList),
        )
        .await;

    context
        .db
        .revocation_lists
        .create_credential_entry(revocation_list.id, credential.id, 0)
        .await;

    context
        .db
        .revocation_lists
        .update_entry(
            revocation_list.id,
            0,
            Some(RevocationListEntryStatus::Revoked),
        )
        .await;

    // WHEN
    let resp = context.api.credentials.reactivate(&credential.id).await;

    // THEN
    assert_eq!(resp.status(), 204);

    let credential = context.db.credentials.get(&credential.id).await;

    assert_eq!(CredentialStateEnum::Accepted, credential.state);

    let revocation_list_entry = context
        .db
        .revocation_lists
        .get_entries(revocation_list.id)
        .await;
    assert_eq!(revocation_list_entry.len(), 1);
    assert_eq!(
        revocation_list_entry[0].status,
        RevocationListEntryStatus::Active
    );
}

#[tokio::test]
async fn test_reactivate_credential_with_lvvc_success() {
    // GIVEN
    let (context, organisation, issuer_did, identifier, ..) = TestContext::new_with_did(None).await;
    let issuer_key = issuer_did
        .keys
        .as_ref()
        .unwrap()
        .first()
        .unwrap()
        .key
        .clone();
    let key = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
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
                did: Some(
                    DidValue::from_str("did:key:z6MkuJnXWiLNmV3SooQ72iDYmUE1sz5HTCXWhKNhDZuqk4Rj")
                        .unwrap(),
                ),
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
        .create("test", &organisation, "LVVC", Default::default())
        .await;
    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Suspended,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                holder_identifier: Some(holder_identifier),
                key: Some(issuer_key),
                ..Default::default()
            },
        )
        .await;
    // WHEN
    let resp = context.api.credentials.reactivate(&credential.id).await;

    // THEN
    assert_eq!(resp.status(), 204);

    let credential = context.db.credentials.get(&credential.id).await;

    assert_eq!(CredentialStateEnum::Accepted, credential.state);
}
