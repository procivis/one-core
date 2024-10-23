use std::str::FromStr;

use one_core::model::credential::CredentialStateEnum;
use one_core::model::did::{KeyRole, RelatedKey};
use shared_types::DidValue;

use crate::fixtures::{TestingCredentialParams, TestingDidParams};
use crate::utils::context::TestContext;
use crate::utils::db_clients::keys::eddsa_testing_params;

#[tokio::test]
async fn test_reactivate_credential_with_bitstring_status_list_success() {
    // GIVEN
    let (context, organisation, issuer_did, _) = TestContext::new_with_did().await;
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
            &issuer_did,
            "OPENID4VC",
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

#[tokio::test]
async fn test_reactivate_credential_with_lvvc_success() {
    // GIVEN
    let (context, organisation, issuer_did, _) = TestContext::new_with_did().await;
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
            &issuer_did,
            "OPENID4VC",
            TestingCredentialParams {
                holder_did: Some(holder_did),
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

    assert_eq!(
        CredentialStateEnum::Accepted,
        credential.state.unwrap()[0].state
    );
}
