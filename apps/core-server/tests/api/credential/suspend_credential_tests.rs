use std::str::FromStr;

use one_core::model::credential::CredentialStateEnum;
use one_core::model::did::DidType;
use one_core::model::revocation_list::RevocationListPurpose;
use shared_types::DidValue;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::fixtures::{TestingCredentialParams, TestingDidParams};
use crate::utils::context::TestContext;

#[tokio::test]
async fn test_suspend_credential_with_bitstring_status_list_success() {
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
            CredentialStateEnum::Accepted,
            &issuer_did,
            "PROCIVIS_TEMPORARY",
            TestingCredentialParams::default(),
        )
        .await;
    context
        .db
        .revocation_lists
        .create(&issuer_did, RevocationListPurpose::Revocation, None)
        .await;
    let suspend_end_date_str = "2023-06-09T14:19:57.000Z";
    let suspend_end_date = OffsetDateTime::parse(suspend_end_date_str, &Rfc3339).unwrap();
    // WHEN
    let resp = context
        .api
        .credentials
        .suspend(&credential.id, Some(suspend_end_date_str.to_string()))
        .await;

    // THEN
    assert_eq!(resp.status(), 204);

    let credential = context.db.credentials.get(&credential.id).await;

    assert_eq!(
        CredentialStateEnum::Suspended,
        credential.state.clone().unwrap()[0].state
    );

    assert_eq!(
        suspend_end_date,
        credential.state.unwrap()[0].suspend_end_date.unwrap()
    );
}

#[tokio::test]
async fn test_suspend_credential_with_lvvc_success() {
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
    let holder_did = context
        .db
        .dids
        .create(
            &organisation,
            TestingDidParams {
                did_type: Some(DidType::Remote),
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
            CredentialStateEnum::Accepted,
            &issuer_did,
            "PROCIVIS_TEMPORARY",
            TestingCredentialParams {
                holder_did: Some(holder_did),
                key: Some(issuer_key),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .revocation_lists
        .create(&issuer_did, RevocationListPurpose::Revocation, None)
        .await;
    let suspend_end_date_str = "2023-06-09T14:19:57.000Z";
    let suspend_end_date = OffsetDateTime::parse(suspend_end_date_str, &Rfc3339).unwrap();
    // WHEN
    let resp = context
        .api
        .credentials
        .suspend(&credential.id, Some(suspend_end_date_str.to_string()))
        .await;

    // THEN
    assert_eq!(resp.status(), 204);

    let credential = context.db.credentials.get(&credential.id).await;

    assert_eq!(
        CredentialStateEnum::Suspended,
        credential.state.clone().unwrap()[0].state
    );

    assert_eq!(
        suspend_end_date,
        credential.state.unwrap()[0].suspend_end_date.unwrap()
    );
}
