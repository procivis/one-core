use std::str::FromStr;

use one_core::model::credential::CredentialStateEnum;
use one_core::model::did::DidType;
use one_core::model::history::HistoryAction;
use one_core::model::identifier::IdentifierType;
use one_core::model::revocation_list::RevocationListPurpose;
use shared_types::DidValue;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::fixtures::{
    assert_history_count, TestingCredentialParams, TestingDidParams, TestingIdentifierParams,
};
use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;

#[tokio::test]
async fn test_suspend_credential_with_bitstring_status_list_success() {
    // GIVEN
    let (context, organisation, issuer_did, identifier, ..) = TestContext::new_with_did(None).await;
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
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams::default(),
        )
        .await;
    context
        .db
        .revocation_lists
        .create(&issuer_did, RevocationListPurpose::Revocation, None, None)
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

    assert_eq!(CredentialStateEnum::Suspended, credential.state.clone());

    assert_eq!(suspend_end_date, credential.suspend_end_date.unwrap());
    assert_history_count(&context, &credential.id.into(), HistoryAction::Suspended, 1).await;
}

#[tokio::test]
async fn test_suspend_credential_with_mdoc_mso_suspend_update_success() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            "MDOC_MSO_UPDATE_SUSPENSION",
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

    assert_eq!(CredentialStateEnum::Suspended, credential.state.clone());

    assert_eq!(suspend_end_date, credential.suspend_end_date.unwrap());
}

#[tokio::test]
async fn test_suspend_credential_with_lvvc_success() {
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
    let holder_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
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
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                holder_identifier: Some(holder_identifier),
                key: Some(issuer_key),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .revocation_lists
        .create(&issuer_did, RevocationListPurpose::Revocation, None, None)
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

    assert_eq!(CredentialStateEnum::Suspended, credential.state);

    assert_eq!(suspend_end_date, credential.suspend_end_date.unwrap());
}

#[tokio::test]
async fn test_suspend_credential_with_none_fails() {
    // GIVEN
    let (context, organisation, issuer_did, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            "NONE",
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
    context
        .db
        .revocation_lists
        .create(&issuer_did, RevocationListPurpose::Revocation, None, None)
        .await;
    // WHEN
    let resp = context.api.credentials.suspend(&credential.id, None).await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0162", resp.error_code().await);
}

#[tokio::test]
async fn test_suspend_credential_fails_credential_deleted() {
    // GIVEN
    let (context, organisation, issuer_did, identifier, ..) = TestContext::new_with_did(None).await;
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
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                deleted_at: Some(OffsetDateTime::now_utc()),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .revocation_lists
        .create(&issuer_did, RevocationListPurpose::Revocation, None, None)
        .await;
    let suspend_end_date_str = "2023-06-09T14:19:57.000Z";
    // WHEN
    let resp = context
        .api
        .credentials
        .suspend(&credential.id, Some(suspend_end_date_str.to_string()))
        .await;

    // THEN
    assert_eq!(resp.status(), 404);
}
