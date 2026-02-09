use one_core::model::revocation_list::{
    RevocationListEntityId, RevocationListEntryStatus, RevocationListPurpose,
};
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::fixtures::sts::{StsSetup, setup_sts};
use crate::utils::context::TestContext;
use crate::utils::db_clients::revocation_lists::TestingRevocationListParams;

#[tokio::test]
async fn test_revoke_wrprc_success() {
    let (context, _org, identifier, ..) = TestContext::new_with_certificate_identifier(None).await;
    let revocation_list_id = context
        .db
        .revocation_lists
        .create(
            identifier.clone(),
            Some(TestingRevocationListParams {
                r#type: Some("TOKENSTATUSLIST".into()),
                ..Default::default()
            }),
        )
        .await
        .id;
    let entry_id = context
        .db
        .revocation_lists
        .create_entry(
            revocation_list_id,
            RevocationListEntityId::Signature("REGISTRATION_CERTIFICATE".to_string(), None),
            Some(0),
        )
        .await;

    let fetch_revocation_info = async || {
        let list = context
            .db
            .revocation_lists
            .get_revocation_by_issuer_identifier_id(
                identifier.id,
                RevocationListPurpose::Revocation,
                &"TOKENSTATUSLIST".into(),
                &Default::default(),
            )
            .await
            .unwrap();
        let entries = context.db.revocation_lists.get_entries(list.id).await;
        (list, entries)
    };
    let (list_before, entries_before) = fetch_revocation_info().await;

    let resp = context.api.signatures.revoke(entry_id.into(), None).await;
    assert_eq!(resp.status(), 204);

    let (list_after, entries_after) = fetch_revocation_info().await;

    assert_eq!(entries_before.len(), entries_after.len());
    assert_eq!(entries_before[0].id, entries_after[0].id);
    assert_eq!(entries_before[0].entity_info, entries_after[0].entity_info);
    assert_eq!(entries_before[0].status, RevocationListEntryStatus::Active);
    assert_eq!(entries_after[0].status, RevocationListEntryStatus::Revoked);

    assert_ne!(list_before.formatted_list, list_after.formatted_list);
    assert!(list_after.last_modified > list_before.last_modified);
}

#[tokio::test]
async fn test_revoke_fail_on_missing_entry() {
    let (context, _, _, _, _) = TestContext::new_with_did(None).await;

    let resp = context
        .api
        .signatures
        .revoke(
            Uuid::from_u128(0x00000000_0000_4444_AAAA_000000000000_u128),
            None,
        )
        .await;
    // FIXME: Missing error -> BR_XXXX mapping
    assert_eq!(resp.status(), 500);
}

#[tokio::test]
async fn test_revoke_fail_on_missing_signer() {
    let (context, _org, identifier, ..) = TestContext::new_with_certificate_identifier(None).await;
    let revocation_list_id = context
        .db
        .revocation_lists
        .create(identifier, None)
        .await
        .id;
    let entry_id = context
        .db
        .revocation_lists
        .create_entry(
            revocation_list_id,
            RevocationListEntityId::Signature("NO_SUCH_THING".to_string(), None),
            Some(0),
        )
        .await;

    let resp = context.api.signatures.revoke(entry_id.into(), None).await;
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_fail_on_missing_signer_specific_permission() {
    let StsSetup {
        config,
        token,
        mock_server: _mock_server,
    } = setup_sts(vec!["X509_CERTIFICATE_REVOKE"]).await;
    let (context, _org, identifier, ..) =
        TestContext::new_with_certificate_identifier(Some(config)).await;
    let revocation_list_id = context
        .db
        .revocation_lists
        .create(identifier, None)
        .await
        .id;
    let entry_id = context
        .db
        .revocation_lists
        .create_entry(
            revocation_list_id,
            RevocationListEntityId::Signature("REGISTRATION_CERTIFICATE".to_string(), None),
            Some(0),
        )
        .await;

    let resp = context
        .api
        .signatures
        .revoke(entry_id.into(), Some(token))
        .await;

    assert_eq!(resp.status(), 403);
}
