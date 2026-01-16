use one_core::model::revocation_list::{
    RevocationListEntityId, RevocationListEntryStatus, RevocationListPurpose, StatusListType,
};
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_revoke_wrprc_success() {
    let (context, _org, _did, identifier, _key) = TestContext::new_with_did(None).await;
    let revocation_list_id = context
        .db
        .revocation_lists
        .create(
            identifier.clone(),
            RevocationListPurpose::Revocation,
            None,
            Some(StatusListType::TokenStatusList),
        )
        .await
        .id;
    let entry_id = context
        .db
        .revocation_lists
        .create_entry(
            revocation_list_id,
            RevocationListEntityId::Signature("REGISTRATION_CERTIFICATE".to_string()),
            0,
        )
        .await;

    let fetch_revocation_info = async || {
        let list = context
            .db
            .revocation_lists
            .get_revocation_by_issuer_identifier_id(
                identifier.id,
                RevocationListPurpose::Revocation,
                StatusListType::TokenStatusList,
                &Default::default(),
            )
            .await
            .unwrap();
        let entries = context.db.revocation_lists.get_entries(list.id).await;
        (list, entries)
    };
    let (list_before, entries_before) = fetch_revocation_info().await;

    let resp = context.api.signatures.revoke(entry_id.into()).await;
    assert_eq!(resp.status(), 204);

    let (list_after, entries_after) = fetch_revocation_info().await;

    assert_eq!(entries_before.len(), entries_after.len());
    assert_eq!(entries_before[0].id, entries_after[0].id);
    assert_eq!(entries_before[0].entity_info, entries_after[0].entity_info);
    assert_eq!(entries_before[0].status, RevocationListEntryStatus::Active);
    assert_eq!(entries_after[0].status, RevocationListEntryStatus::Revoked);

    assert_ne!(list_before.credentials, list_after.credentials);
    assert!(list_after.last_modified > list_before.last_modified);
}

#[tokio::test]
async fn test_revoke_fail_on_missing_entry() {
    let (context, _, _, _, _) = TestContext::new_with_did(None).await;

    let resp = context
        .api
        .signatures
        .revoke(Uuid::from_u128(0x00000000_0000_4444_AAAA_000000000000_u128))
        .await;
    // FIXME: Missing error -> BR_XXXX mapping
    assert_eq!(resp.status(), 500);
}

#[tokio::test]
async fn test_revoke_fail_on_missing_signer() {
    let (context, _, _, identifier, _) = TestContext::new_with_did(None).await;
    let revocation_list_id = context
        .db
        .revocation_lists
        .create(identifier, RevocationListPurpose::Revocation, None, None)
        .await
        .id;
    let entry_id = context
        .db
        .revocation_lists
        .create_entry(
            revocation_list_id,
            RevocationListEntityId::Signature("NO_SUCH_THING".to_string()),
            0,
        )
        .await;

    let resp = context.api.signatures.revoke(entry_id.into()).await;
    assert_eq!(resp.status(), 400);
}
