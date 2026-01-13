use one_core::model::revocation_list::{
    RevocationListEntityId, RevocationListEntryStatus, RevocationListPurpose,
};
use serde_json::json;
use similar_asserts::assert_eq;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_sign_wrprc_success() {
    let (context, _, _, identifier, _) = TestContext::new_with_did(None).await;
    let revocation_list = context
        .db
        .revocation_lists
        .create(identifier, RevocationListPurpose::Revocation, None, None)
        .await;
    let entry_id1 = context
        .db
        .revocation_lists
        .create_entry(
            revocation_list.id,
            RevocationListEntityId::Signature("SIGNATURE_TYPE".to_string()),
            0,
        )
        .await;
    let entry_id2 = context
        .db
        .revocation_lists
        .create_entry(
            revocation_list.id,
            RevocationListEntityId::Signature("OTHER_SIGNATURE_TYPE".to_string()),
            1,
        )
        .await;
    context
        .db
        .revocation_lists
        .update_entry(
            revocation_list.id,
            1,
            Some(RevocationListEntryStatus::Revoked),
        )
        .await;

    let resp = context
        .api
        .signatures
        .revocation_check(vec![entry_id1.into(), entry_id2.into()])
        .await;

    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert_eq!(
        resp,
        json!({
            entry_id1.to_string(): {
                "state": "ACTIVE",
                "type": "SIGNATURE_TYPE"
            },
            entry_id2.to_string(): {
                "state": "REVOKED",
                "type": "OTHER_SIGNATURE_TYPE"
            }
        })
    );
}
