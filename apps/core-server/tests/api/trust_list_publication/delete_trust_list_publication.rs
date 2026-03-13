use one_core::model::history::{HistoryAction, HistoryEntityType};
use one_core::model::trust_entry::TrustEntryStatusEnum;
use one_core::model::trust_list_publication::TrustListPublicationRoleEnum;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_delete_trust_list_publication() {
    // given
    let (context, organisation, identifier, certificate, key) =
        TestContext::new_with_certificate_identifier(None).await;
    let trust_list_publication = context
        .db
        .trust_list_publications
        .create(
            "test_trust_list_publication",
            TrustListPublicationRoleEnum::PidProvider,
            "LOTE_PUBLISHER".into(),
            serde_json::to_vec(&serde_json::Value::Object(serde_json::Map::new())).unwrap(),
            organisation.clone(),
            identifier.clone(),
            Some(key.id),
            Some(certificate.id),
        )
        .await;

    let trust_entry = context
        .db
        .trust_entries
        .create(
            TrustEntryStatusEnum::Active,
            serde_json::to_vec(&serde_json::Value::Object(serde_json::Map::new())).unwrap(),
            trust_list_publication.clone(),
            identifier.clone(),
        )
        .await;

    // when
    let resp = context
        .api
        .trust_list_publication
        .delete_trust_list_publication(trust_list_publication.id)
        .await;

    // then
    similar_asserts::assert_eq!(resp.status(), 204);

    let deleted_publication = context
        .db
        .trust_list_publications
        .get(trust_list_publication.id)
        .await;
    assert!(deleted_publication.is_none());
    let deleted_enty = context.db.trust_entries.get(trust_entry.id).await;
    assert!(deleted_enty.is_none());

    // verify history entry
    let history_list = context
        .db
        .histories
        .get_by_entity_id(&trust_list_publication.id.into())
        .await;
    similar_asserts::assert_eq!(1, history_list.total_items);
    let last = history_list.values.first().unwrap();
    similar_asserts::assert_eq!(HistoryAction::Deleted, last.action);
    similar_asserts::assert_eq!(HistoryEntityType::TrustListPublication, last.entity_type);
}

#[tokio::test]
async fn test_fail_to_delete_trust_list_publication_not_found() {
    // given
    let (context, ..) = TestContext::new_with_certificate_identifier(None).await;
    let non_existent_id = uuid::Uuid::new_v4().into();

    // when
    let resp = context
        .api
        .trust_list_publication
        .delete_trust_list_publication(non_existent_id)
        .await;

    // then
    similar_asserts::assert_eq!(resp.status(), 404);
}
