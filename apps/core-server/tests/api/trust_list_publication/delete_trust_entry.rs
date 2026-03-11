use one_core::model::trust_entry::TrustEntryStatusEnum;
use one_core::model::trust_list_publication::TrustListPublicationRoleEnum;
use uuid::Uuid;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_delete_trust_entry() {
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
            Some(identifier.clone()),
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
        .delete_trust_entry(trust_list_publication.id, trust_entry.id)
        .await;

    // then
    similar_asserts::assert_eq!(resp.status(), 204);
    let deleted_entry = context.db.trust_entries.get(trust_entry.id).await;
    assert!(deleted_entry.is_none());
}

#[tokio::test]
async fn test_fail_to_delete_trust_entry_entry_does_not_belong_to_list() {
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
            Some(identifier.clone()),
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
        .delete_trust_entry(Uuid::new_v4().into(), trust_entry.id)
        .await;

    // then
    similar_asserts::assert_eq!(resp.status(), 400);
    similar_asserts::assert_eq!("BR_0390", resp.error_code().await);
}

#[tokio::test]
async fn test_fail_to_delete_trust_entry_not_found() {
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
            Some(identifier.clone()),
            Some(key.id),
            Some(certificate.id),
        )
        .await;
    let non_existent_id = Uuid::new_v4().into();

    // when
    let resp = context
        .api
        .trust_list_publication
        .delete_trust_entry(trust_list_publication.id, non_existent_id)
        .await;

    // then
    similar_asserts::assert_eq!(resp.status(), 404);
}
