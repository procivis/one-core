use core_server::endpoint::trust_list_publication::dto::TrustEntryStatusRestEnum;
use one_core::model::trust_entry::TrustEntryStatusEnum;
use one_core::model::trust_list_publication::TrustListPublicationRoleEnum;
use uuid::Uuid;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_update_trust_entry() {
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
        .update_trust_entry(
            trust_list_publication.id,
            trust_entry.id,
            Some(TrustEntryStatusRestEnum::Suspended),
            None,
        )
        .await;

    // then
    similar_asserts::assert_eq!(resp.status(), 204);

    // verify update
    let updated_entry = context.db.trust_entries.get(trust_entry.id).await.unwrap();
    similar_asserts::assert_eq!(updated_entry.status, TrustEntryStatusEnum::Suspended);
}

#[tokio::test]
async fn test_fail_to_update_trust_entry_not_found() {
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
        .update_trust_entry(
            trust_list_publication.id,
            non_existent_id,
            Some(TrustEntryStatusRestEnum::Suspended),
            None,
        )
        .await;

    // then
    similar_asserts::assert_eq!(resp.status(), 404);
}
