use one_core::model::trust_entry::TrustEntryStatusEnum;
use one_core::model::trust_list_publication::TrustListPublicationRoleEnum;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_get_trust_list_publication_entries() {
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

    context
        .db
        .trust_entries
        .create(
            TrustEntryStatusEnum::Active,
            serde_json::to_vec(&serde_json::Value::Object(serde_json::Map::new())).unwrap(),
            trust_list_publication.clone(),
            identifier.clone(),
        )
        .await;

    context
        .db
        .trust_entries
        .create(
            TrustEntryStatusEnum::Suspended,
            serde_json::to_vec(&serde_json::Value::Object(serde_json::Map::new())).unwrap(),
            trust_list_publication.clone(),
            identifier.clone(),
        )
        .await;

    // when
    let resp = context
        .api
        .trust_list_publication
        .get_trust_list_publication_entries(trust_list_publication.id, None)
        .await;

    // then
    similar_asserts::assert_eq!(resp.status(), 200);
    let resp_json = resp.json_value().await;
    similar_asserts::assert_eq!(resp_json["totalItems"].as_u64().unwrap(), 2);
    similar_asserts::assert_eq!(resp_json["totalPages"].as_u64().unwrap(), 1);

    let values = resp_json["values"].as_array().unwrap();
    similar_asserts::assert_eq!(values.len(), 2);
}

#[tokio::test]
async fn test_get_trust_list_publication_entries_empty() {
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

    // when
    let resp = context
        .api
        .trust_list_publication
        .get_trust_list_publication_entries(trust_list_publication.id, None)
        .await;

    // then
    similar_asserts::assert_eq!(resp.status(), 200);
    let resp_json = resp.json_value().await;
    similar_asserts::assert_eq!(resp_json["totalItems"].as_u64().unwrap(), 0);
    similar_asserts::assert_eq!(resp_json["totalPages"].as_u64().unwrap(), 0);

    let values = resp_json["values"].as_array().unwrap();
    similar_asserts::assert_eq!(values.len(), 0);
}

#[tokio::test]
async fn test_fail_to_get_trust_list_publication_entries_not_found() {
    // given
    let (context, ..) = TestContext::new_with_certificate_identifier(None).await;
    let non_existent_id = uuid::Uuid::new_v4().into();

    // when
    let resp = context
        .api
        .trust_list_publication
        .get_trust_list_publication_entries(non_existent_id, None)
        .await;

    // then
    similar_asserts::assert_eq!(resp.status(), 404);
}
