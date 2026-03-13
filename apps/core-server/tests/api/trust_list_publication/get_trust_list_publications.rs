use one_core::model::trust_list_publication::TrustListPublicationRoleEnum;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_get_trust_list_publications() {
    // given
    let (context, organisation, identifier, certificate, key) =
        TestContext::new_with_certificate_identifier(None).await;
    context
        .db
        .trust_list_publications
        .create(
            "test_trust_list_publication_1",
            TrustListPublicationRoleEnum::PidProvider,
            "LOTE_PUBLISHER".into(),
            serde_json::to_vec(&serde_json::Value::Object(serde_json::Map::new())).unwrap(),
            organisation.clone(),
            identifier.clone(),
            Some(key.id),
            Some(certificate.id),
        )
        .await;
    context
        .db
        .trust_list_publications
        .create(
            "test_trust_list_publication_2",
            TrustListPublicationRoleEnum::WalletProvider,
            "LOTE_PUBLISHER".into(),
            serde_json::to_vec(&serde_json::Value::Object(serde_json::Map::new())).unwrap(),
            organisation.clone(),
            identifier.clone(),
            Some(key.id),
            Some(certificate.id),
        )
        .await;

    // when
    let resp = context
        .api
        .trust_list_publication
        .get_trust_list_publications(Some(format!("organisationId={}", organisation.id)))
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
async fn test_get_trust_list_publications_empty() {
    // given
    let (context, organisation, ..) = TestContext::new_with_certificate_identifier(None).await;

    // when
    let resp = context
        .api
        .trust_list_publication
        .get_trust_list_publications(Some(format!("organisationId={}", organisation.id)))
        .await;

    // then
    similar_asserts::assert_eq!(resp.status(), 200);
    let resp_json = resp.json_value().await;
    similar_asserts::assert_eq!(resp_json["totalItems"].as_u64().unwrap(), 0);
    similar_asserts::assert_eq!(resp_json["totalPages"].as_u64().unwrap(), 0);

    let values = resp_json["values"].as_array().unwrap();
    similar_asserts::assert_eq!(values.len(), 0);
}
