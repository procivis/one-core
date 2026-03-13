use one_core::model::trust_list_publication::TrustListPublicationRoleEnum;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_get_trust_list_publication() {
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

    // when
    let resp = context
        .api
        .trust_list_publication
        .get_trust_list_publication(trust_list_publication.id)
        .await;

    // then
    similar_asserts::assert_eq!(resp.status(), 200);
    let resp_json = resp.json_value().await;
    similar_asserts::assert_eq!(
        resp_json["id"].as_str().unwrap(),
        trust_list_publication.id.to_string()
    );
    similar_asserts::assert_eq!(
        resp_json["name"].as_str().unwrap(),
        "test_trust_list_publication"
    );
    similar_asserts::assert_eq!(resp_json["role"].as_str().unwrap(), "PID_PROVIDER");
}

#[tokio::test]
async fn test_fail_to_get_trust_list_publication_not_found() {
    // given
    let (context, ..) = TestContext::new_with_certificate_identifier(None).await;
    let non_existent_id = uuid::Uuid::new_v4().into();

    // when
    let resp = context
        .api
        .trust_list_publication
        .get_trust_list_publication(non_existent_id)
        .await;

    // then
    similar_asserts::assert_eq!(resp.status(), 404);
}
