use std::ops::Add;

use one_core::model::certificate::{Certificate, CertificateState};
use one_core::model::identifier::{Identifier, IdentifierType};
use one_core::model::key::Key;
use one_core::model::organisation::Organisation;
use one_core::model::trust_entry::TrustEntryStatusEnum;
use one_core::model::trust_list_publication::TrustListPublicationRoleEnum;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::fixtures::TestingIdentifierParams;
use crate::utils::context::TestContext;
use crate::utils::db_clients::certificates::TestingCertificateParams;

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
            identifier.clone(),
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
            identifier.clone(),
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

#[tokio::test]
async fn test_get_trust_list_publication_entries_sorted_by_identifier() {
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

    let (f_identifier, ..) =
        create_dummy_certificate_identifier(&context, &organisation, &key, "f_identifier").await;
    let (z_identifier, ..) =
        create_dummy_certificate_identifier(&context, &organisation, &key, "z_identifier").await;
    let (a_identifier, ..) =
        create_dummy_certificate_identifier(&context, &organisation, &key, "a_identifier").await;

    context
        .db
        .trust_entries
        .create(
            TrustEntryStatusEnum::Active,
            serde_json::to_vec(&serde_json::Value::Object(serde_json::Map::new())).unwrap(),
            trust_list_publication.clone(),
            f_identifier,
        )
        .await;

    context
        .db
        .trust_entries
        .create(
            TrustEntryStatusEnum::Active,
            serde_json::to_vec(&serde_json::Value::Object(serde_json::Map::new())).unwrap(),
            trust_list_publication.clone(),
            a_identifier,
        )
        .await;

    context
        .db
        .trust_entries
        .create(
            TrustEntryStatusEnum::Active,
            serde_json::to_vec(&serde_json::Value::Object(serde_json::Map::new())).unwrap(),
            trust_list_publication.clone(),
            z_identifier,
        )
        .await;

    // when
    let resp = context
        .api
        .trust_list_publication
        .get_trust_list_publication_entries(trust_list_publication.id, Some("sort=identifier"))
        .await;

    // then
    similar_asserts::assert_eq!(resp.status(), 200);
    let resp_json = resp.json_value().await;
    similar_asserts::assert_eq!(resp_json["totalItems"].as_u64().unwrap(), 3);
    similar_asserts::assert_eq!(resp_json["totalPages"].as_u64().unwrap(), 1);

    let values = resp_json["values"].as_array().unwrap();
    similar_asserts::assert_eq!(values.len(), 3);
    similar_asserts::assert_eq!(values[0]["identifier"]["name"], "a_identifier");
    similar_asserts::assert_eq!(values[1]["identifier"]["name"], "f_identifier");
    similar_asserts::assert_eq!(values[2]["identifier"]["name"], "z_identifier");
}

async fn create_dummy_certificate_identifier(
    context: &TestContext,
    organisation: &Organisation,
    key: &Key,
    identifier_name: impl Into<String>,
) -> (Identifier, Certificate) {
    let identifier_id = Uuid::new_v4().into();
    let now = OffsetDateTime::now_utc();
    let certificate = Certificate {
        id: Uuid::new_v4().into(),
        identifier_id,
        organisation_id: Some(organisation.id),
        created_date: now,
        last_modified: now,
        expiry_date: now.add(Duration::minutes(10)),
        name: Uuid::new_v4().to_string(),
        chain: "".to_string(),
        fingerprint: Uuid::new_v4().to_string(),
        state: CertificateState::Active,
        key: Some(key.clone()),
    };

    let identifier = context
        .db
        .identifiers
        .create(
            organisation,
            TestingIdentifierParams {
                r#type: Some(IdentifierType::Certificate),
                certificates: Some(vec![certificate.clone()]),
                name: Some(identifier_name.into()),
                ..Default::default()
            },
        )
        .await;

    let certificate = context
        .db
        .certificates
        .create(identifier.id, TestingCertificateParams::from(certificate))
        .await;
    (identifier, certificate)
}
