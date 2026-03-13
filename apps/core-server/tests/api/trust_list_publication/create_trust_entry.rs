use core_server::endpoint::trust_list_publication::dto::TrustListPublicationRoleRestEnum;
use one_core::model::history::{HistoryAction, HistoryEntityType};
use one_core::model::trust_list_publication::TrustListPublicationRoleEnum;
use uuid::Uuid;

use crate::fixtures::{create_identifier, create_organisation};
use crate::utils::api_clients::trust_list_publication::CreateTrustListPublicationTestParams;
use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_create_trust_enty() {
    // given
    let (context, organisation, identifier, ..) =
        TestContext::new_with_certificate_identifier(None).await;
    let resp = context
        .api
        .trust_list_publication
        .create_trust_list_publication(CreateTrustListPublicationTestParams {
            identifier_id: identifier.id,
            organisation_id: organisation.id,
            name: "test_trust_list_publication",
            role: TrustListPublicationRoleRestEnum::PidProvider,
            r#type: "LOTE_PUBLISHER".into(),
            key_id: None,
            certificate_id: None,
            params: None,
        })
        .await;
    similar_asserts::assert_eq!(resp.status(), 201);
    let publication_id: shared_types::TrustListPublicationId =
        resp.json_value().await["id"].parse::<Uuid>().into();

    let history_list = context
        .db
        .histories
        .get_by_entity_id(&publication_id.into())
        .await;
    let history_count_before = history_list.total_items;

    // when
    let resp = context
        .api
        .trust_list_publication
        .create_trust_entry(publication_id, identifier.id, None)
        .await;

    // then
    similar_asserts::assert_eq!(resp.status(), 201);
    let resp_json = resp.json_value().await;
    let entry_id = resp_json["id"].parse::<Uuid>().into();
    let existing_trust_entry = context.db.trust_entries.get(entry_id).await.unwrap();
    similar_asserts::assert_eq!(existing_trust_entry.identifier_id, identifier.id);
    similar_asserts::assert_eq!(
        existing_trust_entry.trust_list_publication_id,
        publication_id
    );

    // verify history entry on parent publication (sign_trust_list updates it)
    let history_list = context
        .db
        .histories
        .get_by_entity_id(&publication_id.into())
        .await;
    similar_asserts::assert_eq!(history_count_before + 1, history_list.total_items);
    let last = history_list.values.first().unwrap();
    similar_asserts::assert_eq!(HistoryAction::Updated, last.action);
    similar_asserts::assert_eq!(HistoryEntityType::TrustListPublication, last.entity_type);
}

#[tokio::test]
async fn test_create_trust_entry_certificate_authority() {
    // given
    let (context, organisation, identifier, certificate, key) =
        TestContext::new_with_ca_identifier(None).await;
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
        .create_trust_entry(trust_list_publication.id, identifier.id, None)
        .await;

    // then
    similar_asserts::assert_eq!(resp.status(), 201);
    let resp_json = resp.json_value().await;
    let entry_id = resp_json["id"].parse::<Uuid>().into();
    let existing_trust_entry = context.db.trust_entries.get(entry_id).await.unwrap();
    similar_asserts::assert_eq!(existing_trust_entry.identifier_id, identifier.id);
    similar_asserts::assert_eq!(
        existing_trust_entry.trust_list_publication_id,
        trust_list_publication.id
    );
}

#[tokio::test]
async fn test_fail_to_create_trust_entry_organisation_mismatch() {
    // given
    let (context, _organisation, identifier, certificate, key) =
        TestContext::new_with_certificate_identifier(None).await;
    let other_organisation = create_organisation(&context.db.db_conn).await;
    let trust_list_publication = context
        .db
        .trust_list_publications
        .create(
            "test_trust_list_publication",
            TrustListPublicationRoleEnum::PidProvider,
            "LOTE_PUBLISHER".into(),
            serde_json::to_vec(&serde_json::Value::Object(serde_json::Map::new())).unwrap(),
            other_organisation.clone(),
            identifier.clone(),
            Some(key.id),
            Some(certificate.id),
        )
        .await;

    // when
    let resp = context
        .api
        .trust_list_publication
        .create_trust_entry(trust_list_publication.id, identifier.id, None)
        .await;

    // then
    similar_asserts::assert_eq!(resp.status(), 400);
    similar_asserts::assert_eq!("BR_0285", resp.error_code().await);
}

#[tokio::test]
async fn test_fail_to_create_trust_entry_missing_entry_identifier_capabilities() {
    // given
    let (context, organisation, identifier, certificate, key) =
        TestContext::new_with_certificate_identifier(None).await;
    let did_identifier = create_identifier(&context.db.db_conn, &organisation.clone(), None).await;
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
        .create_trust_entry(trust_list_publication.id, did_identifier.id, None)
        .await;

    // then
    similar_asserts::assert_eq!(resp.status(), 400);
    similar_asserts::assert_eq!("BR_0382", resp.error_code().await);
}
