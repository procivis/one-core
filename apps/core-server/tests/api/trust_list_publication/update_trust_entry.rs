use core_server::endpoint::trust_list_publication::dto::{
    TrustEntryStatusRestEnum, TrustListPublicationRoleRestEnum,
};
use one_core::model::history::{HistoryAction, HistoryEntityType};
use one_core::model::trust_entry::TrustEntryStatusEnum;
use one_core::model::trust_list_publication::TrustListPublicationRoleEnum;
use uuid::Uuid;

use crate::utils::api_clients::trust_list_publication::CreateTrustListPublicationTestParams;
use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_update_trust_entry() {
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
    let publication_id = resp.json_value().await["id"].parse::<Uuid>().into();

    let resp = context
        .api
        .trust_list_publication
        .create_trust_entry(publication_id, identifier.id, None)
        .await;
    similar_asserts::assert_eq!(resp.status(), 201);
    let entry_id = resp.json_value().await["id"].parse::<Uuid>().into();

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
        .update_trust_entry(
            publication_id,
            entry_id,
            Some(TrustEntryStatusRestEnum::Suspended),
            None,
        )
        .await;

    // then
    similar_asserts::assert_eq!(resp.status(), 204);

    // verify update
    let updated_entry = context.db.trust_entries.get(entry_id).await.unwrap();
    similar_asserts::assert_eq!(updated_entry.status, TrustEntryStatusEnum::Suspended);

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
