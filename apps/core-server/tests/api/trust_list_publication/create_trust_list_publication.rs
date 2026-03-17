use core_server::endpoint::trust_list_publication::dto::TrustListRoleRestEnum;
use one_core::model::history::{HistoryAction, HistoryEntityType};
use one_core::model::trust_list_role::TrustListRoleEnum;
use uuid::Uuid;

use crate::fixtures::create_organisation;
use crate::utils::api_clients::trust_list_publication::CreateTrustListPublicationTestParams;
use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_create_trust_list_publication() {
    // given
    let (context, organisation, identifier, ..) =
        TestContext::new_with_certificate_identifier(None).await;

    // when
    let resp = context
        .api
        .trust_list_publication
        .create_trust_list_publication(CreateTrustListPublicationTestParams {
            identifier_id: identifier.id,
            organisation_id: organisation.id,
            name: "name",
            role: TrustListRoleRestEnum::PidProvider,
            r#type: "LOTE_PUBLISHER".into(),
            key_id: None,
            certificate_id: None,
            params: None,
        })
        .await;

    // then
    similar_asserts::assert_eq!(resp.status(), 201);
    let resp_json = resp.json_value().await;
    let publication_id = resp_json["id"].parse::<Uuid>().into();
    let existing_trust_list_publication = context
        .db
        .trust_list_publications
        .get(publication_id)
        .await
        .unwrap();
    similar_asserts::assert_eq!(existing_trust_list_publication.name, "name");
    similar_asserts::assert_eq!(
        existing_trust_list_publication.role,
        TrustListRoleEnum::PidProvider
    );
    similar_asserts::assert_eq!(existing_trust_list_publication.identifier_id, identifier.id);
    similar_asserts::assert_eq!(
        existing_trust_list_publication.organisation_id,
        organisation.id
    );

    // verify history entry
    let history_list = context
        .db
        .histories
        .get_by_entity_id(&publication_id.into())
        .await;
    similar_asserts::assert_eq!(1, history_list.total_items);
    let last = history_list.values.first().unwrap();
    similar_asserts::assert_eq!(HistoryAction::Created, last.action);
    similar_asserts::assert_eq!(HistoryEntityType::TrustListPublication, last.entity_type);
}

#[tokio::test]
async fn test_fail_to_create_trust_list_publication_missing_trust_list_publisher() {
    // given
    let (context, organisation, identifier, ..) =
        TestContext::new_with_certificate_identifier(None).await;

    // when
    let resp = context
        .api
        .trust_list_publication
        .create_trust_list_publication(CreateTrustListPublicationTestParams {
            name: "name",
            role: TrustListRoleRestEnum::PidProvider,
            r#type: "UnknownProvider".into(),
            identifier_id: identifier.id,
            organisation_id: organisation.id,
            key_id: None,
            certificate_id: None,
            params: None,
        })
        .await;

    // then
    similar_asserts::assert_eq!(resp.status(), 400);
    similar_asserts::assert_eq!("BR_0388", resp.error_code().await);
}

#[tokio::test]
async fn test_fail_to_create_trust_list_publication_missing_role_capabilities() {
    // given
    let (context, organisation, identifier, ..) =
        TestContext::new_with_certificate_identifier(None).await;

    // when
    let resp = context
        .api
        .trust_list_publication
        .create_trust_list_publication(CreateTrustListPublicationTestParams {
            name: "name",
            role: TrustListRoleRestEnum::Issuer,
            r#type: "LOTE_PUBLISHER".into(),
            identifier_id: identifier.id,
            organisation_id: organisation.id,
            key_id: None,
            certificate_id: None,
            params: None,
        })
        .await;

    // then
    similar_asserts::assert_eq!(resp.status(), 400);
    similar_asserts::assert_eq!("BR_0386", resp.error_code().await);
}

#[tokio::test]
async fn test_fail_to_create_trust_list_publication_mismatch_organisation() {
    // given
    let (context, _organisation, identifier, ..) =
        TestContext::new_with_certificate_identifier(None).await;
    let other_organisation = create_organisation(&context.db.db_conn).await;

    // when
    let resp = context
        .api
        .trust_list_publication
        .create_trust_list_publication(CreateTrustListPublicationTestParams {
            name: "name",
            role: TrustListRoleRestEnum::PidProvider,
            r#type: "LOTE_PUBLISHER".into(),
            identifier_id: identifier.id,
            organisation_id: other_organisation.id,
            key_id: None,
            certificate_id: None,
            params: None,
        })
        .await;

    // then
    similar_asserts::assert_eq!(resp.status(), 400);
    similar_asserts::assert_eq!("BR_0285", resp.error_code().await);
}

#[tokio::test]
async fn test_fail_to_create_trust_list_publication_missing_identifier_type_capabilities() {
    // given
    let (context, organisation, _did, identifier, ..) = TestContext::new_with_did(None).await;

    // when
    let resp = context
        .api
        .trust_list_publication
        .create_trust_list_publication(CreateTrustListPublicationTestParams {
            name: "name",
            role: TrustListRoleRestEnum::PidProvider,
            r#type: "LOTE_PUBLISHER".into(),
            identifier_id: identifier.id,
            organisation_id: organisation.id,
            key_id: None,
            certificate_id: None,
            params: None,
        })
        .await;

    // then
    similar_asserts::assert_eq!(resp.status(), 400);
    similar_asserts::assert_eq!("BR_0382", resp.error_code().await);
}
