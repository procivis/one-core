use mockall::predicate::eq;
use similar_asserts::assert_eq;
use uuid::Uuid;

use super::*;
use crate::model::common::GetListResponse;
use crate::model::trust_list_publication::TrustListPublication;
use crate::provider::trust_list_publisher::MockTrustListPublisher;
use crate::provider::trust_list_publisher::error::TrustListPublisherError;
use crate::provider::trust_list_publisher::provider::MockTrustListPublisherProvider;
use crate::repository::error::DataLayerError;
use crate::repository::trust_list_publication_repository::MockTrustListPublicationRepository;
use crate::service::test_utilities::dummy_trust_list_publication;

fn publications_for_identifier(
    identifier_id: IdentifierId,
    publications: Vec<TrustListPublication>,
) -> MockTrustListPublicationRepository {
    let mut repository = MockTrustListPublicationRepository::new();
    repository
        .expect_list()
        .withf(move |query| {
            matches!(
                &query.filtering,
                Some(crate::model::list_filter::ListFilterCondition::Value(
                    TrustListPublicationFilterValue::TrustEntryIdentifierId(id)
                )) if *id == identifier_id
            ) && query.pagination.is_none()
                && !query.include_count
        })
        .once()
        .return_once(move |_| {
            Ok(GetListResponse {
                values: publications,
                total_items: None,
                total_pages: None,
            })
        });
    repository
}

#[tokio::test]
async fn regenerates_all_lists_with_their_respective_publishers() {
    let identifier_id = Uuid::new_v4().into();
    let publications: Vec<_> = ["LOTE_JWT", "LOTE_XML", "LOTE_JWT"]
        .into_iter()
        .map(|publisher| TrustListPublication {
            r#type: publisher.into(),
            ..dummy_trust_list_publication()
        })
        .collect();
    let mut provider = MockTrustListPublisherProvider::new();
    let mut jwt = MockTrustListPublisher::new();
    let mut xml = MockTrustListPublisher::new();
    for publication in &publications {
        let publisher = if publication.r#type == "LOTE_JWT".into() {
            &mut jwt
        } else {
            &mut xml
        };
        publisher
            .expect_regenerate_content()
            .with(eq(publication.id))
            .once()
            .returning(|_| Ok(()));
    }
    let jwt = Arc::new(jwt);
    provider
        .expect_get()
        .with(eq(TrustListPublisherId::from("LOTE_JWT")))
        .times(2)
        .returning(move |_| Some(jwt.clone()));
    provider
        .expect_get()
        .with(eq(TrustListPublisherId::from("LOTE_XML")))
        .once()
        .return_once(move |_| Some(Arc::new(xml)));

    let proto = TrustListRegeneratorImpl::new(
        Arc::new(publications_for_identifier(identifier_id, publications)),
        Arc::new(provider),
    );
    proto
        .regenerate_for_identifier(identifier_id)
        .await
        .unwrap();
}

#[tokio::test]
async fn unpublished_identifier_does_not_call_any_publisher() {
    let identifier_id = Uuid::new_v4().into();
    let proto = TrustListRegeneratorImpl::new(
        Arc::new(publications_for_identifier(identifier_id, vec![])),
        Arc::new(MockTrustListPublisherProvider::new()),
    );
    proto
        .regenerate_for_identifier(identifier_id)
        .await
        .unwrap();
}

#[tokio::test]
async fn missing_publisher_is_reported() {
    let identifier_id = Uuid::new_v4().into();
    let publication = dummy_trust_list_publication();
    let publisher_id = publication.r#type.clone();
    let mut provider = MockTrustListPublisherProvider::new();
    provider.expect_get().once().returning(|_| None);
    let proto = TrustListRegeneratorImpl::new(
        Arc::new(publications_for_identifier(
            identifier_id,
            vec![publication],
        )),
        Arc::new(provider),
    );

    assert!(matches!(
        proto.regenerate_for_identifier(identifier_id).await,
        Err(Error::MissingPublisher(id)) if id == publisher_id
    ));
}

#[tokio::test]
async fn regeneration_failure_is_propagated() {
    let identifier_id = Uuid::new_v4().into();
    let mut publisher = MockTrustListPublisher::new();
    publisher
        .expect_regenerate_content()
        .once()
        .returning(|_| Err(TrustListPublisherError::Signing("signing failed".into())));
    let mut provider = MockTrustListPublisherProvider::new();
    provider
        .expect_get()
        .once()
        .return_once(|_| Some(Arc::new(publisher)));
    let proto = TrustListRegeneratorImpl::new(
        Arc::new(publications_for_identifier(
            identifier_id,
            vec![dummy_trust_list_publication()],
        )),
        Arc::new(provider),
    );

    let error = proto
        .regenerate_for_identifier(identifier_id)
        .await
        .unwrap_err();
    assert_eq!(error.error_code(), ErrorCode::BR_0384);
}

#[tokio::test]
async fn listing_failure_is_propagated() {
    let mut repository = MockTrustListPublicationRepository::new();
    repository
        .expect_list()
        .once()
        .returning(|_| Err(DataLayerError::Db(anyhow::anyhow!("listing failed"))));
    let proto = TrustListRegeneratorImpl::new(
        Arc::new(repository),
        Arc::new(MockTrustListPublisherProvider::new()),
    );

    assert!(
        proto
            .regenerate_for_identifier(Uuid::new_v4().into())
            .await
            .is_err()
    );
}
