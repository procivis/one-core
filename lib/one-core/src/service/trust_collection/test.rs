use std::sync::Arc;

use mockall::predicate::eq;
use shared_types::OrganisationId;
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::error::{ErrorCode, ErrorCodeMixin};
use crate::model::trust_collection::{
    TrustCollection, TrustCollectionListQuery, TrustCollectionRelations,
};
use crate::proto::clock::MockClock;
use crate::proto::session_provider::test::StaticSessionProvider;
use crate::repository::error::DataLayerError;
use crate::repository::trust_collection_repository::MockTrustCollectionRepository;
use crate::repository::trust_list_subscription_repository::MockTrustListSubscriptionRepository;
use crate::service::test_utilities::get_dummy_date;
use crate::service::trust_collection::TrustCollectionService;
use crate::service::trust_collection::dto::CreateTrustCollectionRequestDTO;
use crate::service::trust_collection::error::TrustCollectionServiceError;

#[derive(Default)]
struct Mocks {
    trust_collection_repository: MockTrustCollectionRepository,
    trust_list_subscription_repository: MockTrustListSubscriptionRepository,
    session_provider: StaticSessionProvider,
    clock: MockClock,
}

fn mock_service(mocks: Mocks) -> TrustCollectionService {
    TrustCollectionService::new(
        Arc::new(mocks.trust_collection_repository),
        Arc::new(mocks.trust_list_subscription_repository),
        Arc::new(mocks.session_provider),
        Arc::new(mocks.clock),
    )
}

fn dummy_trust_collection(organisation_id: OrganisationId) -> TrustCollection {
    let now = get_dummy_date();
    TrustCollection {
        id: Uuid::new_v4().into(),
        name: "test trust collection".to_string(),
        created_date: now,
        last_modified: now,
        deactivated_at: None,
        remote_trust_collection_url: None,
        organisation_id,
        organisation: None,
    }
}

#[tokio::test]
async fn test_create_trust_collection_success() {
    // given
    let mut trust_collection_repository = MockTrustCollectionRepository::new();
    let mut clock = MockClock::new();

    let session_provider = StaticSessionProvider::new_random();
    let organisation_id = session_provider.0.organisation_id.unwrap();

    let request = CreateTrustCollectionRequestDTO {
        name: "new collection".to_string(),
        organisation_id,
    };

    let now = get_dummy_date();
    clock.expect_now_utc().returning(move || now);

    trust_collection_repository
        .expect_create()
        .withf(move |tc| tc.name == "new collection" && tc.organisation_id == organisation_id)
        .returning(|_| Ok(Uuid::new_v4().into()));

    let service = mock_service(Mocks {
        trust_collection_repository,
        session_provider,
        clock,
        ..Default::default()
    });

    // when
    let result = service.create_trust_collection(request).await;

    // then
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_create_trust_collection_org_mismatch() {
    // given
    let other_organisation_id = Uuid::new_v4().into();
    let request = CreateTrustCollectionRequestDTO {
        name: "new collection".to_string(),
        organisation_id: other_organisation_id,
    };
    let service = mock_service(Default::default());

    // when
    let result = service.create_trust_collection(request).await;

    // then
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);
}

#[tokio::test]
async fn test_create_trust_collection_already_exists() {
    // given
    let mut trust_collection_repository = MockTrustCollectionRepository::new();
    let mut clock = MockClock::new();

    let session_provider = StaticSessionProvider::new_random();
    let organisation_id = session_provider.0.organisation_id.unwrap();

    let request = CreateTrustCollectionRequestDTO {
        name: "new collection".to_string(),
        organisation_id,
    };

    let now = get_dummy_date();
    clock.expect_now_utc().returning(move || now);

    trust_collection_repository
        .expect_create()
        .returning(|_| Err(DataLayerError::AlreadyExists));

    let service = mock_service(Mocks {
        trust_collection_repository,
        session_provider,
        clock,
        ..Default::default()
    });

    // when
    let result = service.create_trust_collection(request).await;

    // then
    assert!(matches!(
        result.unwrap_err(),
        TrustCollectionServiceError::AlreadyExists
    ));
}

#[tokio::test]
async fn test_delete_trust_collection_success() {
    // given
    let mut trust_collection_repository = MockTrustCollectionRepository::new();
    let clock = MockClock::new();

    let session_provider = StaticSessionProvider::new_random();
    let organisation_id = session_provider.0.organisation_id.unwrap();

    let trust_collection = dummy_trust_collection(organisation_id);
    let trust_collection_id = trust_collection.id;

    trust_collection_repository
        .expect_get()
        .with(
            eq(trust_collection_id),
            eq(TrustCollectionRelations::default()),
        )
        .returning(move |_, _| Ok(Some(trust_collection.clone())));

    trust_collection_repository
        .expect_delete()
        .with(eq(trust_collection_id))
        .returning(|_| Ok(()));

    let service = mock_service(Mocks {
        trust_collection_repository,
        session_provider,
        clock,
        ..Default::default()
    });

    // when
    let result = service.delete_trust_collection(trust_collection_id).await;

    // then
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_delete_trust_collection_not_found() {
    // given
    let mut trust_collection_repository = MockTrustCollectionRepository::new();
    let trust_collection_id = Uuid::new_v4().into();

    trust_collection_repository
        .expect_get()
        .returning(|_, _| Ok(None));

    let service = mock_service(Mocks {
        trust_collection_repository,
        ..Default::default()
    });

    // when
    let result = service.delete_trust_collection(trust_collection_id).await;

    // then
    assert!(matches!(
        result.unwrap_err(),
        TrustCollectionServiceError::NotFound(_)
    ));
}

#[tokio::test]
async fn test_delete_trust_collection_org_mismatch() {
    // given
    let mut trust_collection_repository = MockTrustCollectionRepository::new();
    let other_organisation_id = Uuid::new_v4().into();

    let trust_collection = dummy_trust_collection(other_organisation_id);
    let trust_collection_id = trust_collection.id;

    trust_collection_repository
        .expect_get()
        .with(
            eq(trust_collection_id),
            eq(TrustCollectionRelations::default()),
        )
        .returning(move |_, _| Ok(Some(trust_collection.clone())));

    let service = mock_service(Mocks {
        trust_collection_repository,
        ..Default::default()
    });

    // when
    let result = service.delete_trust_collection(trust_collection_id).await;

    // then
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);
}

#[tokio::test]
async fn test_get_trust_collection_success() {
    // given
    let mut trust_collection_repository = MockTrustCollectionRepository::new();

    let session_provider = StaticSessionProvider::new_random();
    let organisation_id = session_provider.0.organisation_id.unwrap();

    let trust_collection = dummy_trust_collection(organisation_id);
    let trust_collection_id = trust_collection.id;

    trust_collection_repository
        .expect_get()
        .with(
            eq(trust_collection_id),
            eq(TrustCollectionRelations::default()),
        )
        .returning(move |_, _| Ok(Some(trust_collection.clone())));

    let service = mock_service(Mocks {
        trust_collection_repository,
        session_provider,
        ..Default::default()
    });

    // when
    let result = service.get_trust_collection(trust_collection_id).await;

    // then
    assert!(result.is_ok());
    assert_eq!(result.unwrap().id, trust_collection_id);
}

#[tokio::test]
async fn test_get_trust_collection_list_success() {
    // given
    let mut trust_collection_repository = MockTrustCollectionRepository::new();

    let session_provider = StaticSessionProvider::new_random();
    let organisation_id = session_provider.0.organisation_id.unwrap();

    let query = TrustCollectionListQuery::default();

    trust_collection_repository.expect_list().returning(|_| {
        Ok(crate::model::common::GetListResponse {
            values: vec![],
            total_items: 0,
            total_pages: 0,
        })
    });

    let service = mock_service(Mocks {
        trust_collection_repository,
        session_provider,
        ..Default::default()
    });

    // when
    let result = service
        .get_trust_collection_list(organisation_id, query)
        .await;

    // then
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_get_trust_collection_list_org_mismatch() {
    // given
    let other_organisation_id = Uuid::new_v4().into();
    let query = TrustCollectionListQuery::default();

    let service = mock_service(Default::default());

    // when
    let result = service
        .get_trust_collection_list(other_organisation_id, query)
        .await;

    // then
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);
}
