use std::sync::Arc;

use mockall::predicate::eq;
use shared_types::OrganisationId;
use similar_asserts::assert_eq;
use url::Url;
use uuid::Uuid;

use crate::error::{ErrorCode, ErrorCodeMixin};
use crate::model::common::GetListResponse;
use crate::model::organisation::OrganisationRelations;
use crate::model::trust_collection::{
    TrustCollection, TrustCollectionListQuery, TrustCollectionRelations,
};
use crate::model::trust_list_role::TrustListRoleEnum;
use crate::model::trust_list_subscription::{
    TrustListSubscription, TrustListSubscriptionListQuery, TrustListSubscriptionRelations,
    TrustListSubscriptionState,
};
use crate::proto::clock::MockClock;
use crate::proto::session_provider::test::StaticSessionProvider;
use crate::provider::trust_list_subscriber::provider::MockTrustListSubscriberProvider;
use crate::provider::trust_list_subscriber::{
    MockTrustListSubscriber, TrustListSubscriberCapabilities, TrustListValidationSuccess,
};
use crate::repository::error::DataLayerError;
use crate::repository::organisation_repository::MockOrganisationRepository;
use crate::repository::trust_collection_repository::MockTrustCollectionRepository;
use crate::repository::trust_list_subscription_repository::MockTrustListSubscriptionRepository;
use crate::service::test_utilities::{dummy_organisation, get_dummy_date};
use crate::service::trust_collection::TrustCollectionService;
use crate::service::trust_collection::dto::{
    CreateTrustCollectionRequestDTO, CreateTrustListSubscriptionRequestDTO,
};
use crate::service::trust_collection::error::TrustCollectionServiceError;

#[derive(Default)]
struct Mocks {
    trust_collection_repository: MockTrustCollectionRepository,
    trust_list_subscription_repository: MockTrustListSubscriptionRepository,
    trust_list_subscriber_provider: MockTrustListSubscriberProvider,
    session_provider: StaticSessionProvider,
    clock: MockClock,
}

fn mock_service(mocks: Mocks) -> TrustCollectionService {
    TrustCollectionService::new(
        Arc::new(mocks.trust_collection_repository),
        Arc::new(mocks.trust_list_subscription_repository),
        Arc::new(mocks.trust_list_subscriber_provider),
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
    let mut organisation_repository = MockOrganisationRepository::new();
    let mut clock = MockClock::new();

    let session_provider = StaticSessionProvider::new_random();
    let organisation_id = session_provider.0.organisation_id.unwrap();

    let request = CreateTrustCollectionRequestDTO {
        name: "new collection".to_string(),
        organisation_id,
    };

    let now = get_dummy_date();
    clock.expect_now_utc().returning(move || now);

    organisation_repository
        .expect_get_organisation()
        .with(eq(organisation_id), eq(OrganisationRelations::default()))
        .returning(move |id, _| Ok(Some(dummy_organisation(Some(*id)))));

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
    let mut organisation_repository = MockOrganisationRepository::new();
    let mut clock = MockClock::new();

    let session_provider = StaticSessionProvider::new_random();
    let organisation_id = session_provider.0.organisation_id.unwrap();

    let request = CreateTrustCollectionRequestDTO {
        name: "new collection".to_string(),
        organisation_id,
    };

    let now = get_dummy_date();
    clock.expect_now_utc().returning(move || now);

    organisation_repository
        .expect_get_organisation()
        .with(eq(organisation_id), eq(OrganisationRelations::default()))
        .returning(move |id, _| Ok(Some(dummy_organisation(Some(*id)))));

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
        TrustCollectionServiceError::TrustCollectionAlreadyExists
    ));
}

#[tokio::test]
async fn test_delete_trust_collection_success() {
    // given
    let mut trust_collection_repository = MockTrustCollectionRepository::new();
    let mut trust_list_subscription_repository = MockTrustListSubscriptionRepository::new();
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

    trust_list_subscription_repository
        .expect_list()
        .returning(|_| {
            Ok(GetListResponse {
                values: vec![],
                total_pages: 0,
                total_items: 0,
            })
        });

    let service = mock_service(Mocks {
        trust_collection_repository,
        session_provider,
        clock,
        trust_list_subscription_repository,
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
        TrustCollectionServiceError::TrustCollectionNotFound(_)
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

#[tokio::test]
async fn test_create_trust_list_subscription_success() {
    // given
    let mut trust_collection_repository = MockTrustCollectionRepository::new();
    let mut trust_list_subscription_repository = MockTrustListSubscriptionRepository::new();
    let mut trust_list_subscriber_provider = MockTrustListSubscriberProvider::new();
    let mut clock = MockClock::new();

    let session_provider = StaticSessionProvider::new_random();
    let organisation_id = session_provider.0.organisation_id.unwrap();

    let trust_collection = dummy_trust_collection(organisation_id);
    let trust_collection_id = trust_collection.id;

    let request = CreateTrustListSubscriptionRequestDTO {
        name: "test subscription".to_string(),
        role: Some(TrustListRoleEnum::Verifier),
        reference: Url::parse("http://test.com").unwrap(),
        r#type: "test".into(),
    };

    let now = get_dummy_date();
    clock.expect_now_utc().returning(move || now);

    trust_collection_repository
        .expect_get()
        .with(
            eq(trust_collection_id),
            eq(TrustCollectionRelations::default()),
        )
        .returning(move |_, _| Ok(Some(trust_collection.clone())));

    let mut trust_list_subscriber = MockTrustListSubscriber::new();
    trust_list_subscriber
        .expect_validate_subscription()
        .returning(|_, role| {
            Ok(TrustListValidationSuccess {
                role: role.unwrap_or(TrustListRoleEnum::Verifier),
            })
        });
    trust_list_subscriber
        .expect_get_capabilities()
        .returning(|| TrustListSubscriberCapabilities {
            roles: vec![TrustListRoleEnum::Verifier],
        });

    let trust_list_subscriber_arc: Arc<
        dyn crate::provider::trust_list_subscriber::TrustListSubscriber,
    > = Arc::new(trust_list_subscriber);
    let type_id = request.r#type.clone();
    trust_list_subscriber_provider
        .expect_get()
        .with(eq(type_id))
        .returning(move |_| Some(trust_list_subscriber_arc.clone()));

    trust_list_subscription_repository
        .expect_create()
        .returning(|_| Ok(Uuid::new_v4().into()));

    let service = mock_service(Mocks {
        trust_collection_repository,
        trust_list_subscription_repository,
        trust_list_subscriber_provider,
        session_provider,
        clock,
    });

    // when
    let result = service
        .create_trust_list_subscription(trust_collection_id, request)
        .await;

    // then
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_create_trust_list_subscription_org_mismatch() {
    // given
    let mut trust_collection_repository = MockTrustCollectionRepository::new();
    let other_organisation_id = Uuid::new_v4().into();
    let trust_collection = dummy_trust_collection(other_organisation_id);
    let trust_collection_id = trust_collection.id;

    trust_collection_repository
        .expect_get()
        .returning(move |_, _| Ok(Some(trust_collection.clone())));

    let request = CreateTrustListSubscriptionRequestDTO {
        name: "test subscription".to_string(),
        role: Some(TrustListRoleEnum::Verifier),
        reference: Url::parse("http://test.com").unwrap(),
        r#type: "test".into(),
    };

    let service = mock_service(Mocks {
        trust_collection_repository,
        ..Default::default()
    });

    // when
    let result = service
        .create_trust_list_subscription(trust_collection_id, request)
        .await;

    // then
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);
}

#[tokio::test]
async fn test_create_trust_list_subscription_validation_fails() {
    // given
    let mut trust_collection_repository = MockTrustCollectionRepository::new();
    let mut trust_list_subscriber_provider = MockTrustListSubscriberProvider::new();

    let session_provider = StaticSessionProvider::new_random();
    let organisation_id = session_provider.0.organisation_id.unwrap();

    let trust_collection = dummy_trust_collection(organisation_id);
    let trust_collection_id = trust_collection.id;

    let request = CreateTrustListSubscriptionRequestDTO {
        name: "test subscription".to_string(),
        role: Some(TrustListRoleEnum::Verifier),
        reference: Url::parse("http://test.com").unwrap(),
        r#type: "test".into(),
    };

    trust_collection_repository
        .expect_get()
        .returning(move |_, _| Ok(Some(trust_collection.clone())));

    let mut trust_list_subscriber = MockTrustListSubscriber::new();
    trust_list_subscriber
        .expect_validate_subscription()
        .returning(|_, _| {
            Err(crate::provider::trust_list_subscriber::error::TrustListSubscriberError::UnknownTrustListRole)
        });

    let trust_list_subscriber_arc: Arc<
        dyn crate::provider::trust_list_subscriber::TrustListSubscriber,
    > = Arc::new(trust_list_subscriber);
    trust_list_subscriber_provider
        .expect_get()
        .returning(move |_| Some(trust_list_subscriber_arc.clone()));

    let service = mock_service(Mocks {
        trust_collection_repository,
        trust_list_subscriber_provider,
        session_provider,
        ..Default::default()
    });

    // when
    let result = service
        .create_trust_list_subscription(trust_collection_id, request)
        .await;

    // then
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0047);
}

#[tokio::test]
async fn test_create_trust_list_subscription_not_found() {
    // given
    let mut trust_collection_repository = MockTrustCollectionRepository::new();
    let trust_collection_id = Uuid::new_v4().into();

    trust_collection_repository
        .expect_get()
        .returning(move |_, _| Ok(None));

    let request = CreateTrustListSubscriptionRequestDTO {
        name: "test subscription".to_string(),
        role: Some(TrustListRoleEnum::Verifier),
        reference: Url::parse("http://test.com").unwrap(),
        r#type: "test".into(),
    };

    let service = mock_service(Mocks {
        trust_collection_repository,
        ..Default::default()
    });

    // when
    let result = service
        .create_trust_list_subscription(trust_collection_id, request)
        .await;

    // then
    assert!(matches!(
        result,
        Err(TrustCollectionServiceError::TrustCollectionNotFound(_))
    ));
}

#[tokio::test]
async fn test_delete_trust_list_subscription_success() {
    // given
    let trust_collection_repository = MockTrustCollectionRepository::new();
    let mut trust_list_subscription_repository = MockTrustListSubscriptionRepository::new();

    let session_provider = StaticSessionProvider::new_random();
    let organisation_id = session_provider.0.organisation_id.unwrap();

    let trust_collection = dummy_trust_collection(organisation_id);
    let trust_list_subscription_id = Uuid::new_v4().into();

    let now = get_dummy_date();
    let trust_list_subscription = TrustListSubscription {
        id: trust_list_subscription_id,
        name: "test subscription".to_string(),
        created_date: now,
        last_modified: now,
        deactivated_at: None,
        r#type: "test".into(),
        reference: "http://test.com".to_string(),
        role: TrustListRoleEnum::Verifier,
        state: TrustListSubscriptionState::Active,
        trust_collection_id: trust_collection.id,
        trust_collection: Some(trust_collection),
    };

    trust_list_subscription_repository
        .expect_get()
        .with(
            eq(trust_list_subscription_id),
            eq(TrustListSubscriptionRelations {
                trust_collection: Some(Default::default()),
            }),
        )
        .returning(move |_, _| Ok(Some(trust_list_subscription.clone())));

    trust_list_subscription_repository
        .expect_delete()
        .with(eq(trust_list_subscription_id))
        .returning(|_| Ok(()));

    let service = mock_service(Mocks {
        trust_collection_repository,
        trust_list_subscription_repository,
        session_provider,
        ..Default::default()
    });

    // when
    let result = service
        .delete_trust_list_subscription(trust_list_subscription_id)
        .await;

    // then
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_delete_trust_list_subscription_not_found() {
    // given
    let mut trust_list_subscription_repository = MockTrustListSubscriptionRepository::new();
    let trust_list_subscription_id = Uuid::new_v4().into();

    trust_list_subscription_repository
        .expect_get()
        .returning(|_, _| Ok(None));

    let service = mock_service(Mocks {
        trust_list_subscription_repository,
        ..Default::default()
    });

    // when
    let result = service
        .delete_trust_list_subscription(trust_list_subscription_id)
        .await;

    // then
    assert!(matches!(
        result,
        Err(TrustCollectionServiceError::TrustListSubscriptionNotFound(
            _
        ))
    ));
}

#[tokio::test]
async fn test_get_trust_list_subscription_list_success() {
    // given
    let session_provider = StaticSessionProvider::new_random();
    let org_id = session_provider.0.organisation_id.unwrap();
    let mut trust_collection_repository = MockTrustCollectionRepository::new();
    trust_collection_repository
        .expect_get()
        .returning(move |_, _| Ok(Some(dummy_trust_collection(org_id))));
    let mut trust_list_subscription_repository = MockTrustListSubscriptionRepository::new();

    let trust_collection_id = Uuid::new_v4().into();
    let query = TrustListSubscriptionListQuery::default();

    trust_list_subscription_repository
        .expect_list()
        .returning(|_| {
            Ok(crate::model::common::GetListResponse {
                values: vec![],
                total_items: 0,
                total_pages: 0,
            })
        });

    let service = mock_service(Mocks {
        trust_collection_repository,
        trust_list_subscription_repository,
        session_provider,
        ..Default::default()
    });

    // when
    let result = service
        .get_trust_list_subscription_list(trust_collection_id, query)
        .await;

    // then
    assert!(result.is_ok());
}
