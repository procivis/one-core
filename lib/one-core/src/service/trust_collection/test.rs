use std::sync::Arc;

use mockall::predicate::eq;
use shared_types::{OrganisationId, TrustCollectionId};
use similar_asserts::assert_eq;
use url::Url;
use uuid::Uuid;

use crate::error::{ErrorCode, ErrorCodeMixin};
use crate::model::common::GetListResponse;
use crate::model::identifier::IdentifierType;
use crate::model::organisation::{Organisation, OrganisationConfiguration};
use crate::model::trust_collection::TrustCollection;
use crate::model::trust_list_role::TrustListRoleEnum;
use crate::model::trust_list_subscription::{TrustListSubscription, TrustListSubscriptionState};
use crate::proto::session_provider::test::StaticSessionProvider;
use crate::provider::ecosystem::MockEcosystem;
use crate::provider::ecosystem::directory::MockEcosystemDirectory;
use crate::provider::trust_list_subscriber::provider::MockTrustListSubscriberProvider;
use crate::provider::trust_list_subscriber::{
    Feature, MockTrustListSubscriber, TrustListSubscriberCapabilities, TrustListValidationSuccess,
};
use crate::repository::error::DataLayerError;
use crate::repository::organisation_repository::MockOrganisationRepository;
use crate::repository::trust_collection_repository::MockTrustCollectionRepository;
use crate::repository::trust_list_subscription_repository::MockTrustListSubscriptionRepository;
use crate::service::common_dto::ListQueryDTO;
use crate::service::test_utilities::{dummy_organisation, get_dummy_date};
use crate::service::trust_collection::TrustCollectionService;
use crate::service::trust_collection::dto::{
    CreateTrustCollectionRequestDTO, CreateTrustListSubscriptionRequestDTO,
    TrustCollectionFilterParamsDTO, TrustListSubscriptionFilterParamsDTO,
};
use crate::service::trust_collection::error::TrustCollectionServiceError;

#[derive(Default)]
struct Mocks {
    organisation_repository: MockOrganisationRepository,
    trust_collection_repository: MockTrustCollectionRepository,
    trust_list_subscription_repository: MockTrustListSubscriptionRepository,
    trust_list_subscriber_provider: MockTrustListSubscriberProvider,
    session_provider: StaticSessionProvider,
    ecosystem_provider: MockEcosystemDirectory,
}

fn mock_service(mocks: Mocks) -> TrustCollectionService {
    TrustCollectionService::new(
        Arc::new(mocks.organisation_repository),
        Arc::new(mocks.trust_collection_repository),
        Arc::new(mocks.trust_list_subscription_repository),
        Arc::new(mocks.trust_list_subscriber_provider),
        Arc::new(mocks.session_provider),
        Arc::new(mocks.ecosystem_provider),
    )
}

fn dummy_trust_collection(organisation_id: OrganisationId) -> TrustCollection {
    let now = get_dummy_date();
    TrustCollection {
        ecosystem: "EUDI".into(),
        id: Uuid::new_v4().into(),
        name: "test trust collection".to_string(),
        created_date: now,
        last_modified: now,
        deactivated_at: None,
        remote_trust_collection_url: None,
        organisation: dummy_organisation(Some(organisation_id)).into(),
    }
}

#[tokio::test]
async fn test_create_trust_collection_success() {
    // given
    let session_provider = StaticSessionProvider::new_random();
    let organisation_id = session_provider.0.organisation_id.unwrap();

    let request = CreateTrustCollectionRequestDTO {
        name: "new collection".to_string(),
        organisation_id,
        ecosystem: "EUDI".into(),
    };

    let mut organisation_repository = MockOrganisationRepository::new();
    organisation_repository
        .expect_get_organisation()
        .with(eq(organisation_id))
        .returning(move |id| {
            Ok(Organisation {
                configuration: OrganisationConfiguration {
                    selected_ecosystems: vec!["EUDI".into()],
                    ..Default::default()
                },
                ..dummy_organisation(Some(*id))
            })
        });

    let mut trust_collection_repository = MockTrustCollectionRepository::new();
    trust_collection_repository
        .expect_create()
        .withf(move |tc| tc.name == "new collection" && tc.organisation.id() == organisation_id)
        .returning(|_| Ok(Uuid::new_v4().into()));

    let mut ecosystem_provider = MockEcosystemDirectory::new();
    ecosystem_provider.expect_get().return_once(|_| {
        let mut ecosystem = MockEcosystem::new();
        ecosystem.expect_enabled().returning(|| true);
        Ok(Arc::new(ecosystem))
    });

    let service = mock_service(Mocks {
        trust_collection_repository,
        session_provider,
        organisation_repository,
        ecosystem_provider,
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
        ecosystem: "EUDI".into(),
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
    let session_provider = StaticSessionProvider::new_random();
    let organisation_id = session_provider.0.organisation_id.unwrap();

    let request = CreateTrustCollectionRequestDTO {
        name: "new collection".to_string(),
        organisation_id,
        ecosystem: "EUDI".into(),
    };

    let mut organisation_repository = MockOrganisationRepository::new();
    organisation_repository
        .expect_get_organisation()
        .with(eq(organisation_id))
        .returning(move |id| {
            Ok(Organisation {
                configuration: OrganisationConfiguration {
                    selected_ecosystems: vec!["EUDI".into()],
                    ..Default::default()
                },
                ..dummy_organisation(Some(*id))
            })
        });

    let mut trust_collection_repository = MockTrustCollectionRepository::new();
    trust_collection_repository
        .expect_create()
        .returning(|_| Err(DataLayerError::AlreadyExists));

    let mut ecosystem_provider = MockEcosystemDirectory::new();
    ecosystem_provider.expect_get().return_once(|_| {
        let mut ecosystem = MockEcosystem::new();
        ecosystem.expect_enabled().returning(|| true);
        Ok(Arc::new(ecosystem))
    });

    let service = mock_service(Mocks {
        trust_collection_repository,
        session_provider,
        organisation_repository,
        ecosystem_provider,
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

    let session_provider = StaticSessionProvider::new_random();
    let organisation_id = session_provider.0.organisation_id.unwrap();

    let trust_collection = dummy_trust_collection(organisation_id);
    let trust_collection_id = trust_collection.id;

    trust_collection_repository
        .expect_get()
        .with(eq(trust_collection_id))
        .returning(move |_| Ok(trust_collection.clone()));

    trust_collection_repository
        .expect_delete()
        .with(eq(trust_collection_id))
        .returning(|_| Ok(()));

    trust_list_subscription_repository
        .expect_list()
        .returning(|_| {
            Ok(GetListResponse {
                values: vec![],
                total_pages: Some(0),
                total_items: Some(0),
            })
        });

    let service = mock_service(Mocks {
        trust_collection_repository,
        session_provider,
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
    let trust_collection_id: TrustCollectionId = Uuid::new_v4().into();

    trust_collection_repository
        .expect_get()
        .returning(move |_| {
            Err(DataLayerError::EntityNotFound {
                kind: crate::repository::error::EntityKind::TrustCollection,
                id: trust_collection_id.into(),
            })
        });

    let service = mock_service(Mocks {
        trust_collection_repository,
        ..Default::default()
    });

    // when
    let result = service.delete_trust_collection(trust_collection_id).await;

    // then
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0391);
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
        .with(eq(trust_collection_id))
        .returning(move |_| Ok(trust_collection.clone()));

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
        .with(eq(trust_collection_id))
        .returning(move |_| Ok(trust_collection.clone()));

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
async fn test_get_trust_collection_parent_org_success() {
    // given
    let mut trust_collection_repository = MockTrustCollectionRepository::new();
    let mut organisation_repository = MockOrganisationRepository::new();

    let session_provider = StaticSessionProvider::new_random();
    let parent_org_id = Uuid::new_v4().into();
    let child_org_id = session_provider.0.organisation_id.unwrap();

    organisation_repository
        .expect_get_organisation()
        .with(eq(child_org_id))
        .returning(move |id| {
            let mut child_org = dummy_organisation(Some(*id));
            child_org.parent_organisation = Some(dummy_organisation(Some(parent_org_id)).into());
            Ok(child_org)
        });

    let trust_collection = dummy_trust_collection(parent_org_id);
    let trust_collection_id = trust_collection.id;

    trust_collection_repository
        .expect_get()
        .with(eq(trust_collection_id))
        .returning(move |_| Ok(trust_collection.clone()));

    let service = mock_service(Mocks {
        organisation_repository,
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

    let query = ListQueryDTO {
        page: 0,
        page_size: 30,
        sort: None,
        sort_direction: None,
        filter: TrustCollectionFilterParamsDTO {
            name: None,
            ids: None,
            exact: None,
            organisation_id,
            created_date_after: None,
            created_date_before: None,
            last_modified_after: None,
            last_modified_before: None,
            include_parent_organisation_collections: false,
            ecosystems: None,
        },
        include: None,
    };

    trust_collection_repository.expect_list().returning(|_| {
        Ok(crate::model::common::GetListResponse {
            values: vec![],
            total_items: Some(0),
            total_pages: Some(0),
        })
    });

    let service = mock_service(Mocks {
        trust_collection_repository,
        session_provider,
        ..Default::default()
    });

    // when
    let result = service.get_trust_collection_list(query).await;

    // then
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_get_trust_collection_list_org_mismatch() {
    // given
    let other_organisation_id = Uuid::new_v4().into();
    let query = ListQueryDTO {
        page: 0,
        page_size: 30,
        sort: None,
        sort_direction: None,
        filter: TrustCollectionFilterParamsDTO {
            name: None,
            ids: None,
            exact: None,
            organisation_id: other_organisation_id,
            created_date_after: None,
            created_date_before: None,
            last_modified_after: None,
            last_modified_before: None,
            include_parent_organisation_collections: false,
            ecosystems: None,
        },
        include: None,
    };

    let service = mock_service(Default::default());

    // when
    let result = service.get_trust_collection_list(query).await;

    // then
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);
}

#[tokio::test]
async fn test_create_trust_list_subscription_success() {
    // given
    let mut trust_collection_repository = MockTrustCollectionRepository::new();
    let mut trust_list_subscription_repository = MockTrustListSubscriptionRepository::new();
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
        .with(eq(trust_collection_id))
        .returning(move |_| Ok(trust_collection.clone()));

    let mut trust_list_subscriber = MockTrustListSubscriber::new();
    trust_list_subscriber
        .expect_validate_subscription()
        .returning(|_, role| Ok(TrustListValidationSuccess { role }));
    trust_list_subscriber
        .expect_get_capabilities()
        .returning(|| TrustListSubscriberCapabilities {
            roles: vec![TrustListRoleEnum::Verifier],
            resolvable_identifier_types: vec![
                IdentifierType::Certificate,
                IdentifierType::CertificateAuthority,
            ],
            features: vec![Feature::SupportsRemoteIdentifiers],
        });

    let trust_list_subscriber_arc: Arc<
        dyn crate::provider::trust_list_subscriber::TrustListSubscriber,
    > = Arc::new(trust_list_subscriber);
    let type_id = request.r#type.clone();
    trust_list_subscriber_provider
        .expect_get()
        .with(eq(type_id))
        .returning(move |_| Ok(trust_list_subscriber_arc.clone()));

    trust_list_subscription_repository
        .expect_create()
        .returning(|_| Ok(Uuid::new_v4().into()));

    let service = mock_service(Mocks {
        trust_collection_repository,
        trust_list_subscription_repository,
        trust_list_subscriber_provider,
        session_provider,
        ..Default::default()
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
        .returning(move |_| Ok(trust_collection.clone()));

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
        .returning(move |_| Ok(trust_collection.clone()));

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
        .returning(move |_| Ok(trust_list_subscriber_arc.clone()));

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
    let trust_collection_id: TrustCollectionId = Uuid::new_v4().into();

    trust_collection_repository
        .expect_get()
        .returning(move |_| {
            Err(DataLayerError::EntityNotFound {
                kind: crate::repository::error::EntityKind::TrustCollection,
                id: trust_collection_id.into(),
            })
        });

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
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0391);
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
        role: Some(TrustListRoleEnum::Verifier),
        state: TrustListSubscriptionState::Active,
        trust_collection: trust_collection.into(),
    };

    trust_list_subscription_repository
        .expect_get()
        .with(eq(trust_list_subscription_id))
        .returning(move |_| Ok(trust_list_subscription.clone()));

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
    let trust_list_subscription_id: shared_types::TrustListSubscriptionId = Uuid::new_v4().into();

    trust_list_subscription_repository
        .expect_get()
        .returning(move |_| {
            Err(DataLayerError::EntityNotFound {
                kind: crate::repository::error::EntityKind::TrustListSubscription,
                id: trust_list_subscription_id.into(),
            })
        });

    let service = mock_service(Mocks {
        trust_list_subscription_repository,
        ..Default::default()
    });

    // when
    let result = service
        .delete_trust_list_subscription(trust_list_subscription_id)
        .await;

    // then
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0402);
}

#[tokio::test]
async fn test_get_trust_list_subscription_list_success() {
    // given
    let session_provider = StaticSessionProvider::new_random();
    let org_id = session_provider.0.organisation_id.unwrap();
    let mut trust_collection_repository = MockTrustCollectionRepository::new();
    trust_collection_repository
        .expect_get()
        .returning(move |_| Ok(dummy_trust_collection(org_id)));
    let mut trust_list_subscription_repository = MockTrustListSubscriptionRepository::new();

    let trust_collection_id: TrustCollectionId = Uuid::new_v4().into();
    let query = ListQueryDTO {
        page: 0,
        page_size: 30,
        sort: None,
        sort_direction: None,
        filter: TrustListSubscriptionFilterParamsDTO {
            name: None,
            reference: None,
            ids: None,
            roles: None,
            states: None,
            types: None,
            exact: None,
            created_date_after: None,
            created_date_before: None,
            last_modified_after: None,
            last_modified_before: None,
        },
        include: None,
    };

    trust_list_subscription_repository
        .expect_list()
        .returning(|_| {
            Ok(crate::model::common::GetListResponse {
                values: vec![],
                total_items: Some(0),
                total_pages: Some(0),
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
