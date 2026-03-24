use std::sync::Arc;

use assert2::check;
use mockall::predicate::{always, eq};
use shared_types::OrganisationId;
use similar_asserts::assert_eq;
use uuid::Uuid;

use super::VerifierInstanceService;
use super::dto::RegisterVerifierInstanceRequestDTO;
use crate::model::trust_collection::{GetTrustCollectionList, TrustCollection};
use crate::model::trust_list_subscription::GetTrustListSubscriptionList;
use crate::model::verifier_instance::VerifierInstance;
use crate::proto::session_provider::NoSessionProvider;
use crate::proto::transaction_manager::NoTransactionManager;
use crate::proto::trust_collection::MockTrustCollectionManager;
use crate::proto::verifier_provider_client::MockVerifierProviderClient;
use crate::provider::verifier::model::FeatureFlags;
use crate::repository::history_repository::MockHistoryRepository;
use crate::repository::organisation_repository::MockOrganisationRepository;
use crate::repository::trust_collection_repository::MockTrustCollectionRepository;
use crate::repository::trust_list_subscription_repository::MockTrustListSubscriptionRepository;
use crate::repository::verifier_instance_repository::MockVerifierInstanceRepository;
use crate::service::test_utilities::{dummy_organisation, get_dummy_date};
use crate::service::verifier_provider::dto::{
    ProviderTrustCollectionDTO, VerifierProviderMetadataResponseDTO,
};

#[derive(Default)]
pub struct Mocks {
    organisation_repository: MockOrganisationRepository,
    verifier_instance_repository: MockVerifierInstanceRepository,
    history_repository: MockHistoryRepository,
    verifier_provider_client: MockVerifierProviderClient,
    trust_collection_manager: MockTrustCollectionManager,
    trust_collection_repository: MockTrustCollectionRepository,
    trust_subscription_repository: MockTrustListSubscriptionRepository,
}

fn get_service(mocks: Mocks) -> VerifierInstanceService {
    VerifierInstanceService::new(
        Arc::new(mocks.organisation_repository),
        Arc::new(mocks.verifier_instance_repository),
        Arc::new(mocks.history_repository),
        Arc::new(mocks.verifier_provider_client),
        Arc::new(mocks.trust_collection_manager),
        Arc::new(mocks.trust_collection_repository),
        Arc::new(mocks.trust_subscription_repository),
        Arc::new(NoTransactionManager),
        Arc::new(NoSessionProvider),
    )
}

#[tokio::test]
async fn test_register_verifier_instance_success() {
    // given
    let organisation_id: OrganisationId = Uuid::new_v4().into();

    let mut organisation_repository = MockOrganisationRepository::new();
    organisation_repository
        .expect_get_organisation()
        .once()
        .return_once(move |id, _| {
            check!(id == &organisation_id);
            Ok(Some(dummy_organisation(Some(*id))))
        });

    let mut verifier_instance_repository = MockVerifierInstanceRepository::new();
    verifier_instance_repository
        .expect_get_by_org_id()
        .once()
        .return_once(move |id| {
            check!(id == &organisation_id);
            Ok(None)
        });
    verifier_instance_repository
        .expect_create()
        .once()
        .withf(move |instance| {
            assert_eq!(instance.organisation.as_ref().unwrap().id, organisation_id);
            assert_eq!(instance.provider_name, "provider-name");
            assert_eq!(instance.provider_type, "PROCIVIS_ONE");
            assert_eq!(instance.provider_url, "https://verifier.provider");
            true
        })
        .return_once(|instance| Ok(instance.id));

    let mut trust_collection_manager = MockTrustCollectionManager::new();
    trust_collection_manager
        .expect_create_empty_trust_collections()
        .once()
        .return_once(|_, _, _| Ok(vec![]));

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .once()
        .return_once(|_| Ok(Uuid::new_v4().into()));

    let mut verifier_provider_client = MockVerifierProviderClient::new();
    verifier_provider_client
        .expect_get_verifier_provider_metadata()
        .once()
        .with(eq(
            "https://verifier.provider/ssi/verifier-provider/v1/PROCIVIS_ONE",
        ))
        .return_once(|_| {
            Ok(VerifierProviderMetadataResponseDTO {
                verifier_name: "provider-name".to_string(),
                app_version: None,
                trust_collections: vec![],
                feature_flags: FeatureFlags {
                    trust_ecosystems_enabled: true,
                },
            })
        });

    let service = get_service(Mocks {
        organisation_repository,
        verifier_instance_repository,
        history_repository,
        trust_collection_manager,
        verifier_provider_client,
        ..Default::default()
    });

    let request = RegisterVerifierInstanceRequestDTO {
        organisation_id,
        r#type: "PROCIVIS_ONE".to_string(),
        verifier_provider_url: "https://verifier.provider".to_string(),
    };

    // when
    let result = service.register_verifier_instance(request).await;

    // then
    assert!(
        result.is_ok(),
        "register_verifier_instance failed: {result:?}"
    );
}

#[tokio::test]
async fn test_get_trust_collections() {
    // given
    let id = Uuid::new_v4().into();
    let organisation_id = Uuid::new_v4().into();

    let mut verifier_instance_repository = MockVerifierInstanceRepository::new();
    verifier_instance_repository
        .expect_get()
        .once()
        .with(eq(id), always())
        .return_once(move |id, _| {
            Ok(Some(VerifierInstance {
                id: *id,
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                provider_type: "PROCIVIS_ONE".to_string(),
                provider_name: "provider-name".to_string(),
                provider_url: "http://provider.url".to_string(),
                organisation: Some(dummy_organisation(Some(organisation_id))),
            }))
        });

    let mut verifier_provider_client = MockVerifierProviderClient::new();
    verifier_provider_client
        .expect_get_verifier_provider_metadata()
        .once()
        .with(eq(
            "http://provider.url/ssi/verifier-provider/v1/PROCIVIS_ONE",
        ))
        .return_once(|_| {
            Ok(VerifierProviderMetadataResponseDTO {
                verifier_name: "provider-name".to_string(),
                app_version: None,
                trust_collections: vec![ProviderTrustCollectionDTO {
                    id: Uuid::new_v4().into(),
                    name: "collection".to_string(),
                    logo: "logo".to_string(),
                    display_name: vec![],
                    description: vec![],
                }],
                feature_flags: FeatureFlags {
                    trust_ecosystems_enabled: true,
                },
            })
        });

    let trust_collection_id = Uuid::new_v4().into();
    let mut trust_collection_repository = MockTrustCollectionRepository::new();
    trust_collection_repository
        .expect_list()
        .once()
        .return_once(move |_| {
            Ok(GetTrustCollectionList {
                values: vec![TrustCollection {
                    id: trust_collection_id,
                    name: "collection".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    deactivated_at: None,
                    remote_trust_collection_url: None,
                    organisation_id,
                    organisation: None,
                }],
                total_pages: 1,
                total_items: 1,
            })
        });

    let mut trust_subscription_repository = MockTrustListSubscriptionRepository::new();
    trust_subscription_repository
        .expect_list()
        .once()
        .return_once(move |_| {
            Ok(GetTrustListSubscriptionList {
                values: vec![],
                total_pages: 0,
                total_items: 0,
            })
        });

    let service = get_service(Mocks {
        verifier_instance_repository,
        verifier_provider_client,
        trust_collection_repository,
        trust_subscription_repository,
        ..Default::default()
    });

    // when
    let result = service.get_trust_collections(id).await;

    // then
    let trust_collections = result.unwrap().trust_collections;
    assert_eq!(trust_collections.len(), 1);
    let trust_collection = &trust_collections[0];
    assert_eq!(trust_collection.selected, false);
    assert_eq!(trust_collection.collection.id, trust_collection_id);
}
