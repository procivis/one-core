use std::sync::Arc;

use assert2::check;
use mockall::predicate::eq;
use shared_types::OrganisationId;
use similar_asserts::assert_eq;
use uuid::Uuid;

use super::VerifierInstanceService;
use super::dto::RegisterVerifierInstanceRequestDTO;
use crate::proto::session_provider::NoSessionProvider;
use crate::proto::transaction_manager::NoTransactionManager;
use crate::proto::trust_collection::MockTrustCollectionManager;
use crate::proto::verifier_provider_client::MockVerifierProviderClient;
use crate::provider::verifier::model::FeatureFlags;
use crate::repository::history_repository::MockHistoryRepository;
use crate::repository::organisation_repository::MockOrganisationRepository;
use crate::repository::verifier_instance_repository::MockVerifierInstanceRepository;
use crate::service::test_utilities::dummy_organisation;
use crate::service::verifier_provider::dto::VerifierProviderMetadataResponseDTO;

#[derive(Default)]
pub struct Mocks {
    organisation_repository: MockOrganisationRepository,
    verifier_instance_repository: MockVerifierInstanceRepository,
    history_repository: MockHistoryRepository,
    verifier_provider_client: MockVerifierProviderClient,
    trust_collection_manager: MockTrustCollectionManager,
}

fn get_service(mocks: Mocks) -> VerifierInstanceService {
    VerifierInstanceService::new(
        Arc::new(mocks.organisation_repository),
        Arc::new(mocks.verifier_instance_repository),
        Arc::new(mocks.history_repository),
        Arc::new(mocks.verifier_provider_client),
        Arc::new(mocks.trust_collection_manager),
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
