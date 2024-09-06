use std::collections::HashMap;
use std::sync::Arc;

use one_providers::common_models::key::OpenKey;
use one_providers::key_algorithm::model::KeyAlgorithmCapabilities;
use one_providers::key_algorithm::provider::MockKeyAlgorithmProvider;
use one_providers::key_algorithm::MockKeyAlgorithm;
use one_providers::key_storage::imp::provider::KeyProviderImpl;
use one_providers::key_storage::model::StorageGeneratedKey;
use one_providers::key_storage::{KeyStorage, MockKeyStorage};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::KeyService;
use crate::model::key::GetKeyList;
use crate::model::organisation::Organisation;
use crate::provider::did_method::mdl::validator::MockDidMdlValidator;
use crate::repository::history_repository::MockHistoryRepository;
use crate::repository::key_repository::MockKeyRepository;
use crate::repository::organisation_repository::MockOrganisationRepository;
use crate::service::error::{BusinessLogicError, ServiceError, ValidationError};
use crate::service::key::dto::{
    GetKeyQueryDTO, KeyGenerateCSRRequestDTO, KeyGenerateCSRRequestProfile,
    KeyGenerateCSRRequestSubjectDTO, KeyRequestDTO,
};
use crate::service::test_utilities::generic_config;

fn setup_service(
    repository: MockKeyRepository,
    history_repository: MockHistoryRepository,
    organisation_repository: MockOrganisationRepository,
    did_mdl_validator: MockDidMdlValidator,
    key_storage: MockKeyStorage,
    config: crate::config::core_config::CoreConfig,
    key_algorithm_provider: MockKeyAlgorithmProvider,
) -> KeyService {
    let mut storages: HashMap<String, Arc<dyn KeyStorage>> = HashMap::new();
    storages.insert("INTERNAL".to_string(), Arc::new(key_storage));

    let provider = KeyProviderImpl::new(storages);

    KeyService::new(
        Arc::new(repository),
        Arc::new(history_repository),
        Arc::new(organisation_repository),
        Arc::new(did_mdl_validator),
        Arc::new(provider),
        Arc::new(config),
        Arc::new(key_algorithm_provider),
    )
}

fn generic_key(name: &str, organisation_id: Uuid) -> OpenKey {
    let now = OffsetDateTime::now_utc();
    OpenKey {
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
        public_key: vec![],
        name: name.to_owned(),
        key_reference: vec![],
        storage_type: "INTERNAL".to_string(),
        key_type: "EDDSA".to_string(),
        organisation: Some(
            Organisation {
                id: organisation_id.into(),
                created_date: now,
                last_modified: now,
            }
            .into(),
        ),
    }
}

#[tokio::test]
async fn test_create_key_success() {
    let mut repository = MockKeyRepository::default();
    let mut organisation_repository = MockOrganisationRepository::default();
    let mut key_storage = MockKeyStorage::default();
    let key_algorithm_provider = MockKeyAlgorithmProvider::default();

    let org_id = Uuid::new_v4();

    let key = generic_key("NAME", org_id);
    let organisation = key.organisation.to_owned().unwrap();
    {
        let organisation = organisation.clone();

        organisation_repository
            .expect_get_organisation()
            .once()
            .returning(move |_, _| Ok(Some(organisation.clone().into())));

        key_storage.expect_generate().once().returning(|_, _| {
            Ok(StorageGeneratedKey {
                public_key: vec![],
                key_reference: vec![],
            })
        });

        repository
            .expect_create_key()
            .once()
            .returning(move |_| Ok(key.id));
    }

    let mut history_repository = MockHistoryRepository::default();
    history_repository
        .expect_create_history()
        .times(1)
        .returning(|history| Ok(history.id));

    let service = setup_service(
        repository,
        history_repository,
        organisation_repository,
        MockDidMdlValidator::default(),
        key_storage,
        generic_config().core,
        key_algorithm_provider,
    );

    let result = service
        .generate_key(KeyRequestDTO {
            organisation_id: organisation.id.into(),
            key_type: "EDDSA".to_string(),
            key_params: Default::default(),
            name: "NAME".to_string(),
            storage_type: "INTERNAL".to_string(),
            storage_params: Default::default(),
        })
        .await;

    assert!(result.is_ok());
    assert_eq!(key.id, result.unwrap().into());
}

#[tokio::test]
async fn test_get_key_success() {
    let mut repository = MockKeyRepository::default();
    let organisation_repository = MockOrganisationRepository::default();
    let key_storage = MockKeyStorage::default();
    let key_algorithm_provider = MockKeyAlgorithmProvider::default();

    let org_id: Uuid = Uuid::new_v4();
    let key = generic_key("NAME", org_id);
    {
        let key = key.clone();
        repository
            .expect_get_key()
            .once()
            .returning(move |_, _| Ok(Some(key.clone())));
    }

    let service = setup_service(
        repository,
        MockHistoryRepository::default(),
        organisation_repository,
        MockDidMdlValidator::default(),
        key_storage,
        generic_config().core,
        key_algorithm_provider,
    );

    let result = service.get_key(&key.id.to_owned().into()).await;

    assert!(result.is_ok());
    assert_eq!(key.id, result.unwrap().id.into());
}

#[tokio::test]
async fn test_get_key_list() {
    let mut repository = MockKeyRepository::default();
    let organisation_repository = MockOrganisationRepository::default();
    let key_storage = MockKeyStorage::default();
    let org_id: Uuid = Uuid::new_v4();
    let keys = vec![generic_key("NAME1", org_id), generic_key("NAME2", org_id)];
    let key_algorithm_provider = MockKeyAlgorithmProvider::default();

    let moved_keys = keys.clone();
    repository.expect_get_key_list().once().returning(move |_| {
        Ok(GetKeyList {
            values: moved_keys.clone(),
            total_pages: 1,
            total_items: 2,
        })
    });

    let service = setup_service(
        repository,
        MockHistoryRepository::default(),
        organisation_repository,
        MockDidMdlValidator::default(),
        key_storage,
        generic_config().core,
        key_algorithm_provider,
    );

    let query = GetKeyQueryDTO {
        page: 0,
        page_size: 10,
        sort: None,
        sort_direction: None,
        name: Some("NAME".to_owned()),
        organisation_id: org_id.into(),
        exact: None,
        ids: None,
    };

    let result = service.get_key_list(query).await;

    assert!(result.is_ok());

    let data = result.unwrap();

    assert_eq!(data.total_items, 2);
    assert_eq!(data.total_pages, 1);
    assert_eq!(data.values.len(), 2);

    assert_eq!(data.values[0].name, keys[0].name);
    assert_eq!(data.values[1].name, keys[1].name);
}

fn generic_csr_request() -> KeyGenerateCSRRequestDTO {
    KeyGenerateCSRRequestDTO {
        profile: KeyGenerateCSRRequestProfile::Mdl,
        not_before: OffsetDateTime::now_utc(),
        expires_at: OffsetDateTime::now_utc(),
        subject: KeyGenerateCSRRequestSubjectDTO {
            country_name: "CH".to_string(),
            common_name: "name".to_string(),
            state_or_province_name: None,
            organisation_name: None,
            locality_name: None,
            serial_number: None,
        },
    }
}

#[tokio::test]
async fn test_generate_csr_failed_unsupported_key_type_for_csr() {
    let mut repository = MockKeyRepository::default();
    let organisation_repository = MockOrganisationRepository::default();
    let key_storage = MockKeyStorage::default();
    let mut key_algorithm_provider = MockKeyAlgorithmProvider::default();
    let mut key_alg = MockKeyAlgorithm::default();
    key_alg
        .expect_get_capabilities()
        .once()
        .returning(|| KeyAlgorithmCapabilities { features: vec![] });

    let key_alg = Arc::new(key_alg);

    let org_id: Uuid = Uuid::new_v4();
    let mut key = generic_key("NAME", org_id);
    key.key_type = "BBS_PLUS".to_string();
    {
        let key = key.clone();
        repository
            .expect_get_key()
            .once()
            .returning(move |_, _| Ok(Some(key.clone())));

        key_algorithm_provider
            .expect_get_key_algorithm()
            .once()
            .withf(move |alg| {
                assert_eq!(alg, "BBS_PLUS");
                true
            })
            .returning(move |_| Some(key_alg.clone()));
    }

    let service = setup_service(
        repository,
        MockHistoryRepository::default(),
        organisation_repository,
        MockDidMdlValidator::default(),
        key_storage,
        generic_config().core,
        key_algorithm_provider,
    );

    let result = service
        .generate_csr(&key.id.to_owned().into(), generic_csr_request())
        .await;
    assert!(matches!(
        result,
        Err(ServiceError::BusinessLogic(
            BusinessLogicError::UnsupportedKeyTypeForCSR
        ))
    ));
}

#[tokio::test]
async fn test_generate_csr_failed_requested_for_more_than_457_days() {
    let mut repository = MockKeyRepository::default();
    let organisation_repository = MockOrganisationRepository::default();
    let key_storage = MockKeyStorage::default();
    let mut key_algorithm_provider = MockKeyAlgorithmProvider::default();
    let mut key_alg = MockKeyAlgorithm::default();
    key_alg
        .expect_get_capabilities()
        .once()
        .returning(|| KeyAlgorithmCapabilities {
            features: vec!["GENERATE_CSR".to_string()],
        });

    let key_alg = Arc::new(key_alg);

    let org_id: Uuid = Uuid::new_v4();
    let key = generic_key("NAME", org_id);
    {
        let key = key.clone();
        repository
            .expect_get_key()
            .once()
            .returning(move |_, _| Ok(Some(key.clone())));

        key_algorithm_provider
            .expect_get_key_algorithm()
            .once()
            .withf(move |alg| {
                assert_eq!(alg, "EDDSA");
                true
            })
            .returning(move |_| Some(key_alg.clone()));
    }

    let service = setup_service(
        repository,
        MockHistoryRepository::default(),
        organisation_repository,
        MockDidMdlValidator::default(),
        key_storage,
        generic_config().core,
        key_algorithm_provider,
    );

    let mut request = generic_csr_request();
    request.expires_at = request.not_before + Duration::days(458);

    let result = service
        .generate_csr(&key.id.to_owned().into(), request)
        .await;
    assert!(matches!(
        result,
        Err(ServiceError::Validation(
            ValidationError::CertificateRequestedForMoreThan457Days
        ))
    ));
}
