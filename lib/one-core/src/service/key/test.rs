use std::sync::Arc;

use similar_asserts::assert_eq;
use time::OffsetDateTime;
use uuid::Uuid;

use super::KeyService;
use crate::config::core_config::KeyAlgorithmType;
use crate::error::{ErrorCode, ErrorCodeMixin};
use crate::model::key::{GetKeyList, Key, KeyFilterValue, KeyListQuery};
use crate::model::list_filter::{ListFilterValue, StringMatch};
use crate::model::list_query::ListPagination;
use crate::proto::session_provider::NoSessionProvider;
use crate::proto::session_provider::test::StaticSessionProvider;
use crate::provider::key_algorithm::MockKeyAlgorithm;
use crate::provider::key_algorithm::model::KeyAlgorithmCapabilities;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::key_storage::MockKeyStorage;
use crate::provider::key_storage::model::{KeyStorageCapabilities, StorageGeneratedKey};
use crate::provider::key_storage::provider::MockKeyProvider;
use crate::repository::history_repository::MockHistoryRepository;
use crate::repository::key_repository::MockKeyRepository;
use crate::repository::organisation_repository::MockOrganisationRepository;
use crate::service::key::dto::{
    KeyGenerateCSRRequestDTO, KeyGenerateCSRRequestProfile, KeyGenerateCSRRequestSubjectDTO,
    KeyRequestDTO,
};
use crate::service::key::error::KeyServiceError;
use crate::service::test_utilities::{dummy_organisation, generic_config};

fn setup_service(
    repository: MockKeyRepository,
    organisation_repository: MockOrganisationRepository,
    key_storage: MockKeyStorage,
    config: crate::config::core_config::CoreConfig,
    key_algorithm_provider: MockKeyAlgorithmProvider,
    history_repository: MockHistoryRepository,
) -> KeyService {
    let key_storage = Arc::new(key_storage);
    let mut provider = MockKeyProvider::new();
    provider
        .expect_get_key_storage()
        .returning(move |_| Some(key_storage.clone()));

    KeyService::new(
        Arc::new(repository),
        Arc::new(organisation_repository),
        Arc::new(provider),
        Arc::new(config),
        Arc::new(key_algorithm_provider),
        Arc::new(history_repository),
        Arc::new(NoSessionProvider),
    )
}

fn generic_key(name: &str, organisation_id: Uuid) -> Key {
    let now = OffsetDateTime::now_utc();
    Key {
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
        public_key: vec![],
        name: name.to_owned(),
        key_reference: None,
        storage_type: "INTERNAL".to_string(),
        key_type: "EDDSA".to_string(),
        organisation: Some(dummy_organisation(Some(organisation_id.into()))),
    }
}

#[tokio::test]
async fn test_create_key_success() {
    let mut repository = MockKeyRepository::default();
    let mut organisation_repository = MockOrganisationRepository::default();
    let mut key_storage = MockKeyStorage::default();
    let key_algorithm_provider = MockKeyAlgorithmProvider::default();
    let history_repository = MockHistoryRepository::default();

    let org_id = Uuid::new_v4();

    let key = generic_key("NAME", org_id);
    let organisation = key.organisation.to_owned().unwrap();
    {
        let organisation = organisation.clone();

        organisation_repository
            .expect_get_organisation()
            .once()
            .returning(move |_, _| Ok(Some(organisation.clone())));

        key_storage
            .expect_get_capabilities()
            .returning(|| KeyStorageCapabilities {
                algorithms: vec![KeyAlgorithmType::Eddsa],
                ..Default::default()
            });

        key_storage.expect_generate().once().returning(|_, _| {
            Ok(StorageGeneratedKey {
                public_key: vec![],
                key_reference: None,
            })
        });

        repository
            .expect_create_key()
            .once()
            .returning(move |_| Ok(key.id));
    }

    let service = setup_service(
        repository,
        organisation_repository,
        key_storage,
        generic_config().core,
        key_algorithm_provider,
        history_repository,
    );

    let result = service
        .create_key(KeyRequestDTO {
            organisation_id: organisation.id,
            key_type: "EDDSA".to_string(),
            key_params: Default::default(),
            name: "NAME".to_string(),
            storage_type: "INTERNAL".to_string(),
            storage_params: Default::default(),
        })
        .await;

    assert!(result.is_ok());
    assert_eq!(key.id, result.unwrap());
}

#[tokio::test]
async fn test_get_key_success() {
    let mut repository = MockKeyRepository::default();
    let organisation_repository = MockOrganisationRepository::default();
    let key_storage = MockKeyStorage::default();
    let key_algorithm_provider = MockKeyAlgorithmProvider::default();
    let history_repository = MockHistoryRepository::default();

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
        organisation_repository,
        key_storage,
        generic_config().core,
        key_algorithm_provider,
        history_repository,
    );

    let result = service.get_key(&key.id).await;

    assert!(result.is_ok());
    assert_eq!(key.id, result.unwrap().id);
}

#[tokio::test]
async fn test_get_key_list() {
    let mut repository = MockKeyRepository::default();
    let organisation_repository = MockOrganisationRepository::default();
    let key_storage = MockKeyStorage::default();
    let org_id: Uuid = Uuid::new_v4();
    let keys = vec![generic_key("NAME1", org_id), generic_key("NAME2", org_id)];
    let key_algorithm_provider = MockKeyAlgorithmProvider::default();
    let history_repository = MockHistoryRepository::default();

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
        organisation_repository,
        key_storage,
        generic_config().core,
        key_algorithm_provider,
        history_repository,
    );

    let query = KeyListQuery {
        pagination: Some(ListPagination {
            page: 0,
            page_size: 10,
        }),
        sorting: None,
        filtering: Some(
            KeyFilterValue::Name(StringMatch::contains("Name")).condition()
                & KeyFilterValue::OrganisationId(org_id.into()),
        ),
        include: None,
    };

    let result = service.get_key_list(&org_id.into(), query).await;

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
        subject: KeyGenerateCSRRequestSubjectDTO {
            country_name: Some("CH".to_string()),
            common_name: Some("name".to_string()),
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
    let history_repository = MockHistoryRepository::default();

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
            .expect_key_algorithm_from_type()
            .once()
            .withf(move |alg| {
                assert_eq!(*alg, KeyAlgorithmType::BbsPlus);
                true
            })
            .returning(move |_| Some(key_alg.clone()));
    }

    let service = setup_service(
        repository,
        organisation_repository,
        key_storage,
        generic_config().core,
        key_algorithm_provider,
        history_repository,
    );

    let result = service.generate_csr(&key.id, generic_csr_request()).await;
    assert!(matches!(
        result,
        Err(KeyServiceError::UnsupportedKeyTypeForCSR)
    ));
}

#[tokio::test]
async fn test_create_key_session_org_mismatch() {
    let service = KeyService::new(
        Arc::new(MockKeyRepository::default()),
        Arc::new(MockOrganisationRepository::new()),
        Arc::new(MockKeyProvider::new()),
        Arc::new(generic_config().core),
        Arc::new(MockKeyAlgorithmProvider::new()),
        Arc::new(MockHistoryRepository::new()),
        Arc::new(StaticSessionProvider::new_random()),
    );

    let result = service
        .create_key(KeyRequestDTO {
            organisation_id: Uuid::new_v4().into(),
            key_type: "".to_string(),
            key_params: Default::default(),
            name: "".to_string(),
            storage_type: "".to_string(),
            storage_params: Default::default(),
        })
        .await
        .err()
        .unwrap();
    assert_eq!(result.error_code(), ErrorCode::BR_0178);
}

#[tokio::test]
async fn test_list_key_session_org_mismatch() {
    let service = KeyService::new(
        Arc::new(MockKeyRepository::default()),
        Arc::new(MockOrganisationRepository::new()),
        Arc::new(MockKeyProvider::new()),
        Arc::new(generic_config().core),
        Arc::new(MockKeyAlgorithmProvider::new()),
        Arc::new(MockHistoryRepository::new()),
        Arc::new(StaticSessionProvider::new_random()),
    );

    let result = service
        .get_key_list(
            &Uuid::new_v4().into(),
            KeyListQuery {
                pagination: None,
                sorting: None,
                filtering: None,
                include: None,
            },
        )
        .await
        .err()
        .unwrap();
    assert_eq!(result.error_code(), ErrorCode::BR_0178);
}

#[tokio::test]
async fn test_key_ops_session_org_mismatch() {
    let mut repository = MockKeyRepository::default();
    let key_id = Uuid::new_v4();
    repository
        .expect_get_key()
        .returning(move |_, _| Ok(Some(generic_key("NAME", key_id))));

    let service = KeyService::new(
        Arc::new(repository),
        Arc::new(MockOrganisationRepository::new()),
        Arc::new(MockKeyProvider::new()),
        Arc::new(generic_config().core),
        Arc::new(MockKeyAlgorithmProvider::new()),
        Arc::new(MockHistoryRepository::new()),
        Arc::new(StaticSessionProvider::new_random()),
    );

    let err = service.get_key(&key_id.into()).await.err().unwrap();
    assert_eq!(err.error_code(), ErrorCode::BR_0178);
    let err = service
        .generate_csr(&key_id.into(), generic_csr_request())
        .await
        .err()
        .unwrap();
    assert_eq!(err.error_code(), ErrorCode::BR_0178);
}
