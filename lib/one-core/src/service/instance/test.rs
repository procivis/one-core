use std::sync::Arc;

use assert2::check;
use mockall::predicate::eq;
use shared_types::{InstanceId, ManagedInstanceId, OrganisationId};
use similar_asserts::assert_eq;
use uuid::Uuid;

use super::InstanceService;
use super::dto::{HolderRegisterInstanceRequestDTO, InstanceProviderDTO};
use super::error::HolderInstanceError;
use crate::config::core_config::CoreConfig;
use crate::model::instance::{Instance, InstanceRole, InstanceStatus, WalletProviderType};
use crate::model::organisation::Organisation;
use crate::proto::clock::DefaultClock;
use crate::proto::credential_schema::importer::MockCredentialSchemaImporter;
use crate::proto::credential_schema::parser::MockCredentialSchemaImportParser;
use crate::proto::csr_creator::MockCsrCreator;
use crate::proto::http_client::MockHttpClient;
use crate::proto::identifier_creator::MockIdentifierCreator;
use crate::proto::os_provider::MockOSInfoProvider;
use crate::proto::os_provider::dto::OSName;
use crate::proto::session_provider::NoSessionProvider;
use crate::proto::trust_collection::MockTrustCollectionManager;
use crate::proto::verifier_provider_client::MockVerifierProviderClient;
use crate::proto::wallet_instance::{MockHolderWalletUnitProto, WalletUnitStatusCheckResponse};
use crate::proto::wallet_provider_client::MockWalletProviderClient;
use crate::provider::credential_formatter::model::MockSignatureProvider;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::key_storage::MockKeyStorage;
use crate::provider::key_storage::error::KeyStorageError;
use crate::provider::key_storage::model::StorageGeneratedKey;
use crate::provider::key_storage::provider::MockKeyProvider;
use crate::repository::credential_schema_repository::MockCredentialSchemaRepository;
use crate::repository::history_repository::MockHistoryRepository;
use crate::repository::instance_repository::MockInstanceRepository;
use crate::repository::key_repository::MockKeyRepository;
use crate::repository::organisation_repository::MockOrganisationRepository;
use crate::repository::proof_schema_repository::MockProofSchemaRepository;
use crate::service::managed_instance::dto::{
    ActivateWalletUnitResponseDTO, FeatureFlags, RegisterWalletUnitResponseDTO,
    WalletProviderMetadataResponseDTO, WalletUnitAttestationMetadataDTO,
};
use crate::service::test_utilities::{dummy_organisation, generic_config, get_dummy_date};

const BASE_URL: &str = "https://localhost";

fn mock_instance_service() -> InstanceService {
    InstanceService {
        organisation_repository: Arc::new(MockOrganisationRepository::default()),
        key_repository: Arc::new(MockKeyRepository::default()),
        wallet_provider_client: Arc::new(MockWalletProviderClient::default()),
        verifier_provider_client: Arc::new(MockVerifierProviderClient::default()),
        holder_wallet_instance_repository: Arc::new(MockInstanceRepository::default()),
        history_repository: Arc::new(MockHistoryRepository::default()),
        key_provider: Arc::new(MockKeyProvider::default()),
        key_algorithm_provider: Arc::new(MockKeyAlgorithmProvider::default()),
        os_info_provider: Arc::new(MockOSInfoProvider::default()),
        clock: Arc::new(DefaultClock),
        base_url: Some(BASE_URL.to_string()),
        config: Arc::new(CoreConfig::default()),
        session_provider: Arc::new(NoSessionProvider),
        wallet_unit_proto: Arc::new(MockHolderWalletUnitProto::default()),
        trust_collection_manager: Arc::new(MockTrustCollectionManager::default()),
        client: Arc::new(MockHttpClient::default()),
        credential_schema_import_parser: Arc::new(MockCredentialSchemaImportParser::default()),
        credential_schema_importer: Arc::new(MockCredentialSchemaImporter::default()),
        proof_schema_repository: Arc::new(MockProofSchemaRepository::default()),
        credential_schema_repository: Arc::new(MockCredentialSchemaRepository::default()),
        csr_creator: Arc::new(MockCsrCreator::default()),
        identifier_creator: Arc::new(MockIdentifierCreator::default()),
    }
}

#[tokio::test]
async fn holder_register_success() {
    // given
    let organisation_id: OrganisationId = Uuid::new_v4().into();

    let mut organisation_repository = MockOrganisationRepository::new();
    organisation_repository
        .expect_get_organisation()
        .once()
        .return_once(move |id| {
            check!(id == &organisation_id);
            Ok(Organisation {
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                ..dummy_organisation(Some(*id))
            })
        });

    let mut key_repository = MockKeyRepository::new();
    key_repository
        .expect_create_key()
        .once()
        .return_once(move |dto| Ok(dto.id));
    let mut key_storage = MockKeyStorage::new();
    key_storage
        .expect_generate_attestation_key()
        .times(1)
        .returning(move |_, _| {
            Ok(StorageGeneratedKey {
                public_key: vec![1, 2, 3, 4],
                key_reference: Some(vec![1, 2, 3]),
            })
        });
    key_storage
        .expect_generate_attestation()
        .times(1)
        .returning(move |_, nonce| {
            assert_eq!(nonce, Some("test_nonce".to_string()));
            Ok(vec!["test_attestation".to_string()])
        });

    let key_storage = Arc::new(key_storage);
    let mut key_provider = MockKeyProvider::new();
    key_provider
        .expect_get_key_storage()
        .returning(move |_| Ok(key_storage.clone()));
    key_provider
        .expect_get_attestation_signature_provider()
        .returning(move |_, _, _| {
            let mut signature_provider = MockSignatureProvider::new();
            signature_provider
                .expect_jose_alg()
                .returning(|| Ok("EdDSA".to_string()));
            signature_provider.expect_get_key_id().returning(|| None);
            signature_provider
                .expect_sign()
                .once()
                .returning(|_| Ok(vec![0x01]));
            Ok(Box::new(signature_provider))
        });

    let mut os_info_provider = MockOSInfoProvider::new();
    os_info_provider
        .expect_get_os_name()
        .once()
        .return_once(|| OSName::Android);

    let wallet_unit_id: ManagedInstanceId = Uuid::new_v4().into();
    let mut wallet_provider_client = MockWalletProviderClient::new();
    wallet_provider_client
        .expect_register()
        .once()
        .return_once(move |url, _dto| {
            check!(url == "https://wallet.provider");
            Ok(RegisterWalletUnitResponseDTO {
                id: wallet_unit_id,
                nonce: Some("test_nonce".to_string()),
                user_nonce: None,
            })
        });
    wallet_provider_client
        .expect_get_wallet_provider_metadata()
        .once()
        .return_once(move |_| {
            Ok(WalletProviderMetadataResponseDTO {
                wallet_unit_attestation: WalletUnitAttestationMetadataDTO {
                    app_integrity_check_required: true,
                    enabled: true,
                    required: true,
                },
                name: "Wallet Provider Name".to_string(),
                app_version: None,
                feature_flags: FeatureFlags {
                    ecosystems_enabled: true,
                    refresh_credential_batch_enabled: true,
                    document_signing_enabled: false,
                    ecosystems_enforcement_enabled: false,
                },
                trust_collections: vec![],
                user_authentication: None,
                document_signers: vec![],
                ecosystems: vec![],
            })
        });

    wallet_provider_client
        .expect_activate()
        .once()
        .return_once(move |url, _, _| {
            check!(url == "https://wallet.provider");
            Ok(ActivateWalletUnitResponseDTO {
                access_certificate: None,
            })
        });

    let mut holder_wallet_unit_repository = MockInstanceRepository::new();
    holder_wallet_unit_repository
        .expect_get_by_role()
        .once()
        .return_once(|_, _| Ok(None));
    holder_wallet_unit_repository
        .expect_create()
        .once()
        .return_once(move |att: Instance| {
            check!(att.status == InstanceStatus::Active);
            check!(att.provider_instance_id == wallet_unit_id);
            Ok(att.id)
        });

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

    let service = InstanceService {
        organisation_repository: Arc::new(organisation_repository),
        key_repository: Arc::new(key_repository),
        wallet_provider_client: Arc::new(wallet_provider_client),
        holder_wallet_instance_repository: Arc::new(holder_wallet_unit_repository),
        history_repository: Arc::new(history_repository),
        key_provider: Arc::new(key_provider),
        os_info_provider: Arc::new(os_info_provider),
        trust_collection_manager: Arc::new(trust_collection_manager),
        config: Arc::new(generic_config().core),
        ..mock_instance_service()
    };

    let request = HolderRegisterInstanceRequestDTO {
        organisation_id,
        key_type: "EDDSA".to_string(),
        role: InstanceRole::Wallet,
        provider: InstanceProviderDTO {
            r#type: WalletProviderType::ProcivisOne,
            url: "https://wallet.provider/register".to_string(),
        },
    };

    // when
    let result = service.holder_register(request).await;

    // then
    assert!(result.is_ok(), "holder_register failed: {result:?}");
}

#[tokio::test]
async fn holder_register_key_attestation_not_supported() {
    // given
    let organisation_id: OrganisationId = Uuid::new_v4().into();

    let mut organisation_repository = MockOrganisationRepository::new();
    organisation_repository
        .expect_get_organisation()
        .once()
        .return_once(move |id| {
            check!(id == &organisation_id);
            Ok(Organisation {
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                ..dummy_organisation(Some(*id))
            })
        });

    let mut key_storage = MockKeyStorage::new();
    key_storage
        .expect_generate_attestation_key()
        .once()
        .returning(|_, _| Err(KeyStorageError::NotSupported("test".to_string())));

    let key_storage = Arc::new(key_storage);
    let mut key_provider = MockKeyProvider::new();
    key_provider
        .expect_get_key_storage()
        .returning(move |_| Ok(key_storage.clone()));

    let mut os_info_provider = MockOSInfoProvider::new();
    os_info_provider
        .expect_get_os_name()
        .once()
        .return_once(|| OSName::Android);

    let wallet_unit_id: ManagedInstanceId = Uuid::new_v4().into();
    let mut wallet_provider_client = MockWalletProviderClient::new();
    wallet_provider_client
        .expect_register()
        .once()
        .return_once(move |url, _dto| {
            check!(url == "https://wallet.provider");
            Ok(RegisterWalletUnitResponseDTO {
                id: wallet_unit_id,
                nonce: Some("test_nonce".to_string()),
                user_nonce: None,
            })
        });
    wallet_provider_client
        .expect_get_wallet_provider_metadata()
        .once()
        .return_once(move |_| {
            Ok(WalletProviderMetadataResponseDTO {
                wallet_unit_attestation: WalletUnitAttestationMetadataDTO {
                    app_integrity_check_required: true,
                    enabled: true,
                    required: true,
                },
                name: "Wallet Provider Name".to_string(),
                app_version: None,
                feature_flags: FeatureFlags {
                    ecosystems_enabled: true,
                    refresh_credential_batch_enabled: true,
                    document_signing_enabled: false,
                    ecosystems_enforcement_enabled: false,
                },
                trust_collections: vec![],
                user_authentication: None,
                document_signers: vec![],
                ecosystems: vec![],
            })
        });

    let mut holder_wallet_unit_repository = MockInstanceRepository::new();
    holder_wallet_unit_repository
        .expect_get_by_role()
        .once()
        .return_once(|_, _| Ok(None));
    holder_wallet_unit_repository
        .expect_create()
        .once()
        .return_once(move |att: Instance| {
            check!(att.status == InstanceStatus::Unattested);
            check!(att.provider_instance_id == wallet_unit_id);
            Ok(att.id)
        });

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

    let service = InstanceService {
        organisation_repository: Arc::new(organisation_repository),
        wallet_provider_client: Arc::new(wallet_provider_client),
        holder_wallet_instance_repository: Arc::new(holder_wallet_unit_repository),
        history_repository: Arc::new(history_repository),
        key_provider: Arc::new(key_provider),
        os_info_provider: Arc::new(os_info_provider),
        trust_collection_manager: Arc::new(trust_collection_manager),
        config: Arc::new(generic_config().core),
        ..mock_instance_service()
    };

    let request = HolderRegisterInstanceRequestDTO {
        organisation_id,
        key_type: "EDDSA".to_string(),
        role: InstanceRole::Wallet,
        provider: InstanceProviderDTO {
            r#type: WalletProviderType::ProcivisOne,
            url: "https://wallet.provider/register".to_string(),
        },
    };

    // when
    let result = service.holder_register(request).await.unwrap();

    // then
    assert_eq!(result.status, InstanceStatus::Unattested);
}

#[tokio::test]
async fn holder_instance_status_check_still_valid() {
    // given
    let wallet_unit_id: shared_types::InstanceId = Uuid::new_v4().into();

    let mut holder_wallet_unit_repository = MockInstanceRepository::new();
    holder_wallet_unit_repository
        .expect_get()
        .once()
        .return_once(move |_| {
            Ok(crate::model::instance::Instance {
                id: wallet_unit_id,
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                status: InstanceStatus::Active,
                role: InstanceRole::Wallet,
                provider_type: WalletProviderType::ProcivisOne,
                provider_name: "PROCIVIS_ONE".to_string(),
                provider_url: "https://wallet.provider".to_string(),
                provider_instance_id: Uuid::new_v4().into(),
                organisation: dummy_organisation(None).into(),
                authentication_key: None,
                wallet_unit_attestations: Default::default(),
                nonce: None,
                user_nonce: None,
            })
        });

    let mut wallet_unit_proto = MockHolderWalletUnitProto::new();
    wallet_unit_proto
        .expect_check_wallet_unit_status()
        .once()
        .return_once(|_| Ok(WalletUnitStatusCheckResponse::Active));

    let service = InstanceService {
        holder_wallet_instance_repository: Arc::new(holder_wallet_unit_repository),
        wallet_unit_proto: Arc::new(wallet_unit_proto),
        ..mock_instance_service()
    };

    // when
    let result = service.holder_instance_status(wallet_unit_id).await;

    // then
    assert!(
        result.is_ok(),
        "status check should succeed without marking as revoked"
    );
}

#[tokio::test]
async fn holder_instance_status_check_revocation() {
    // given
    let wallet_unit_id: shared_types::InstanceId = Uuid::new_v4().into();

    let mut holder_wallet_unit_repository = MockInstanceRepository::new();
    holder_wallet_unit_repository
        .expect_get()
        .once()
        .return_once(move |_| {
            Ok(Instance {
                id: wallet_unit_id,
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                status: InstanceStatus::Active,
                role: InstanceRole::Wallet,
                provider_type: WalletProviderType::ProcivisOne,
                provider_name: "PROCIVIS_ONE".to_string(),
                provider_url: "https://wallet.provider".to_string(),
                provider_instance_id: Uuid::new_v4().into(),
                organisation: Organisation {
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    ..dummy_organisation(None)
                }
                .into(),
                authentication_key: None,
                wallet_unit_attestations: Default::default(),
                nonce: None,
                user_nonce: None,
            })
        });

    let mut wallet_unit_proto = MockHolderWalletUnitProto::new();
    wallet_unit_proto
        .expect_check_wallet_unit_status()
        .once()
        .return_once(|_| Ok(WalletUnitStatusCheckResponse::Revoked));

    holder_wallet_unit_repository
        .expect_update()
        .once()
        .return_once(move |id, request| {
            check!(id == &wallet_unit_id);
            check!(request.status == Some(InstanceStatus::Revoked));
            Ok(())
        });

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .once()
        .return_once(|_| Ok(Uuid::new_v4().into()));

    let service = InstanceService {
        holder_wallet_instance_repository: Arc::new(holder_wallet_unit_repository),
        wallet_unit_proto: Arc::new(wallet_unit_proto),
        history_repository: Arc::new(history_repository),
        ..mock_instance_service()
    };

    // when
    let result = service.holder_instance_status(wallet_unit_id).await;

    // then
    assert!(
        result.is_ok(),
        "status check should succeed and update status to revoked"
    );
}

#[tokio::test]
async fn holder_instance_status_check_not_found() {
    // given
    let wallet_unit_id: shared_types::InstanceId = Uuid::new_v4().into();

    let mut holder_wallet_unit_repository = MockInstanceRepository::new();
    holder_wallet_unit_repository
        .expect_get()
        .once()
        .return_once(move |_| {
            Err(crate::repository::error::DataLayerError::EntityNotFound {
                kind: crate::repository::error::EntityKind::Instance,
                id: wallet_unit_id.into(),
            })
        });

    let service = InstanceService {
        holder_wallet_instance_repository: Arc::new(holder_wallet_unit_repository),
        ..mock_instance_service()
    };

    // when
    let result = service.holder_instance_status(wallet_unit_id).await;

    // then
    assert!(result.is_err(), "should return error for not found");
}

#[tokio::test]
async fn holder_instance_status_check_already_revoked() {
    // given
    let wallet_unit_id: shared_types::InstanceId = Uuid::new_v4().into();

    let mut holder_wallet_unit_repository = MockInstanceRepository::new();
    holder_wallet_unit_repository
        .expect_get()
        .once()
        .return_once(move |_| {
            Ok(crate::model::instance::Instance {
                id: wallet_unit_id,
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                status: InstanceStatus::Revoked,
                role: InstanceRole::Wallet,
                provider_type: WalletProviderType::ProcivisOne,
                provider_name: "PROCIVIS_ONE".to_string(),
                provider_url: "https://wallet.provider".to_string(),
                provider_instance_id: Uuid::new_v4().into(),
                organisation: dummy_organisation(None).into(),
                authentication_key: None,
                wallet_unit_attestations: Default::default(),
                nonce: None,
                user_nonce: None,
            })
        });

    // wallet_unit_proto should NOT be called since wallet unit is already revoked
    let wallet_unit_proto = MockHolderWalletUnitProto::new();

    let service = InstanceService {
        holder_wallet_instance_repository: Arc::new(holder_wallet_unit_repository),
        wallet_unit_proto: Arc::new(wallet_unit_proto),
        ..mock_instance_service()
    };

    // when
    let result = service.holder_instance_status(wallet_unit_id).await;

    // then
    assert!(
        result.is_ok(),
        "status check should succeed without checking revocation"
    );
}

#[tokio::test]
async fn holder_register_already_exists() {
    // given
    let organisation_id: OrganisationId = Uuid::new_v4().into();

    let existing_instance_id: InstanceId = Uuid::new_v4().into();

    let mut organisation_repository = MockOrganisationRepository::new();
    organisation_repository
        .expect_get_organisation()
        .once()
        .return_once(move |id| {
            check!(id == &organisation_id);
            Ok(Organisation {
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                ..dummy_organisation(Some(*id))
            })
        });

    let mut holder_wallet_unit_repository = MockInstanceRepository::new();
    holder_wallet_unit_repository
        .expect_get_by_role()
        .once()
        .with(eq(InstanceRole::Wallet), eq(organisation_id))
        .return_once(move |_, _| {
            Ok(Some(Instance {
                id: existing_instance_id,
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                status: InstanceStatus::Revoked,
                role: InstanceRole::Wallet,
                provider_type: WalletProviderType::ProcivisOne,
                provider_name: "PROCIVIS_ONE".to_string(),
                provider_url: "https://wallet.provider".to_string(),
                provider_instance_id: Uuid::new_v4().into(),
                organisation: dummy_organisation(None).into(),
                authentication_key: None,
                wallet_unit_attestations: Default::default(),
                nonce: None,
                user_nonce: None,
            }))
        });

    let service = InstanceService {
        organisation_repository: Arc::new(organisation_repository),
        holder_wallet_instance_repository: Arc::new(holder_wallet_unit_repository),
        config: Arc::new(generic_config().core),
        ..mock_instance_service()
    };

    let request = HolderRegisterInstanceRequestDTO {
        organisation_id,
        key_type: "EDDSA".to_string(),
        role: InstanceRole::Wallet,
        provider: InstanceProviderDTO {
            r#type: WalletProviderType::ProcivisOne,
            url: "https://wallet.provider/register".to_string(),
        },
    };

    // when
    let result = service.holder_register(request).await;

    // then
    assert!(matches!(
        result.unwrap_err(),
        HolderInstanceError::WalletInstanceAlreadyExists(_)
    ));
}
