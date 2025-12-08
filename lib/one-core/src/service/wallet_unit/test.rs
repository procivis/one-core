use std::sync::Arc;

use assert2::check;
use one_crypto::signer::ecdsa::ECDSASigner;
use shared_types::{OrganisationId, WalletUnitId};
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::config::core_config::CoreConfig;
use crate::model::holder_wallet_unit::CreateHolderWalletUnitRequest;
use crate::model::organisation::Organisation;
use crate::model::wallet_unit::WalletUnitStatus;
use crate::proto::clock::DefaultClock;
use crate::proto::os_provider::MockOSInfoProvider;
use crate::proto::os_provider::dto::OSName;
use crate::proto::session_provider::NoSessionProvider;
use crate::proto::wallet_unit::{MockHolderWalletUnitProto, WalletUnitStatusCheckResponse};
use crate::provider::credential_formatter::model::MockSignatureProvider;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::key_storage::MockKeyStorage;
use crate::provider::key_storage::model::StorageGeneratedKey;
use crate::provider::key_storage::provider::MockKeyProvider;
use crate::provider::wallet_provider_client::MockWalletProviderClient;
use crate::repository::history_repository::MockHistoryRepository;
use crate::repository::holder_wallet_unit_repository::MockHolderWalletUnitRepository;
use crate::repository::key_repository::MockKeyRepository;
use crate::repository::organisation_repository::MockOrganisationRepository;
use crate::service::test_utilities::{generic_config, get_dummy_date};
use crate::service::wallet_provider::dto::{
    RegisterWalletUnitResponseDTO, WalletProviderMetadataResponseDTO,
    WalletUnitAttestationMetadataDTO,
};
use crate::service::wallet_unit::WalletUnitService;
use crate::service::wallet_unit::dto::{HolderRegisterWalletUnitRequestDTO, WalletProviderDTO};

const BASE_URL: &str = "https://localhost";

fn mock_wallet_unit_service() -> WalletUnitService {
    WalletUnitService {
        organisation_repository: Arc::new(MockOrganisationRepository::default()),
        key_repository: Arc::new(MockKeyRepository::default()),
        wallet_provider_client: Arc::new(MockWalletProviderClient::default()),
        holder_wallet_unit_repository: Arc::new(MockHolderWalletUnitRepository::default()),
        history_repository: Arc::new(MockHistoryRepository::default()),
        key_provider: Arc::new(MockKeyProvider::default()),
        key_algorithm_provider: Arc::new(MockKeyAlgorithmProvider::default()),
        os_info_provider: Arc::new(MockOSInfoProvider::default()),
        clock: Arc::new(DefaultClock),
        base_url: Some(BASE_URL.to_string()),
        config: Arc::new(CoreConfig::default()),
        session_provider: Arc::new(NoSessionProvider),
        wallet_unit_proto: Arc::new(MockHolderWalletUnitProto::default()),
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
        .return_once(move |id, _| {
            check!(id == &organisation_id);
            Ok(Some(Organisation {
                id: *id,
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                name: "Org".to_string(),
                deactivated_at: None,
                wallet_provider: None,
                wallet_provider_issuer: None,
            }))
        });

    let (_holder_private, _holder_public) = ECDSASigner::generate_key_pair();

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
        .returning(move |_| Some(key_storage.clone()));
    key_provider
        .expect_get_attestation_signature_provider()
        .returning(move |_, _, _| {
            let mut signature_provider = MockSignatureProvider::new();
            signature_provider
                .expect_jose_alg()
                .returning(|| Some("EdDSA".to_string()));
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

    let wallet_unit_id: WalletUnitId = Uuid::new_v4().into();
    let mut wallet_provider_client = MockWalletProviderClient::new();
    wallet_provider_client
        .expect_register()
        .once()
        .return_once(move |url, _dto| {
            check!(url == "https://wallet.provider");
            Ok(RegisterWalletUnitResponseDTO {
                id: wallet_unit_id,
                nonce: Some("test_nonce".to_string()),
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
            })
        });

    wallet_provider_client
        .expect_activate()
        .once()
        .return_once(move |url, _, _| {
            check!(url == "https://wallet.provider");
            Ok(())
        });

    let mut att_repo = MockHolderWalletUnitRepository::new();
    att_repo
        .expect_create_holder_wallet_unit()
        .once()
        .return_once(move |att: CreateHolderWalletUnitRequest| {
            check!(att.status == WalletUnitStatus::Active);
            check!(att.provider_wallet_unit_id == wallet_unit_id);
            Ok(att.id)
        });

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .once()
        .return_once(|_| Ok(Uuid::new_v4().into()));

    let service = WalletUnitService {
        organisation_repository: Arc::new(organisation_repository),
        key_repository: Arc::new(key_repository),
        wallet_provider_client: Arc::new(wallet_provider_client),
        holder_wallet_unit_repository: Arc::new(att_repo),
        history_repository: Arc::new(history_repository),
        key_provider: Arc::new(key_provider),
        os_info_provider: Arc::new(os_info_provider),
        config: Arc::new(generic_config().core),
        ..mock_wallet_unit_service()
    };

    let request = HolderRegisterWalletUnitRequestDTO {
        organisation_id,
        key_type: "EDDSA".to_string(),
        wallet_provider: WalletProviderDTO {
            r#type: crate::model::wallet_unit::WalletProviderType::ProcivisOne,
            url: "https://wallet.provider/register".to_string(),
        },
    };

    // when
    let result = service.holder_register(request).await;

    // then
    assert!(result.is_ok(), "holder_register failed: {result:?}");
}

#[tokio::test]
async fn holder_wallet_unit_status_check_still_valid() {
    // given
    let wallet_unit_id: shared_types::HolderWalletUnitId = Uuid::new_v4().into();

    let mut holder_wallet_unit_repository = MockHolderWalletUnitRepository::new();
    holder_wallet_unit_repository
        .expect_get_holder_wallet_unit()
        .once()
        .return_once(move |_, _| {
            Ok(Some(crate::model::holder_wallet_unit::HolderWalletUnit {
                id: wallet_unit_id,
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                status: WalletUnitStatus::Active,
                wallet_provider_type: crate::model::wallet_unit::WalletProviderType::ProcivisOne,
                wallet_provider_name: "PROCIVIS_ONE".to_string(),
                wallet_provider_url: "https://wallet.provider".to_string(),
                provider_wallet_unit_id: Uuid::new_v4().into(),
                organisation: None,
                authentication_key: None,
                wallet_unit_attestations: None,
            }))
        });

    let mut wallet_unit_proto = MockHolderWalletUnitProto::new();
    wallet_unit_proto
        .expect_check_wallet_unit_status()
        .once()
        .return_once(|_| Ok(WalletUnitStatusCheckResponse::Active));

    let service = WalletUnitService {
        holder_wallet_unit_repository: Arc::new(holder_wallet_unit_repository),
        wallet_unit_proto: Arc::new(wallet_unit_proto),
        ..mock_wallet_unit_service()
    };

    // when
    let result = service.holder_wallet_unit_status(wallet_unit_id).await;

    // then
    assert!(
        result.is_ok(),
        "status check should succeed without marking as revoked"
    );
}

#[tokio::test]
async fn holder_wallet_unit_status_check_revocation() {
    // given
    let wallet_unit_id: shared_types::HolderWalletUnitId = Uuid::new_v4().into();

    let mut holder_wallet_unit_repository = MockHolderWalletUnitRepository::new();
    holder_wallet_unit_repository
        .expect_get_holder_wallet_unit()
        .once()
        .return_once(move |_, _| {
            Ok(Some(crate::model::holder_wallet_unit::HolderWalletUnit {
                id: wallet_unit_id,
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                status: WalletUnitStatus::Active,
                wallet_provider_type: crate::model::wallet_unit::WalletProviderType::ProcivisOne,
                wallet_provider_name: "PROCIVIS_ONE".to_string(),
                wallet_provider_url: "https://wallet.provider".to_string(),
                provider_wallet_unit_id: Uuid::new_v4().into(),
                organisation: Some(Organisation {
                    id: Uuid::new_v4().into(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    name: "Test Org".to_string(),
                    deactivated_at: None,
                    wallet_provider: None,
                    wallet_provider_issuer: None,
                }),
                authentication_key: None,
                wallet_unit_attestations: None,
            }))
        });

    let mut wallet_unit_proto = MockHolderWalletUnitProto::new();
    wallet_unit_proto
        .expect_check_wallet_unit_status()
        .once()
        .return_once(|_| Ok(WalletUnitStatusCheckResponse::Revoked));

    holder_wallet_unit_repository
        .expect_update_holder_wallet_unit()
        .once()
        .return_once(move |id, request| {
            check!(id == &wallet_unit_id);
            check!(request.status == Some(WalletUnitStatus::Revoked));
            Ok(())
        });

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .once()
        .return_once(|_| Ok(Uuid::new_v4().into()));

    let service = WalletUnitService {
        holder_wallet_unit_repository: Arc::new(holder_wallet_unit_repository),
        wallet_unit_proto: Arc::new(wallet_unit_proto),
        history_repository: Arc::new(history_repository),
        ..mock_wallet_unit_service()
    };

    // when
    let result = service.holder_wallet_unit_status(wallet_unit_id).await;

    // then
    assert!(
        result.is_ok(),
        "status check should succeed and update status to revoked"
    );
}

#[tokio::test]
async fn holder_wallet_unit_status_check_not_found() {
    // given
    let wallet_unit_id: shared_types::HolderWalletUnitId = Uuid::new_v4().into();

    let mut holder_wallet_unit_repository = MockHolderWalletUnitRepository::new();
    holder_wallet_unit_repository
        .expect_get_holder_wallet_unit()
        .once()
        .return_once(|_, _| Ok(None));

    let service = WalletUnitService {
        holder_wallet_unit_repository: Arc::new(holder_wallet_unit_repository),
        ..mock_wallet_unit_service()
    };

    // when
    let result = service.holder_wallet_unit_status(wallet_unit_id).await;

    // then
    assert!(result.is_err(), "should return error for not found");
}

#[tokio::test]
async fn holder_wallet_unit_status_check_already_revoked() {
    // given
    let wallet_unit_id: shared_types::HolderWalletUnitId = Uuid::new_v4().into();

    let mut holder_wallet_unit_repository = MockHolderWalletUnitRepository::new();
    holder_wallet_unit_repository
        .expect_get_holder_wallet_unit()
        .once()
        .return_once(move |_, _| {
            Ok(Some(crate::model::holder_wallet_unit::HolderWalletUnit {
                id: wallet_unit_id,
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                status: WalletUnitStatus::Revoked,
                wallet_provider_type: crate::model::wallet_unit::WalletProviderType::ProcivisOne,
                wallet_provider_name: "PROCIVIS_ONE".to_string(),
                wallet_provider_url: "https://wallet.provider".to_string(),
                provider_wallet_unit_id: Uuid::new_v4().into(),
                organisation: None,
                authentication_key: None,
                wallet_unit_attestations: None,
            }))
        });

    // wallet_unit_proto should NOT be called since wallet unit is already revoked
    let wallet_unit_proto = MockHolderWalletUnitProto::new();

    let service = WalletUnitService {
        holder_wallet_unit_repository: Arc::new(holder_wallet_unit_repository),
        wallet_unit_proto: Arc::new(wallet_unit_proto),
        ..mock_wallet_unit_service()
    };

    // when
    let result = service.holder_wallet_unit_status(wallet_unit_id).await;

    // then
    assert!(
        result.is_ok(),
        "status check should succeed without checking revocation"
    );
}
