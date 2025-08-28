use std::collections::HashMap;
use std::sync::Arc;

use assert2::check;
use async_trait::async_trait;
use one_crypto::signer::ecdsa::ECDSASigner;
use one_crypto::{Signer, SignerError};
use secrecy::SecretSlice;
use shared_types::{KeyId, OrganisationId, WalletUnitAttestationId, WalletUnitId};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::config::core_config::KeyAlgorithmType;
use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::model::wallet_unit::WalletUnitStatus;
use crate::model::wallet_unit_attestation::{
    UpdateWalletUnitAttestationRequest, WalletUnitAttestation,
};
use crate::provider::credential_formatter::common::SignatureProvider;
use crate::provider::key_algorithm::KeyAlgorithm;
use crate::provider::key_algorithm::ecdsa::Ecdsa;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::key_storage::provider::{KeyProviderImpl, MockKeyProvider};
use crate::provider::key_storage::{KeyStorage, MockKeyStorage};
use crate::provider::os_provider::MockOSInfoProvider;
use crate::provider::os_provider::dto::OSName;
use crate::provider::wallet_provider_client::MockWalletProviderClient;
use crate::provider::wallet_provider_client::dto::RefreshWalletUnitResponse;
use crate::repository::history_repository::MockHistoryRepository;
use crate::repository::key_repository::MockKeyRepository;
use crate::repository::organisation_repository::MockOrganisationRepository;
use crate::repository::wallet_unit_attestation_repository::MockWalletUnitAttestationRepository;
use crate::repository::wallet_unit_repository::MockWalletUnitRepository;
use crate::service::ssi_wallet_provider::dto::{
    RefreshWalletUnitResponseDTO, RegisterWalletUnitResponseDTO,
};
use crate::service::test_utilities::get_dummy_date;
use crate::service::wallet_unit::WalletUnitService;
use crate::service::wallet_unit::dto::{
    HolderRefreshWalletUnitRequestDTO, HolderRegisterWalletUnitRequestDTO, WalletProviderDTO,
};
use crate::util::clock::DefaultClock;
use crate::util::jwt::Jwt;
use crate::util::jwt::model::{JWTHeader, JWTPayload};

const BASE_URL: &str = "https://localhost";

fn mock_wallet_unit_service() -> WalletUnitService {
    WalletUnitService {
        organisation_repository: Arc::new(MockOrganisationRepository::default()),
        key_repository: Arc::new(MockKeyRepository::default()),
        wallet_provider_client: Arc::new(MockWalletProviderClient::default()),
        wallet_unit_repository: Arc::new(MockWalletUnitRepository::default()),
        wallet_unit_attestation_repository: Arc::new(MockWalletUnitAttestationRepository::default()),
        history_repository: Arc::new(MockHistoryRepository::default()),
        key_provider: Arc::new(MockKeyProvider::default()),
        key_algorithm_provider: Arc::new(MockKeyAlgorithmProvider::default()),
        os_info_provider: Arc::new(MockOSInfoProvider::default()),
        clock: Arc::new(DefaultClock),
        base_url: Some(BASE_URL.to_string()),
    }
}

#[tokio::test]
async fn holder_register_success() {
    // given
    let organisation_id: OrganisationId = Uuid::new_v4().into();
    let key_id: KeyId = Uuid::new_v4().into();

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .once()
        .return_once(|_| Some(Arc::new(Ecdsa)));

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
            }))
        });

    let (holder_private, holder_public) = ECDSASigner::generate_key_pair();
    let holder_public_clone_for_repo = holder_public.clone();

    let mut key_repository = MockKeyRepository::new();
    key_repository
        .expect_get_key()
        .once()
        .return_once(move |id, _| {
            check!(id == &key_id);
            Ok(Some(Key {
                id: *id,
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                public_key: holder_public_clone_for_repo,
                name: "holder".to_string(),
                key_reference: None,
                storage_type: "TEST".to_string(),
                key_type: "ECDSA".to_string(),
                organisation: None,
            }))
        });

    let holder_key_handle = Ecdsa
        .reconstruct_key(&holder_public, Some(holder_private.clone()), None)
        .unwrap();

    let mut key_storage = MockKeyStorage::new();
    key_storage
        .expect_key_handle()
        .times(2)
        .returning(move |_| Ok(holder_key_handle.clone()));

    let mut key_storages: HashMap<String, Arc<dyn KeyStorage>> = HashMap::new();
    key_storages.insert("TEST".to_string(), Arc::new(key_storage));

    let key_provider_impl = KeyProviderImpl::new(key_storages);

    let mut os_info_provider = MockOSInfoProvider::new();
    os_info_provider
        .expect_get_os_name()
        .once()
        .return_once(|| OSName::Android);

    let now = OffsetDateTime::now_utc();
    let attestation_token = make_attestation_jwt(now + Duration::minutes(60)).await;

    let wallet_unit_attestation_id: WalletUnitAttestationId = Uuid::new_v4().into();
    let wallet_unit_id: WalletUnitId = Uuid::new_v4().into();

    let mut wallet_provider_client = MockWalletProviderClient::new();
    wallet_provider_client
        .expect_register()
        .once()
        .return_once(move |url, _dto| {
            check!(url == "https://wallet.provider/register");
            Ok(RegisterWalletUnitResponseDTO {
                id: wallet_unit_id,
                attestation: attestation_token,
            })
        });

    let mut att_repo = MockWalletUnitAttestationRepository::new();
    att_repo
        .expect_create_wallet_unit_attestation()
        .once()
        .return_once(move |att| {
            check!(att.status == WalletUnitStatus::Active);
            check!(att.wallet_unit_id == wallet_unit_id);
            Ok(wallet_unit_attestation_id)
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
        wallet_unit_attestation_repository: Arc::new(att_repo),
        history_repository: Arc::new(history_repository),
        key_provider: Arc::new(key_provider_impl),
        key_algorithm_provider: Arc::new(key_algorithm_provider),
        os_info_provider: Arc::new(os_info_provider),
        ..mock_wallet_unit_service()
    };

    let request = HolderRegisterWalletUnitRequestDTO {
        organisation_id,
        key: key_id,
        wallet_provider: WalletProviderDTO {
            name: "PROCIVIS_ONE".to_string(),
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
async fn holder_refresh_success_active() {
    // given
    let organisation_id: OrganisationId = Uuid::new_v4().into();

    let (holder_private, holder_public) = ECDSASigner::generate_key_pair();
    let holder_key_handle = Ecdsa
        .reconstruct_key(&holder_public, Some(holder_private.clone()), None)
        .unwrap();

    let key_for_attestation = Key {
        id: Uuid::new_v4().into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        public_key: holder_public.clone(),
        name: "holder".to_string(),
        key_reference: None,
        storage_type: "TEST".to_string(),
        key_type: "ECDSA".to_string(),
        organisation: None,
    };

    let mut key_storage = MockKeyStorage::new();
    key_storage
        .expect_key_handle()
        .once()
        .return_once(|_| Ok(holder_key_handle));

    let mut key_storages: HashMap<String, Arc<dyn KeyStorage>> = HashMap::new();
    key_storages.insert("TEST".to_string(), Arc::new(key_storage));
    let key_provider_impl = KeyProviderImpl::new(key_storages);

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .once()
        .return_once(|_| Some(Arc::new(Ecdsa)));

    let mut att_repo = MockWalletUnitAttestationRepository::new();
    att_repo
        .expect_get_wallet_unit_attestation_by_organisation()
        .once()
        .return_once({
            let organisation = Organisation {
                id: organisation_id,
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                name: "Org".to_string(),
                deactivated_at: None,
            };
            move |id, _rels| {
                check!(id == &organisation_id);
                Ok(Some(WalletUnitAttestation {
                    id: Uuid::new_v4().into(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    expiration_date: OffsetDateTime::now_utc() + Duration::minutes(5),
                    status: WalletUnitStatus::Active,
                    attestation: "old".to_string(),
                    wallet_unit_id: Uuid::new_v4().into(),
                    wallet_provider_url: "https://wallet.provider/refresh".to_string(),
                    wallet_provider_type:
                        crate::model::wallet_unit::WalletProviderType::ProcivisOne,
                    wallet_provider_name: "PROCIVIS_ONE".to_string(),
                    organisation: Some(organisation.clone()),
                    key: Some(key_for_attestation),
                }))
            }
        });

    att_repo
        .expect_update_wallet_attestation()
        .once()
        .return_once(|_id, req: UpdateWalletUnitAttestationRequest| {
            assert!(req.attestation.is_some());
            assert!(req.expiration_date.is_some());
            Ok(())
        });

    let mut wallet_provider_client = MockWalletProviderClient::new();
    wallet_provider_client.expect_refresh().once().return_once({
        let new_attestation =
            make_attestation_jwt(OffsetDateTime::now_utc() + Duration::minutes(60)).await;
        move |_url, _id, _dto| {
            Ok(RefreshWalletUnitResponse::Active(
                RefreshWalletUnitResponseDTO {
                    id: Uuid::new_v4().into(),
                    attestation: new_attestation,
                },
            ))
        }
    });

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .once()
        .return_once(|_| Ok(Uuid::new_v4().into()));

    let mut os_info_provider = MockOSInfoProvider::new();
    os_info_provider
        .expect_get_os_name()
        .once()
        .return_once(|| OSName::Android);

    let service = WalletUnitService {
        wallet_provider_client: Arc::new(wallet_provider_client),
        wallet_unit_attestation_repository: Arc::new(att_repo),
        history_repository: Arc::new(history_repository),
        key_provider: Arc::new(key_provider_impl),
        key_algorithm_provider: Arc::new(key_algorithm_provider),
        os_info_provider: Arc::new(os_info_provider),
        ..mock_wallet_unit_service()
    };

    let request = HolderRefreshWalletUnitRequestDTO { organisation_id };

    // when
    let result = service.holder_refresh(request).await;

    // then
    assert!(result.is_ok(), "holder_refresh failed: {result:?}");
}

#[tokio::test]
async fn holder_attestation_success() {
    // given
    let organisation_id: OrganisationId = Uuid::new_v4().into();

    let mut att_repo = MockWalletUnitAttestationRepository::new();
    att_repo
        .expect_get_wallet_unit_attestation_by_organisation()
        .once()
        .return_once(move |id, _| {
            check!(id == &organisation_id);
            Ok(Some(WalletUnitAttestation {
                id: Uuid::new_v4().into(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                expiration_date: OffsetDateTime::now_utc() + Duration::minutes(60),
                status: WalletUnitStatus::Active,
                attestation: "token".to_string(),
                wallet_unit_id: Uuid::new_v4().into(),
                wallet_provider_url: "https://wallet".to_string(),
                wallet_provider_type: crate::model::wallet_unit::WalletProviderType::ProcivisOne,
                wallet_provider_name: "PROCIVIS_ONE".to_string(),
                organisation: None,
                key: None,
            }))
        });

    let service = WalletUnitService {
        wallet_unit_attestation_repository: Arc::new(att_repo),
        ..mock_wallet_unit_service()
    };

    // when
    let result = service.holder_attestation(organisation_id).await;

    // then
    assert!(result.is_ok(), "holder_attestation failed: {result:?}");
    let dto = result.unwrap();
    check!(dto.status == WalletUnitStatus::Active);
    check!(dto.wallet_provider_name == "PROCIVIS_ONE");
}

async fn make_attestation_jwt(exp: OffsetDateTime) -> String {
    let (issuer_private, issuer_public) = ECDSASigner::generate_key_pair();
    let issuer_key_handle = Ecdsa
        .reconstruct_key(&issuer_public, Some(issuer_private.clone()), None)
        .unwrap();
    let jwk = issuer_key_handle.public_key_as_jwk().unwrap();

    let now = OffsetDateTime::now_utc();
    let jwt = Jwt {
        header: JWTHeader {
            algorithm: "ES256".to_string(),
            key_id: None,
            r#type: None,
            jwk: Some(jwk.into()),
            jwt: None,
            x5c: None,
        },
        payload: JWTPayload {
            issued_at: Some(now),
            expires_at: Some(exp),
            invalid_before: Some(now),
            issuer: None,
            subject: None,
            audience: Some(vec![BASE_URL.to_string()]),
            jwt_id: None,
            proof_of_possession_key: None,
            custom: (),
        },
    };

    let signer = TestEcdsaSigner {
        public_key: issuer_public,
        private_key: issuer_private,
        key_id: "".to_string(),
    };
    jwt.tokenize(Some(Box::new(signer))).await.unwrap()
}

struct TestEcdsaSigner {
    public_key: Vec<u8>,
    private_key: SecretSlice<u8>,
    key_id: String,
}

#[async_trait]
impl SignatureProvider for TestEcdsaSigner {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignerError> {
        ECDSASigner {}.sign(message, &self.public_key, &self.private_key)
    }

    fn get_key_id(&self) -> Option<String> {
        Some(self.key_id.clone())
    }

    fn get_key_algorithm(&self) -> Result<KeyAlgorithmType, String> {
        Ok(KeyAlgorithmType::Ecdsa)
    }

    fn jose_alg(&self) -> Option<String> {
        Some("ES256".to_string())
    }

    fn get_public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }
}
