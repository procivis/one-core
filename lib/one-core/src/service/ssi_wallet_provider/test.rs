use std::collections::HashMap;
use std::ops::{Add, Sub};
use std::sync::Arc;

use assert2::let_assert;
use async_trait::async_trait;
use one_crypto::signer::ecdsa::ECDSASigner;
use one_crypto::{Signer, SignerError};
use secrecy::SecretSlice;
use serde_json::json;
use shared_types::IdentifierId;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::config;
use crate::config::core_config::{CoreConfig, Fields, KeyAlgorithmType, Params};
use crate::model::history::HistoryMetadata;
use crate::model::identifier::{Identifier, IdentifierState, IdentifierType};
use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::model::wallet_unit::{WalletProviderType, WalletUnit, WalletUnitClaims, WalletUnitOs};
use crate::proto::session_provider::NoSessionProvider;
use crate::provider::credential_formatter::common::SignatureProvider;
use crate::provider::key_algorithm::KeyAlgorithm;
use crate::provider::key_algorithm::ecdsa::Ecdsa;
use crate::provider::key_algorithm::key::KeyHandle;
use crate::provider::key_algorithm::provider::{MockKeyAlgorithmProvider, ParsedKey};
use crate::provider::key_storage::provider::{KeyProviderImpl, MockKeyProvider};
use crate::provider::key_storage::{KeyStorage, MockKeyStorage};
use crate::repository::history_repository::MockHistoryRepository;
use crate::repository::identifier_repository::MockIdentifierRepository;
use crate::repository::organisation_repository::MockOrganisationRepository;
use crate::repository::wallet_unit_repository::MockWalletUnitRepository;
use crate::service::certificate::validator::MockCertificateValidator;
use crate::service::ssi_wallet_provider::SSIWalletProviderService;
use crate::service::ssi_wallet_provider::dto::{
    RefreshWalletUnitRequestDTO, RegisterWalletUnitRequestDTO,
};
use crate::service::test_utilities::get_dummy_date;
use crate::util::clock::DefaultClock;
use crate::util::jwt::Jwt;
use crate::util::jwt::model::{JWTHeader, JWTPayload};

const BASE_URL: &str = "https://localhost";

fn mock_ssi_wallet_service() -> SSIWalletProviderService {
    SSIWalletProviderService {
        organisation_repository: Arc::new(MockOrganisationRepository::default()),
        wallet_unit_repository: Arc::new(MockWalletUnitRepository::default()),
        identifier_repository: Arc::new(MockIdentifierRepository::default()),
        history_repository: Arc::new(MockHistoryRepository::default()),
        key_provider: Arc::new(MockKeyProvider::default()),
        key_algorithm_provider: Arc::new(MockKeyAlgorithmProvider::default()),
        certificate_validator: Arc::new(MockCertificateValidator::default()),
        clock: Arc::new(DefaultClock),
        base_url: Some(BASE_URL.to_string()),
        config: Arc::new(CoreConfig::default()),
        session_provider: Arc::new(NoSessionProvider),
    }
}

fn wallet_provider_config(
    integrity_check_enabled: bool,
) -> Fields<config::core_config::WalletProviderType> {
    Fields {
        r#type: config::core_config::WalletProviderType::ProcivisOne,
        display: "display".into(),
        order: None,
        enabled: Some(true),
        capabilities: None,
        params: Some(Params {
            public: Some(json!({
                "walletName": "Procivis One Dev Wallet",
                "walletLink": "https://procivis.ch",
                "android": {
                    "bundleId": "com.procivis...",
                    "signingCertificateFingerprints": ["test"],
                    "trustedAttestationCAs": ["-----BEGIN CERTIFICATE-----..."]
                },
                "ios": {
                    "bundleId": "com.procivis...",
                    "trustedAttestationCAs": ["-----BEGIN CERTIFICATE-----..."],
                    "enforceProductionBuild": true
                },
                "lifetime": {
                  "expirationTime": 60,
                  "minimumRefreshTime": 60
                },
                "integrityCheck": {
                    "enabled": integrity_check_enabled
                }
            })),
            private: None,
        }),
    }
}

#[tokio::test]
async fn test_register_wallet_unit() {
    // given
    let mut config = CoreConfig::default();
    let issuer_identifier_id: IdentifierId = Uuid::new_v4().into();

    let procivis_one_provider = "PROCIVIS_ONE";
    config.wallet_provider.insert(
        procivis_one_provider.to_string(),
        wallet_provider_config(false),
    );

    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation_for_wallet_provider()
        .returning(move |_| {
            Ok(Some(Organisation {
                id: Uuid::new_v4().into(),
                name: "test org".to_string(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                deactivated_at: None,
                wallet_provider: Some(procivis_one_provider.to_string()),
                wallet_provider_issuer: Some(issuer_identifier_id),
            }))
        });

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_jose_alg()
        .once()
        .return_once(|_| Some((KeyAlgorithmType::Ecdsa, Arc::new(Ecdsa))));

    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .once()
        .return_once(|_| Some(Arc::new(Ecdsa)));

    let mut wallet_unit_repository = MockWalletUnitRepository::new();
    wallet_unit_repository
        .expect_create_wallet_unit()
        .return_once(|wu| Ok(wu.id));

    let (issuer_private, issuer_public) = ECDSASigner::generate_key_pair();
    let issuer_public_clone = issuer_public.clone();
    let mut identifier_repository = MockIdentifierRepository::new();
    identifier_repository
        .expect_get()
        .return_once(move |id, _| {
            Ok(Some(Identifier {
                id,
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                name: "test".to_string(),
                r#type: IdentifierType::Key,
                is_remote: false,
                state: IdentifierState::Active,
                deleted_at: None,
                organisation: None,
                did: None,
                key: Some(Key {
                    id: Uuid::new_v4().into(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    public_key: issuer_public_clone,
                    name: "".to_string(),
                    key_reference: None,
                    storage_type: "TEST".to_string(),
                    key_type: "ECDSA".to_string(),
                    organisation: None,
                }),
                certificates: None,
            }))
        });

    let issuer_key_handle = Ecdsa
        .reconstruct_key(&issuer_public, Some(issuer_private.clone()), None)
        .unwrap();

    let mut key_storage = MockKeyStorage::new();
    key_storage
        .expect_key_handle()
        .returning(move |_| Ok(issuer_key_handle.clone()));

    let mut key_storages: HashMap<String, Arc<dyn KeyStorage>> = HashMap::new();
    key_storages.insert("TEST".to_string(), Arc::new(key_storage));

    let key_provider = KeyProviderImpl::new(key_storages);

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .return_once(|entry| {
            let_assert!(Some(metadata) = entry.metadata);
            let_assert!(HistoryMetadata::WalletUnitJWT(attestation) = metadata);
            assert!(!attestation.is_empty());
            Ok(Uuid::new_v4().into())
        });

    let ssi_wallet_provider_service = SSIWalletProviderService {
        organisation_repository: Arc::new(organisation_repository),
        key_algorithm_provider: Arc::new(key_algorithm_provider),
        wallet_unit_repository: Arc::new(wallet_unit_repository),
        identifier_repository: Arc::new(identifier_repository),
        history_repository: Arc::new(history_repository),
        key_provider: Arc::new(key_provider),
        config: Arc::new(config),
        ..mock_ssi_wallet_service()
    };

    let (proof, holder_jwk) = create_proof().await;
    let request = RegisterWalletUnitRequestDTO {
        wallet_provider: procivis_one_provider.to_string(),
        os: WalletUnitOs::Android,
        public_key: Some(holder_jwk.public_key_as_jwk().unwrap().into()),
        proof: Some(proof),
    };

    // when
    let result = ssi_wallet_provider_service
        .register_wallet_unit(request)
        .await
        .unwrap();

    // then
    assert!(result.attestation.is_some());
    assert!(result.nonce.is_none());

    let attestation_jwt =
        Jwt::<WalletUnitClaims>::decompose_token(&result.attestation.unwrap()).unwrap();

    assert!(attestation_jwt.header.jwk.is_some());
}

#[tokio::test]
async fn test_register_wallet_unit_integrity_check() {
    // given
    let mut config = CoreConfig::default();
    let issuer_identifier_id: IdentifierId = Uuid::new_v4().into();
    let procivis_one_provider = "PROCIVIS_ONE";
    config.wallet_provider.insert(
        procivis_one_provider.to_string(),
        wallet_provider_config(true),
    );

    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation_for_wallet_provider()
        .returning(move |_| {
            Ok(Some(Organisation {
                id: Uuid::new_v4().into(),
                name: "test org".to_string(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                deactivated_at: None,
                wallet_provider: Some(procivis_one_provider.to_string()),
                wallet_provider_issuer: Some(issuer_identifier_id),
            }))
        });

    let mut wallet_unit_repository = MockWalletUnitRepository::new();
    wallet_unit_repository
        .expect_create_wallet_unit()
        .return_once(|wu| Ok(wu.id));

    let (issuer_private, issuer_public) = ECDSASigner::generate_key_pair();
    let issuer_public_clone = issuer_public.clone();
    let mut identifier_repository = MockIdentifierRepository::new();
    identifier_repository
        .expect_get()
        .return_once(move |id, _| {
            Ok(Some(Identifier {
                id,
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                name: "test".to_string(),
                r#type: IdentifierType::Key,
                is_remote: false,
                state: IdentifierState::Active,
                deleted_at: None,
                organisation: None,
                did: None,
                key: Some(Key {
                    id: Uuid::new_v4().into(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    public_key: issuer_public_clone,
                    name: "".to_string(),
                    key_reference: None,
                    storage_type: "TEST".to_string(),
                    key_type: "ECDSA".to_string(),
                    organisation: None,
                }),
                certificates: None,
            }))
        });

    let issuer_key_handle = Ecdsa
        .reconstruct_key(&issuer_public, Some(issuer_private.clone()), None)
        .unwrap();

    let mut key_storage = MockKeyStorage::new();
    key_storage
        .expect_key_handle()
        .return_once(|_| Ok(issuer_key_handle));

    let mut key_storages: HashMap<String, Arc<dyn KeyStorage>> = HashMap::new();
    key_storages.insert("TEST".to_string(), Arc::new(key_storage));

    let key_provider = KeyProviderImpl::new(key_storages);

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .return_once(|_| Ok(Uuid::new_v4().into()));

    let ssi_wallet_provider_service = SSIWalletProviderService {
        organisation_repository: Arc::new(organisation_repository),
        key_algorithm_provider: Arc::new(MockKeyAlgorithmProvider::new()),
        wallet_unit_repository: Arc::new(wallet_unit_repository),
        identifier_repository: Arc::new(identifier_repository),
        history_repository: Arc::new(history_repository),
        key_provider: Arc::new(key_provider),
        config: Arc::new(config),
        ..mock_ssi_wallet_service()
    };

    let request = RegisterWalletUnitRequestDTO {
        wallet_provider: "PROCIVIS_ONE".to_string(),
        os: WalletUnitOs::Android,
        public_key: None,
        proof: None,
    };

    // when
    let result = ssi_wallet_provider_service
        .register_wallet_unit(request)
        .await
        .unwrap();

    // then
    assert!(result.nonce.is_some());
    assert!(result.attestation.is_none());
}

#[tokio::test]
async fn test_refresh_wallet_unit_success() {
    // given
    let mut config = CoreConfig::default();
    let issuer_identifier_id: IdentifierId = Uuid::new_v4().into();
    let procivis_one_provider = "PROCIVIS_ONE";
    config.wallet_provider.insert(
        procivis_one_provider.to_string(),
        wallet_provider_config(false),
    );

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_parse_jwk()
        .once()
        .return_once(|jwk| {
            let algorithm = Ecdsa;
            let public_key = algorithm.parse_jwk(jwk).unwrap();
            Ok(ParsedKey {
                algorithm_type: algorithm.algorithm_type(),
                key: public_key,
            })
        });

    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .once()
        .return_once(|_| Some(Arc::new(Ecdsa)));
    // issuer key to sign attestation
    let (issuer_private, issuer_public) = ECDSASigner::generate_key_pair();
    let issuer_public_clone = issuer_public.clone();

    let mut identifier_repository = MockIdentifierRepository::new();
    identifier_repository
        .expect_get()
        .return_once(move |id, _| {
            Ok(Some(Identifier {
                id,
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                name: "issuer".to_string(),
                r#type: IdentifierType::Key,
                is_remote: false,
                state: IdentifierState::Active,
                deleted_at: None,
                organisation: None,
                did: None,
                key: Some(Key {
                    id: Uuid::new_v4().into(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    public_key: issuer_public_clone,
                    name: "".to_string(),
                    key_reference: None,
                    storage_type: "TEST".to_string(),
                    key_type: "ECDSA".to_string(),
                    organisation: None,
                }),
                certificates: None,
            }))
        });

    let issuer_key_handle = Ecdsa
        .reconstruct_key(&issuer_public, Some(issuer_private.clone()), None)
        .unwrap();

    let mut key_storage = MockKeyStorage::new();
    key_storage
        .expect_key_handle()
        .returning(move |_| Ok(issuer_key_handle.clone()));

    let mut key_storages: HashMap<String, Arc<dyn KeyStorage>> = HashMap::new();
    key_storages.insert("TEST".to_string(), Arc::new(key_storage));

    let key_provider = KeyProviderImpl::new(key_storages);

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .return_once(|_| Ok(Uuid::new_v4().into()));

    // wallet unit keypair (used by the app to prove possession)
    let (proof, holder_key_handle) = create_proof().await;
    let holder_public_key_str =
        serde_json::to_string(&holder_key_handle.public_key_as_jwk().unwrap()).unwrap();

    let now = OffsetDateTime::now_utc();
    let wallet_unit_id = Uuid::new_v4().into();

    let mut wallet_unit_repository = MockWalletUnitRepository::new();
    wallet_unit_repository
        .expect_get_wallet_unit()
        .return_once({
            move |id, _| {
                Ok(Some(WalletUnit {
                    id: *id,
                    name: "PROCIVIS_ONE-ANDROID-123".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    os: WalletUnitOs::Android,
                    status: crate::model::wallet_unit::WalletUnitStatus::Active,
                    wallet_provider_name: "PROCIVIS_ONE".to_string(),
                    wallet_provider_type: WalletProviderType::ProcivisOne,
                    public_key: Some(holder_public_key_str),
                    // ensure refresh window has passed
                    last_issuance: Some(now.sub(Duration::minutes(120))),
                    nonce: None,
                    organisation: Some(Organisation {
                        id: Uuid::new_v4().into(),
                        name: "test org".to_string(),
                        created_date: get_dummy_date(),
                        last_modified: get_dummy_date(),
                        deactivated_at: None,
                        wallet_provider: Some(procivis_one_provider.to_string()),
                        wallet_provider_issuer: Some(issuer_identifier_id),
                    }),
                }))
            }
        });
    wallet_unit_repository
        .expect_update_wallet_unit()
        .return_once(|_, u| {
            assert!(u.last_issuance.is_some());
            Ok(())
        });

    let ssi_wallet_provider_service = SSIWalletProviderService {
        key_algorithm_provider: Arc::new(key_algorithm_provider),
        wallet_unit_repository: Arc::new(wallet_unit_repository),
        identifier_repository: Arc::new(identifier_repository),
        history_repository: Arc::new(history_repository),
        key_provider: Arc::new(key_provider),
        config: Arc::new(config),
        ..mock_ssi_wallet_service()
    };

    // build refresh request with a valid proof signed by wallet unit key
    let request = RefreshWalletUnitRequestDTO { proof };

    // when
    let result = ssi_wallet_provider_service
        .refresh_wallet_unit(wallet_unit_id, request)
        .await;

    // then
    assert!(result.is_ok(), "Failed: {result:?}");
}

async fn create_proof() -> (String, KeyHandle) {
    let (holder_private, holder_public) = ECDSASigner::generate_key_pair();
    let holder_key_handle = Ecdsa
        .reconstruct_key(&holder_public, Some(holder_private.clone()), None)
        .unwrap();

    let jwk = holder_key_handle.public_key_as_jwk().unwrap();

    let now = OffsetDateTime::now_utc();
    let proof = Jwt {
        header: JWTHeader {
            algorithm: "ES256".to_string(),
            key_id: None,
            r#type: None,
            jwk: Some(jwk.clone().into()),
            jwt: None,
            x5c: None,
        },
        payload: JWTPayload {
            issued_at: Some(now.sub(Duration::minutes(30))),
            expires_at: Some(now.add(Duration::minutes(30))),
            invalid_before: Some(now.sub(Duration::minutes(20))),
            issuer: None,
            subject: None,
            audience: Some(vec![BASE_URL.to_string()]),
            jwt_id: None,
            proof_of_possession_key: None,
            custom: (),
        },
    };

    let signer = FakeEcdsaSigner {
        public_key: holder_public,
        private_key: holder_private,
        key_id: "".to_string(),
    };
    let proof = proof.tokenize(Some(Box::new(signer))).await.unwrap();

    (proof, holder_key_handle)
}

struct FakeEcdsaSigner {
    public_key: Vec<u8>,
    private_key: SecretSlice<u8>,
    key_id: String,
}

#[async_trait]
impl SignatureProvider for FakeEcdsaSigner {
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
