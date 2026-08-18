use std::collections::HashMap;
use std::ops::{Add, Sub};
use std::sync::Arc;

use async_trait::async_trait;
use one_crypto::Signer;
use one_crypto::signer::ecdsa::ECDSASigner;
use secrecy::SecretSlice;
use serde_json::json;
use shared_types::IdentifierId;
use similar_asserts::assert_eq;
use time::Duration;
use uuid::Uuid;

use crate::config;
use crate::config::core_config::{
    CoreConfig, DocumentSignerType, Fields, KeyAlgorithmType, Params,
};
use crate::error::{ErrorCode, ErrorCodeMixin};
use crate::model::common::GetListResponse;
use crate::model::credential_schema::CredentialSchema;
use crate::model::identifier::{Identifier, IdentifierData, IdentifierState};
use crate::model::instance::{InstanceRole, InstanceStatus};
use crate::model::key::Key;
use crate::model::managed_instance::{ManagedInstance, ManagedInstanceOs};
use crate::model::organisation::{Organisation, OrganisationConfiguration};
use crate::model::relation::Related;
use crate::model::trust_collection::TrustCollection;
use crate::proto::certificate_validator::MockCertificateValidator;
use crate::proto::clock::DefaultClock;
use crate::proto::http_client::{
    Method, MockHttpClient, Request, RequestBuilder, Response, StatusCode,
};
use crate::proto::jwt::Jwt;
use crate::proto::jwt::model::{JWTHeader, JWTPayload};
use crate::proto::session_provider::NoSessionProvider;
use crate::proto::session_provider::test::StaticSessionProvider;
use crate::proto::transaction_manager::NoTransactionManager;
use crate::provider::credential_formatter::common::SignatureProvider;
use crate::provider::document_signer::provider::{
    DocumentSignerMetadata, MockDocumentSignerProvider,
};
use crate::provider::key_algorithm::KeyAlgorithm;
use crate::provider::key_algorithm::ecdsa::Ecdsa;
use crate::provider::key_algorithm::error::KeyAlgorithmError;
use crate::provider::key_algorithm::key::KeyHandle;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::key_storage::MockKeyStorage;
use crate::provider::key_storage::provider::MockKeyProvider;
use crate::provider::revocation::provider::MockRevocationMethodProvider;
use crate::provider::signer::provider::MockSignerProvider;
use crate::provider::verifier::model::{ConfigFeatureFlags, VerifierParams};
use crate::provider::verifier::provider::MockVerifierProvider;
use crate::repository::credential_schema_repository::MockCredentialSchemaRepository;
use crate::repository::history_repository::MockHistoryRepository;
use crate::repository::identifier_repository::MockIdentifierRepository;
use crate::repository::managed_instance_repository::MockManagedInstanceRepository;
use crate::repository::organisation_repository::MockOrganisationRepository;
use crate::repository::trust_collection_repository::MockTrustCollectionRepository;
use crate::service::common_dto::ListQueryDTO;
use crate::service::managed_instance::ManagedInstanceService;
use crate::service::managed_instance::dto::{
    DisplayNameDTO, ManagedInstanceFilterParamsDTO, RegisterWalletUnitRequestDTO,
};
use crate::service::test_utilities::{
    dummy_credential_schema, dummy_organisation, generic_config, get_dummy_date,
};

const BASE_URL: &str = "https://localhost";

fn mock_wallet_provider_service() -> ManagedInstanceService {
    ManagedInstanceService {
        organisation_repository: Arc::new(MockOrganisationRepository::default()),
        wallet_instance_repository: Arc::new(MockManagedInstanceRepository::default()),
        identifier_repository: Arc::new(MockIdentifierRepository::default()),
        history_repository: Arc::new(MockHistoryRepository::default()),
        trust_collection_repository: Arc::new(MockTrustCollectionRepository::default()),
        credential_schema_repository: Arc::new(MockCredentialSchemaRepository::default()),
        tx_manager: Arc::new(NoTransactionManager),
        key_provider: Arc::new(MockKeyProvider::default()),
        key_algorithm_provider: Arc::new(MockKeyAlgorithmProvider::default()),
        revocation_method_provider: Arc::new(MockRevocationMethodProvider::default()),
        signer_provider: Arc::new(MockSignerProvider::default()),
        certificate_validator: Arc::new(MockCertificateValidator::default()),
        http_client: Arc::new(MockHttpClient::default()),
        clock: Arc::new(DefaultClock),
        base_url: Some(BASE_URL.to_string()),
        config: Arc::new(CoreConfig::default()),
        session_provider: Arc::new(NoSessionProvider),
        document_signer_provider: Arc::new(MockDocumentSignerProvider::default()),
        verifier_provider: Arc::new(MockVerifierProvider::default()),
    }
}

fn wallet_provider_config(
    integrity_check_enabled: bool,
) -> Fields<config::core_config::WalletProviderType> {
    Fields {
        r#type: config::core_config::WalletProviderType::ProcivisOne,
        display: "display".into(),
        order: None,
        priority: None,
        enabled: true,
        capabilities: None,
        params: Some(Params {
            public: Some(json!({
                "walletName": "Procivis One Dev Wallet",
                "walletClientId": "mock-client-id",
                "walletLink": "https://procivis.ch",
                "walletRegistration": "MANDATORY",
                "walletInstanceAttestation": {
                    "expirationSeconds": 60,
                    "integrityCheck": {
                        "enabled": integrity_check_enabled,
                        "android": {
                            "bundleId": "com.procivis...",
                            "signingCertificateFingerprints": ["test"],
                            "trustedAttestationCAs": ["-----BEGIN CERTIFICATE-----..."]
                        },
                        "ios": {
                            "bundleId": "com.procivis...",
                            "trustedAttestationCAs": ["-----BEGIN CERTIFICATE-----..."],
                            "enforceProductionBuild": true
                        }
                    },
                },
                "walletUnitAttestation": {
                    "expirationSeconds": 60
                },
                "deviceAuthLeewaySeconds": 60,
                "appVersion": {
                    "minimum": "v1.50.0",
                },
                "featureFlags": {
                    "ecosystemsEnabled": true,
                    "refreshCredentialBatchEnabled": true,
                    "documentSigningEnabled": true
                },
                "documentSigners": ["SIGN8"]
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
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                wallet_provider: Some(procivis_one_provider.to_string()),
                wallet_provider_issuer: Some(issuer_identifier_id),
                ..dummy_organisation(None)
            }))
        });

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_jose_alg()
        .once()
        .return_once(|_| Some((KeyAlgorithmType::Ecdsa, Arc::new(Ecdsa))));

    let mut wallet_unit_repository = MockManagedInstanceRepository::new();
    wallet_unit_repository
        .expect_create()
        .return_once(|wu| Ok(wu.id));

    let (issuer_private, issuer_public) = ECDSASigner::generate_key_pair();
    let issuer_public_clone = issuer_public.clone();
    let mut identifier_repository = MockIdentifierRepository::new();
    identifier_repository.expect_get().return_once(move |id| {
        Ok(Identifier {
            id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            name: "test".to_string(),
            data: IdentifierData::Key(Related::from(Key {
                id: Uuid::new_v4().into(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                public_key: issuer_public_clone,
                name: "".to_string(),
                key_reference: None,
                storage_type: "TEST".to_string(),
                key_type: "ECDSA".to_string(),
                organisation: dummy_organisation(None).into(),
            })),
            is_remote: false,
            state: IdentifierState::Active,
            deleted_at: None,
            organisation: dummy_organisation(Some(uuid::Uuid::new_v4().into())).into(),
            trust_information: Default::default(),
        })
    });

    let issuer_key_handle = Ecdsa
        .reconstruct_key(&issuer_public, Some(issuer_private.clone()), None)
        .unwrap();

    let mut key_storage = MockKeyStorage::new();
    key_storage
        .expect_key_handle()
        .returning(move |_| Ok(issuer_key_handle.clone()));

    let key_storage = Arc::new(key_storage);
    let mut key_provider = MockKeyProvider::new();
    key_provider
        .expect_get_key_storage()
        .returning(move |_| Ok(key_storage.clone()));

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .return_once(|_| Ok(Uuid::new_v4().into()));

    let ssi_wallet_provider_service = ManagedInstanceService {
        organisation_repository: Arc::new(organisation_repository),
        key_algorithm_provider: Arc::new(key_algorithm_provider),
        wallet_instance_repository: Arc::new(wallet_unit_repository),
        identifier_repository: Arc::new(identifier_repository),
        history_repository: Arc::new(history_repository),
        key_provider: Arc::new(key_provider),
        config: Arc::new(config),
        ..mock_wallet_provider_service()
    };

    let (proof, holder_jwk) = create_proof().await;
    let request = RegisterWalletUnitRequestDTO {
        provider: procivis_one_provider.to_string(),
        role: InstanceRole::Wallet,
        os: ManagedInstanceOs::Android,
        public_key: Some(holder_jwk.public_key_as_jwk().unwrap()),
        proof: Some(proof),
    };

    // when
    let result = ssi_wallet_provider_service
        .register_instance(request)
        .await
        .unwrap();

    // then
    assert!(result.nonce.is_none());
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
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                wallet_provider: Some(procivis_one_provider.to_string()),
                wallet_provider_issuer: Some(issuer_identifier_id),
                ..dummy_organisation(None)
            }))
        });

    let mut wallet_unit_repository = MockManagedInstanceRepository::new();
    wallet_unit_repository
        .expect_create()
        .return_once(|wu| Ok(wu.id));

    let (issuer_private, issuer_public) = ECDSASigner::generate_key_pair();
    let issuer_public_clone = issuer_public.clone();
    let mut identifier_repository = MockIdentifierRepository::new();
    identifier_repository.expect_get().return_once(move |id| {
        Ok(Identifier {
            id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            name: "test".to_string(),
            data: IdentifierData::Key(Related::from(Key {
                id: Uuid::new_v4().into(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                public_key: issuer_public_clone,
                name: "".to_string(),
                key_reference: None,
                storage_type: "TEST".to_string(),
                key_type: "ECDSA".to_string(),
                organisation: dummy_organisation(None).into(),
            })),
            is_remote: false,
            state: IdentifierState::Active,
            deleted_at: None,
            organisation: dummy_organisation(Some(uuid::Uuid::new_v4().into())).into(),
            trust_information: Default::default(),
        })
    });

    let issuer_key_handle = Ecdsa
        .reconstruct_key(&issuer_public, Some(issuer_private.clone()), None)
        .unwrap();

    let mut key_storage = MockKeyStorage::new();
    key_storage
        .expect_key_handle()
        .return_once(|_| Ok(issuer_key_handle));

    let key_storage = Arc::new(key_storage);
    let mut key_provider = MockKeyProvider::new();
    key_provider
        .expect_get_key_storage()
        .returning(move |_| Ok(key_storage.clone()));

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .return_once(|_| Ok(Uuid::new_v4().into()));

    let ssi_wallet_provider_service = ManagedInstanceService {
        organisation_repository: Arc::new(organisation_repository),
        key_algorithm_provider: Arc::new(MockKeyAlgorithmProvider::new()),
        wallet_instance_repository: Arc::new(wallet_unit_repository),
        identifier_repository: Arc::new(identifier_repository),
        history_repository: Arc::new(history_repository),
        key_provider: Arc::new(key_provider),
        config: Arc::new(config),
        ..mock_wallet_provider_service()
    };

    let request = RegisterWalletUnitRequestDTO {
        provider: "PROCIVIS_ONE".to_string(),
        role: InstanceRole::Wallet,
        os: ManagedInstanceOs::Android,
        public_key: None,
        proof: None,
    };

    // when
    let result = ssi_wallet_provider_service
        .register_instance(request)
        .await
        .unwrap();

    // then
    assert!(result.nonce.is_some());
}

fn verifier_provider_params() -> VerifierParams {
    VerifierParams {
        app_version: None,
        feature_flags: ConfigFeatureFlags {
            ecosystems_enabled: false,
            ecosystems_enforcement_enabled: false,
        },
        verifier_instance_attestation: None,
        user_authentication: None,
        access_certificate_configuration: None,
        device_auth_leeway_seconds: Duration::seconds(60),
    }
}

#[tokio::test]
async fn test_register_verifier_unit() {
    // given
    let issuer_identifier_id: IdentifierId = Uuid::new_v4().into();
    let verifier_provider_name = "VERIFIER_PROVIDER";

    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation_for_verifier_provider()
        .returning(move |_| {
            Ok(Some(Organisation {
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                verifier_provider: Some(verifier_provider_name.to_string()),
                verifier_provider_issuer: Some(issuer_identifier_id),
                ..dummy_organisation(None)
            }))
        });

    let mut verifier_provider = MockVerifierProvider::new();
    verifier_provider
        .expect_get_by_id()
        .withf(|id| id == "VERIFIER_PROVIDER")
        .returning(|_| Ok(verifier_provider_params()));

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_jose_alg()
        .once()
        .return_once(|_| Some((KeyAlgorithmType::Ecdsa, Arc::new(Ecdsa))));

    let mut wallet_unit_repository = MockManagedInstanceRepository::new();
    wallet_unit_repository
        .expect_create()
        .return_once(|wu| Ok(wu.id));

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .return_once(|_| Ok(Uuid::new_v4().into()));

    let service = ManagedInstanceService {
        organisation_repository: Arc::new(organisation_repository),
        key_algorithm_provider: Arc::new(key_algorithm_provider),
        wallet_instance_repository: Arc::new(wallet_unit_repository),
        history_repository: Arc::new(history_repository),
        verifier_provider: Arc::new(verifier_provider),
        ..mock_wallet_provider_service()
    };

    let (proof, holder_jwk) = create_proof().await;
    let request = RegisterWalletUnitRequestDTO {
        provider: verifier_provider_name.to_string(),
        role: InstanceRole::Verifier,
        os: ManagedInstanceOs::Android,
        public_key: Some(holder_jwk.public_key_as_jwk().unwrap()),
        proof: Some(proof),
    };

    // when
    let result = service.register_instance(request).await.unwrap();

    // then
    assert!(result.nonce.is_none());
}

#[tokio::test]
async fn test_register_verifier_unit_provider_not_associated_with_organisation() {
    // given
    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation_for_verifier_provider()
        .returning(|_| Ok(None));

    let service = ManagedInstanceService {
        organisation_repository: Arc::new(organisation_repository),
        ..mock_wallet_provider_service()
    };

    let request = RegisterWalletUnitRequestDTO {
        provider: "VERIFIER_PROVIDER".to_string(),
        role: InstanceRole::Verifier,
        os: ManagedInstanceOs::Android,
        public_key: None,
        proof: None,
    };

    // when
    let result = service.register_instance(request).await;

    // then
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0471);
}

// ===== validate_org_verifier_provider tests =====
// Regression coverage for BR_0470: a verifier-role failure must not surface the
// wallet-flavored "Wallet provider not configured" message (BR_0284).

#[test]
fn validate_org_verifier_provider_organisation_disabled() {
    let org = Organisation {
        deactivated_at: Some(get_dummy_date()),
        verifier_provider: Some("VERIFIER_PROVIDER".to_string()),
        verifier_provider_issuer: Some(Uuid::new_v4().into()),
        ..dummy_organisation(None)
    };

    let result = super::validator::validate_org_verifier_provider(&org, "VERIFIER_PROVIDER");

    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0470);
}

#[test]
fn validate_org_verifier_provider_not_configured_on_organisation() {
    let org = dummy_organisation(None); // no verifier_provider set

    let result = super::validator::validate_org_verifier_provider(&org, "VERIFIER_PROVIDER");

    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0470);
}

#[test]
fn validate_org_verifier_provider_mismatched_provider() {
    let org = Organisation {
        verifier_provider: Some("OTHER_PROVIDER".to_string()),
        verifier_provider_issuer: Some(Uuid::new_v4().into()),
        ..dummy_organisation(None)
    };

    let result = super::validator::validate_org_verifier_provider(&org, "VERIFIER_PROVIDER");

    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0470);
}

#[test]
fn validate_org_verifier_provider_missing_issuer() {
    let org = Organisation {
        verifier_provider: Some("VERIFIER_PROVIDER".to_string()),
        verifier_provider_issuer: None,
        ..dummy_organisation(None)
    };

    let result = super::validator::validate_org_verifier_provider(&org, "VERIFIER_PROVIDER");

    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0470);
}

#[test]
fn validate_org_verifier_provider_success() {
    let issuer_id: IdentifierId = Uuid::new_v4().into();
    let org = Organisation {
        verifier_provider: Some("VERIFIER_PROVIDER".to_string()),
        verifier_provider_issuer: Some(issuer_id),
        ..dummy_organisation(None)
    };

    let result = super::validator::validate_org_verifier_provider(&org, "VERIFIER_PROVIDER");

    assert_eq!(result.unwrap(), issuer_id);
}

#[tokio::test]
async fn provider_wallet_unit_ops_session_org_mismatch() {
    // given
    let service = ManagedInstanceService {
        session_provider: Arc::new(StaticSessionProvider::new_random()),
        config: Arc::new(generic_config().core),
        ..mock_wallet_provider_service()
    };

    // when
    let result = service
        .get_managed_instance_list(ListQueryDTO {
            page: 0,
            page_size: 1,
            sort: None,
            sort_direction: None,
            filter: ManagedInstanceFilterParamsDTO {
                name: None,
                ids: None,
                status: None,
                os: None,
                provider_names: None,
                roles: None,
                attestation: None,
                organisation_id: Uuid::new_v4().into(),
                created_date_after: None,
                created_date_before: None,
                user_sub: None,
            },
            include: None,
        })
        .await;

    // then
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);
}

#[tokio::test]
async fn provider_get_wallet_unit_session_org_mismatch() {
    let wallet_unit = ManagedInstance {
        id: Uuid::new_v4().into(),
        name: "".to_string(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        os: ManagedInstanceOs::Ios,
        status: InstanceStatus::Active,
        role: InstanceRole::Wallet,
        provider: "test provider".to_string(),
        authentication_key_jwk: None,
        last_issuance: None,
        nonce: None,
        user_nonce: None,
        user_sub: None,
        verifier_csr: None,
        verifier_signature_ids: None,
        organisation: dummy_organisation(None).into(),
        attested_keys: Default::default(),
    };
    let mut wallet_unit_repository = MockManagedInstanceRepository::new();
    wallet_unit_repository
        .expect_get()
        .returning(move |_| Ok(wallet_unit.clone()));

    // given
    let service = ManagedInstanceService {
        wallet_instance_repository: Arc::new(wallet_unit_repository),
        session_provider: Arc::new(StaticSessionProvider::new_random()),
        config: Arc::new(generic_config().core),
        ..mock_wallet_provider_service()
    };

    // when
    let result = service.get_managed_instance(&Uuid::new_v4().into()).await;

    // then
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);
}

async fn create_proof() -> (String, KeyHandle) {
    let (holder_private, holder_public) = ECDSASigner::generate_key_pair();
    let holder_key_handle = Ecdsa
        .reconstruct_key(&holder_public, Some(holder_private.clone()), None)
        .unwrap();

    let jwk = holder_key_handle.public_key_as_jwk().unwrap();

    let now = crate::clock::now_utc();
    let proof = Jwt {
        header: JWTHeader {
            algorithm: "ES256".to_string(),
            key_id: None,
            r#type: None,
            jwk: Some(jwk.clone()),
            jwt: None,
            key_attestation: None,
            x5c: None,
            x5u: None,
            x5t_s256: None,
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
    let proof = proof.tokenize(Some(&signer)).await.unwrap();

    (proof, holder_key_handle)
}

struct FakeEcdsaSigner {
    public_key: Vec<u8>,
    private_key: SecretSlice<u8>,
    key_id: String,
}

#[async_trait]
impl SignatureProvider for FakeEcdsaSigner {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeyAlgorithmError> {
        Ok(ECDSASigner.sign(message, &self.public_key, &self.private_key)?)
    }

    fn get_key_id(&self) -> Option<String> {
        Some(self.key_id.clone())
    }

    fn get_key_algorithm(&self) -> Result<KeyAlgorithmType, KeyAlgorithmError> {
        Ok(KeyAlgorithmType::Ecdsa)
    }

    fn jose_alg(&self) -> Result<String, KeyAlgorithmError> {
        Ok("ES256".to_string())
    }

    fn get_public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }
}

// ===== validate_user_id_token tests =====

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct TestIdTokenClaims {
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
}

fn user_auth_params(required: bool) -> super::dto::UserAuthenticationParams {
    super::dto::UserAuthenticationParams {
        required,
        identity_provider: "https://idp.example.com".to_string(),
        client_id: "my-client".to_string(),
        redirect_uri: "myapp://callback".to_string(),
        token_validation: super::dto::TokenValidationParams {
            aud: "test-aud".to_string(),
            iss: "https://idp.example.com".to_string(),
            jwks_uri: "https://idp.example.com/.well-known/jwks.json".to_string(),
        },
    }
}

async fn make_user_id_token(
    iss: &str,
    aud: &str,
    sub: Option<&str>,
    nonce: Option<&str>,
) -> (String, standardized_types::jwk::PublicJwk) {
    let (private, public) = ECDSASigner::generate_key_pair();
    let key_handle = Ecdsa
        .reconstruct_key(&public, Some(private.clone()), None)
        .unwrap();
    let public_jwk = key_handle.public_key_as_jwk().unwrap();

    let jwt: Jwt<TestIdTokenClaims> = Jwt {
        header: JWTHeader {
            algorithm: "ES256".to_string(),
            key_id: None,
            r#type: None,
            jwk: None,
            jwt: None,
            key_attestation: None,
            x5c: None,
            x5u: None,
            x5t_s256: None,
        },
        payload: JWTPayload {
            issued_at: None,
            expires_at: None,
            invalid_before: None,
            issuer: Some(iss.to_string()),
            subject: sub.map(str::to_string),
            audience: Some(vec![aud.to_string()]),
            jwt_id: None,
            proof_of_possession_key: None,
            custom: TestIdTokenClaims {
                nonce: nonce.map(str::to_string),
            },
        },
    };

    let signer = FakeEcdsaSigner {
        public_key: public,
        private_key: private,
        key_id: "".to_string(),
    };
    let token = jwt.tokenize(Some(&signer)).await.unwrap();
    (token, public_jwk)
}

fn make_jwks_http_client(public_jwk: standardized_types::jwk::PublicJwk) -> MockHttpClient {
    let jwks_body = serde_json::to_vec(&serde_json::json!({ "keys": [public_jwk] })).unwrap();
    let mut http_client = MockHttpClient::new();
    http_client.expect_get().returning(move |url| {
        let body = jwks_body.clone();
        let url_owned = url.to_string();
        let url_for_inner = url_owned.clone();
        let mut inner = MockHttpClient::new();
        inner.expect_send().returning(move |_, _, _, _, _| {
            Ok(Response {
                body: body.clone(),
                headers: Default::default(),
                status: StatusCode(200),
                request: Request {
                    body: None,
                    headers: Default::default(),
                    method: Method::Get,
                    url: url_for_inner.clone(),
                    timeout: None,
                },
            })
        });
        RequestBuilder::new(Arc::new(inner), Method::Get, &url_owned)
    });
    http_client
}

fn make_jwks_http_client_error() -> MockHttpClient {
    let mut http_client = MockHttpClient::new();
    http_client.expect_get().returning(|url| {
        let url_owned = url.to_string();
        let url_for_inner = url_owned.clone();
        let mut inner = MockHttpClient::new();
        inner.expect_send().returning(move |_, _, _, _, _| {
            Ok(Response {
                body: vec![],
                headers: Default::default(),
                status: StatusCode(500),
                request: Request {
                    body: None,
                    headers: Default::default(),
                    method: Method::Get,
                    url: url_for_inner.clone(),
                    timeout: None,
                },
            })
        });
        RequestBuilder::new(Arc::new(inner), Method::Get, &url_owned)
    });
    http_client
}

fn make_key_algorithm_provider() -> MockKeyAlgorithmProvider {
    let mut kap = MockKeyAlgorithmProvider::new();
    kap.expect_key_algorithm_from_jose_alg()
        .returning(|_| Some((KeyAlgorithmType::Ecdsa, Arc::new(Ecdsa))));
    kap
}

#[tokio::test]
async fn validate_user_id_token_no_token_not_required() {
    let service = mock_wallet_provider_service();
    let result = service.validate_user_id_token(None, None, None).await;
    assert_eq!(result.unwrap(), None);
}

#[tokio::test]
async fn validate_user_id_token_no_token_optional_auth() {
    let service = mock_wallet_provider_service();
    let auth = user_auth_params(false);
    let result = service
        .validate_user_id_token(None, Some(&auth), None)
        .await;
    assert_eq!(result.unwrap(), None);
}

#[tokio::test]
async fn validate_user_id_token_no_token_required() {
    let service = mock_wallet_provider_service();
    let auth = user_auth_params(true);
    let result = service
        .validate_user_id_token(None, Some(&auth), None)
        .await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0447);
}

#[tokio::test]
async fn validate_user_id_token_not_expected() {
    let service = mock_wallet_provider_service();
    let result = service
        .validate_user_id_token(Some("some.jwt.token"), None, None)
        .await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0446);
}

#[tokio::test]
async fn validate_user_id_token_invalid_jwt_format() {
    let service = mock_wallet_provider_service();
    let auth = user_auth_params(false);
    let result = service
        .validate_user_id_token(Some("not-a-jwt"), Some(&auth), Some("nonce"))
        .await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0448);
}

#[tokio::test]
async fn validate_user_id_token_jwks_fetch_error() {
    let (token, _) = make_user_id_token(
        "https://idp.example.com",
        "test-aud",
        Some("user-sub"),
        Some("nonce-123"),
    )
    .await;

    let service = ManagedInstanceService {
        http_client: Arc::new(make_jwks_http_client_error()),
        ..mock_wallet_provider_service()
    };
    let auth = user_auth_params(false);
    let result = service
        .validate_user_id_token(Some(&token), Some(&auth), Some("nonce-123"))
        .await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0347);
}

#[tokio::test]
async fn validate_user_id_token_no_matching_jwks_key() {
    let (token, _) = make_user_id_token(
        "https://idp.example.com",
        "test-aud",
        Some("user-sub"),
        Some("nonce-123"),
    )
    .await;

    let jwks_body = serde_json::to_vec(&serde_json::json!({ "keys": [] })).unwrap();
    let mut http_client = MockHttpClient::new();
    http_client.expect_get().returning(move |url| {
        let body = jwks_body.clone();
        let url_owned = url.to_string();
        let url_for_inner = url_owned.clone();
        let mut inner = MockHttpClient::new();
        inner.expect_send().returning(move |_, _, _, _, _| {
            Ok(Response {
                body: body.clone(),
                headers: Default::default(),
                status: StatusCode(200),
                request: Request {
                    body: None,
                    headers: Default::default(),
                    method: Method::Get,
                    url: url_for_inner.clone(),
                    timeout: None,
                },
            })
        });
        RequestBuilder::new(Arc::new(inner), Method::Get, &url_owned)
    });

    let service = ManagedInstanceService {
        http_client: Arc::new(http_client),
        key_algorithm_provider: Arc::new(make_key_algorithm_provider()),
        ..mock_wallet_provider_service()
    };
    let auth = user_auth_params(false);
    let result = service
        .validate_user_id_token(Some(&token), Some(&auth), Some("nonce-123"))
        .await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0448);
}

#[tokio::test]
async fn validate_user_id_token_invalid_iss() {
    let (token, public_jwk) = make_user_id_token(
        "https://wrong-idp.example.com",
        "test-aud",
        Some("user-sub"),
        Some("nonce-123"),
    )
    .await;

    let service = ManagedInstanceService {
        http_client: Arc::new(make_jwks_http_client(public_jwk)),
        key_algorithm_provider: Arc::new(make_key_algorithm_provider()),
        ..mock_wallet_provider_service()
    };
    let auth = user_auth_params(false);
    let result = service
        .validate_user_id_token(Some(&token), Some(&auth), Some("nonce-123"))
        .await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0448);
}

#[tokio::test]
async fn validate_user_id_token_invalid_aud() {
    let (token, public_jwk) = make_user_id_token(
        "https://idp.example.com",
        "wrong-aud",
        Some("user-sub"),
        Some("nonce-123"),
    )
    .await;

    let service = ManagedInstanceService {
        http_client: Arc::new(make_jwks_http_client(public_jwk)),
        key_algorithm_provider: Arc::new(make_key_algorithm_provider()),
        ..mock_wallet_provider_service()
    };
    let auth = user_auth_params(false);
    let result = service
        .validate_user_id_token(Some(&token), Some(&auth), Some("nonce-123"))
        .await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0448);
}

#[tokio::test]
async fn validate_user_id_token_missing_user_nonce() {
    let (token, public_jwk) = make_user_id_token(
        "https://idp.example.com",
        "test-aud",
        Some("user-sub"),
        Some("nonce-123"),
    )
    .await;

    let service = ManagedInstanceService {
        http_client: Arc::new(make_jwks_http_client(public_jwk)),
        key_algorithm_provider: Arc::new(make_key_algorithm_provider()),
        ..mock_wallet_provider_service()
    };
    let auth = user_auth_params(false);
    let result = service
        .validate_user_id_token(Some(&token), Some(&auth), None)
        .await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0448);
}

#[tokio::test]
async fn validate_user_id_token_nonce_mismatch() {
    let (token, public_jwk) = make_user_id_token(
        "https://idp.example.com",
        "test-aud",
        Some("user-sub"),
        Some("wrong-nonce"),
    )
    .await;

    let service = ManagedInstanceService {
        http_client: Arc::new(make_jwks_http_client(public_jwk)),
        key_algorithm_provider: Arc::new(make_key_algorithm_provider()),
        ..mock_wallet_provider_service()
    };
    let auth = user_auth_params(false);
    let result = service
        .validate_user_id_token(Some(&token), Some(&auth), Some("expected-nonce"))
        .await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0448);
}

#[tokio::test]
async fn validate_user_id_token_missing_sub() {
    let (token, public_jwk) = make_user_id_token(
        "https://idp.example.com",
        "test-aud",
        None, // no sub
        Some("nonce-123"),
    )
    .await;

    let service = ManagedInstanceService {
        http_client: Arc::new(make_jwks_http_client(public_jwk)),
        key_algorithm_provider: Arc::new(make_key_algorithm_provider()),
        ..mock_wallet_provider_service()
    };
    let auth = user_auth_params(false);
    let result = service
        .validate_user_id_token(Some(&token), Some(&auth), Some("nonce-123"))
        .await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0448);
}

#[tokio::test]
async fn validate_user_id_token_success() {
    let (token, public_jwk) = make_user_id_token(
        "https://idp.example.com",
        "test-aud",
        Some("user-sub-123"),
        Some("nonce-123"),
    )
    .await;

    let service = ManagedInstanceService {
        http_client: Arc::new(make_jwks_http_client(public_jwk)),
        key_algorithm_provider: Arc::new(make_key_algorithm_provider()),
        ..mock_wallet_provider_service()
    };
    let auth = user_auth_params(false);
    let result = service
        .validate_user_id_token(Some(&token), Some(&auth), Some("nonce-123"))
        .await;
    assert_eq!(result.unwrap(), Some("user-sub-123".to_string()));
}

#[tokio::test]
async fn test_get_wallet_provider_metadata_includes_document_signers() {
    let mut config = CoreConfig::default();
    config
        .wallet_provider
        .insert("PROCIVIS_ONE".to_string(), wallet_provider_config(false));

    let mut document_signer_provider = MockDocumentSignerProvider::default();
    document_signer_provider
        .expect_metadata()
        .withf(|name| name == "SIGN8")
        .once()
        .returning(|_| {
            Ok(DocumentSignerMetadata {
                r#type: DocumentSignerType::WalletCentric,
                display_name: HashMap::from([
                    ("en".to_string(), "SIGN8 Signer".to_string()),
                    ("de".to_string(), "SIGN8 Signierer".to_string()),
                ]),
                description: HashMap::from([
                    ("en".to_string(), "Sign documents".to_string()),
                    ("de".to_string(), "Dokumente signieren".to_string()),
                ]),
                logo: "sign8-logo".to_string(),
            })
        });

    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation_for_wallet_provider()
        .once()
        .returning(|_| Ok(None));

    let mut service = mock_wallet_provider_service();
    service.config = Arc::new(config);
    service.document_signer_provider = Arc::new(document_signer_provider);
    service.organisation_repository = Arc::new(organisation_repository);

    let result = service
        .get_wallet_provider_metadata("PROCIVIS_ONE".to_string())
        .await
        .unwrap();

    assert!(result.feature_flags.document_signing_enabled);
    assert!(result.ecosystems.is_empty());
    assert!(!result.feature_flags.ecosystems_enforcement_enabled);
    assert_eq!(result.document_signers.len(), 1);

    let doc_signer = &result.document_signers[0];
    assert_eq!(doc_signer.name, "SIGN8");
    assert_eq!(doc_signer.r#type, DocumentSignerType::WalletCentric);
    assert_eq!(doc_signer.logo, "sign8-logo");
    assert_eq!(doc_signer.display_name.len(), 2);
    assert_eq!(doc_signer.description.len(), 2);
}

fn display_names(values: &[DisplayNameDTO]) -> Vec<(String, String)> {
    values
        .iter()
        .map(|entry| (entry.lang.to_owned(), entry.value.to_owned()))
        .collect()
}

fn eudi_ecosystem_config() -> Fields<config::core_config::EcosystemProviderType> {
    Fields {
        r#type: config::core_config::EcosystemProviderType::Eudi,
        display: config::core_config::ConfigEntryDisplay::Translated(HashMap::from([(
            "en".to_string(),
            "EUDI".to_string(),
        )])),
        order: None,
        priority: None,
        enabled: true,
        capabilities: None,
        params: Some(Params {
            public: Some(json!({
                "logo": "eudi-logo",
                "description": { "en": "EUDI ecosystem" },
            })),
            private: None,
        }),
    }
}

#[tokio::test]
async fn test_get_wallet_provider_metadata_includes_ecosystems_of_provider_organisation() {
    let organisation_id = Uuid::new_v4().into();
    // the advertised ecosystems are the ones selected by the provider organisation
    let organisation = Organisation {
        wallet_provider: Some("PROCIVIS_ONE".to_string()),
        configuration: OrganisationConfiguration {
            selected_ecosystems: vec!["EUDI".into()],
            ..Default::default()
        },
        ..dummy_organisation(Some(organisation_id))
    };

    // the enforcement flag comes from the provider config
    let mut provider_config = wallet_provider_config(false);
    let public = provider_config
        .params
        .as_mut()
        .and_then(|params| params.public.as_mut())
        .unwrap();
    public["featureFlags"]["ecosystemsEnforcementEnabled"] = json!(true);

    let mut config = CoreConfig::default();
    config
        .wallet_provider
        .insert("PROCIVIS_ONE".to_string(), provider_config);
    config
        .ecosystem
        .insert("EUDI".into(), eudi_ecosystem_config());

    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation_for_wallet_provider()
        .once()
        .return_once(move |_| Ok(Some(organisation)));

    let collection = TrustCollection {
        ecosystem: "EUDI".into(),
        id: Uuid::new_v4().into(),
        name: "EUDI collection".to_string(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        deactivated_at: None,
        remote_trust_collection_url: None,
        organisation: dummy_organisation(Some(organisation_id)).into(),
    };
    let collection_id = collection.id;

    let mut trust_collection_repository = MockTrustCollectionRepository::default();
    trust_collection_repository
        .expect_list()
        .once()
        .return_once(move |_| Ok(GetListResponse::one(collection)));

    let credential_schema = CredentialSchema {
        ecosystem: Some("EUDI".into()),
        imported_source_url: "https://schemas.example.com/pid".to_string(),
        ..dummy_credential_schema()
    };

    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    credential_schema_repository
        .expect_get_credential_schema_list()
        .once()
        .return_once(move |_| Ok(GetListResponse::one(credential_schema)));

    let mut document_signer_provider = MockDocumentSignerProvider::default();
    document_signer_provider.expect_metadata().returning(|_| {
        Ok(DocumentSignerMetadata {
            r#type: DocumentSignerType::WalletCentric,
            display_name: HashMap::new(),
            description: HashMap::new(),
            logo: "sign8-logo".to_string(),
        })
    });

    let mut service = mock_wallet_provider_service();
    service.config = Arc::new(config);
    service.organisation_repository = Arc::new(organisation_repository);
    service.trust_collection_repository = Arc::new(trust_collection_repository);
    service.credential_schema_repository = Arc::new(credential_schema_repository);
    service.document_signer_provider = Arc::new(document_signer_provider);

    let result = service
        .get_wallet_provider_metadata("PROCIVIS_ONE".to_string())
        .await
        .unwrap();

    assert!(result.feature_flags.ecosystems_enforcement_enabled);
    assert_eq!(result.ecosystems.len(), 1);

    let ecosystem = &result.ecosystems[0];
    assert_eq!(ecosystem.name, "EUDI".into());
    assert_eq!(ecosystem.logo, "eudi-logo");
    assert_eq!(
        display_names(&ecosystem.display_name),
        vec![("en".to_string(), "EUDI".to_string())]
    );
    assert_eq!(
        display_names(&ecosystem.description),
        vec![("en".to_string(), "EUDI ecosystem".to_string())]
    );
    assert_eq!(ecosystem.trust_collections.len(), 1);
    assert_eq!(ecosystem.trust_collections[0].id, collection_id);
    assert_eq!(ecosystem.trust_collections[0].name, "EUDI collection");
    assert_eq!(
        ecosystem.credential_schemas,
        vec!["https://schemas.example.com/pid".to_string()]
    );
    assert!(ecosystem.proof_schemas.is_empty());

    // the deprecated flat list mirrors the collections of the advertised ecosystems
    assert_eq!(result.trust_collections.len(), 1);
    assert_eq!(result.trust_collections[0].id, collection_id);
    assert_eq!(result.trust_collections[0].logo, "eudi-logo");
}

#[tokio::test]
async fn test_get_wallet_provider_metadata_fails_for_unknown_ecosystem() {
    let organisation = Organisation {
        wallet_provider: Some("PROCIVIS_ONE".to_string()),
        configuration: OrganisationConfiguration {
            selected_ecosystems: vec!["UNKNOWN".into()],
            ..Default::default()
        },
        ..dummy_organisation(None)
    };

    let mut config = CoreConfig::default();
    config
        .wallet_provider
        .insert("PROCIVIS_ONE".to_string(), wallet_provider_config(false));
    config
        .ecosystem
        .insert("EUDI".into(), eudi_ecosystem_config());

    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation_for_wallet_provider()
        .once()
        .return_once(move |_| Ok(Some(organisation)));

    let mut trust_collection_repository = MockTrustCollectionRepository::default();
    trust_collection_repository
        .expect_list()
        .once()
        .return_once(|_| Ok(GetListResponse::empty()));

    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    credential_schema_repository
        .expect_get_credential_schema_list()
        .once()
        .return_once(|_| Ok(GetListResponse::empty()));

    let mut service = mock_wallet_provider_service();
    service.config = Arc::new(config);
    service.organisation_repository = Arc::new(organisation_repository);
    service.trust_collection_repository = Arc::new(trust_collection_repository);
    service.credential_schema_repository = Arc::new(credential_schema_repository);

    let error = service
        .get_wallet_provider_metadata("PROCIVIS_ONE".to_string())
        .await
        .unwrap_err();

    assert_eq!(error.error_code(), ErrorCode::BR_0089);
}
