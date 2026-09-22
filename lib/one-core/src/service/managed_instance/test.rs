use std::ops::{Add, Sub};
use std::sync::Arc;

use async_trait::async_trait;
use mockall::predicate::eq;
use one_crypto::Signer;
use one_crypto::signer::ecdsa::ECDSASigner;
use secrecy::SecretSlice;
use serde_json::json;
use shared_types::IdentifierId;
use similar_asserts::assert_eq;
use time::Duration;
use uuid::Uuid;

use super::ManagedInstanceService;
use super::dto::{ManagedInstanceFilterParamsDTO, RegisterWalletUnitRequestDTO};
use crate::config;
use crate::config::core_config::{CoreConfig, Fields, KeyAlgorithmType, Params};
use crate::error::{ErrorCode, ErrorCodeMixin};
use crate::model::instance::{InstanceRole, InstanceStatus};
use crate::model::managed_instance::{ManagedInstance, ManagedInstanceOs};
use crate::model::organisation::Organisation;
use crate::proto::certificate_validator::MockCertificateValidator;
use crate::proto::http_client::{
    Method, MockHttpClient, Request, RequestBuilder, Response, StatusCode,
};
use crate::proto::jwt::Jwt;
use crate::proto::jwt::model::{JWTHeader, JWTPayload};
use crate::proto::session_provider::NoSessionProvider;
use crate::proto::session_provider::test::StaticSessionProvider;
use crate::proto::transaction_manager::NoTransactionManager;
use crate::provider::credential_formatter::common::SignatureProvider;
use crate::provider::key_algorithm::KeyAlgorithm;
use crate::provider::key_algorithm::ecdsa::Ecdsa;
use crate::provider::key_algorithm::error::KeyAlgorithmError;
use crate::provider::key_algorithm::key::KeyHandle;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::revocation::provider::MockRevocationMethodProvider;
use crate::provider::signer::provider::MockSignerProvider;
use crate::provider::verifier::MockVerifierProvider;
use crate::provider::verifier::provider::MockVerifierProviderDirectory;
use crate::provider::wallet::MockWalletProvider;
use crate::provider::wallet::provider::MockWalletProviderDirectory;
use crate::repository::history_repository::MockHistoryRepository;
use crate::repository::managed_instance_repository::MockManagedInstanceRepository;
use crate::repository::organisation_repository::MockOrganisationRepository;
use crate::service::common_dto::ListQueryDTO;
use crate::service::managed_instance::dto::{IntegrityCheck, ProviderRegistrationParams};
use crate::service::test_utilities::{dummy_organisation, generic_config, get_dummy_date};

const BASE_URL: &str = "https://localhost";

fn mock_wallet_provider_service() -> ManagedInstanceService {
    ManagedInstanceService {
        organisation_repository: Arc::new(MockOrganisationRepository::default()),
        managed_instance_repository: Arc::new(MockManagedInstanceRepository::default()),
        history_repository: Arc::new(MockHistoryRepository::default()),
        tx_manager: Arc::new(NoTransactionManager),
        key_algorithm_provider: Arc::new(MockKeyAlgorithmProvider::default()),
        revocation_method_provider: Arc::new(MockRevocationMethodProvider::default()),
        signer_provider: Arc::new(MockSignerProvider::default()),
        certificate_validator: Arc::new(MockCertificateValidator::default()),
        http_client: Arc::new(MockHttpClient::default()),
        base_url: Some(BASE_URL.to_string()),
        config: Arc::new(CoreConfig::default()),
        session_provider: Arc::new(NoSessionProvider),
        verifier_provider_directory: Arc::new(MockVerifierProviderDirectory::default()),
        wallet_provider_directory: Arc::new(MockWalletProviderDirectory::default()),
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
                "walletCertification": "https://procivis.ch",
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
                "walletKeyAttestation": {
                    "expirationSeconds": 60
                },
                "signerIdentifierTypes": ["CERTIFICATE"],
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

    let mut managed_instance_repository = MockManagedInstanceRepository::new();
    managed_instance_repository
        .expect_create()
        .return_once(|wu| Ok(wu.id));

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .return_once(|_| Ok(Uuid::new_v4().into()));

    let mut wallet_provider_directory = MockWalletProviderDirectory::new();
    wallet_provider_directory
        .expect_get_provider()
        .with(eq(procivis_one_provider))
        .return_once(|_| {
            let mut wallet_provider = MockWalletProvider::new();
            wallet_provider
                .expect_get_registration_params()
                .return_once(|| {
                    Ok(ProviderRegistrationParams {
                        name_label: procivis_one_provider.to_string(),
                        integrity_check: IntegrityCheck {
                            enabled: false,
                            ..Default::default()
                        },
                        device_auth_leeway: Default::default(),
                        user_authentication: None,
                    })
                });

            Ok(Arc::new(wallet_provider))
        });

    let ssi_wallet_provider_service = ManagedInstanceService {
        organisation_repository: Arc::new(organisation_repository),
        key_algorithm_provider: Arc::new(key_algorithm_provider),
        managed_instance_repository: Arc::new(managed_instance_repository),
        history_repository: Arc::new(history_repository),
        wallet_provider_directory: Arc::new(wallet_provider_directory),
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

    let mut managed_instance_repository = MockManagedInstanceRepository::new();
    managed_instance_repository
        .expect_create()
        .return_once(|wu| Ok(wu.id));

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .return_once(|_| Ok(Uuid::new_v4().into()));

    let mut wallet_provider_directory = MockWalletProviderDirectory::new();
    wallet_provider_directory
        .expect_get_provider()
        .with(eq(procivis_one_provider))
        .return_once(|_| {
            let mut wallet_provider = MockWalletProvider::new();
            wallet_provider
                .expect_get_registration_params()
                .return_once(|| {
                    Ok(ProviderRegistrationParams {
                        name_label: procivis_one_provider.to_string(),
                        integrity_check: IntegrityCheck {
                            enabled: true,
                            ..Default::default()
                        },
                        device_auth_leeway: Default::default(),
                        user_authentication: None,
                    })
                });

            Ok(Arc::new(wallet_provider))
        });

    let ssi_wallet_provider_service = ManagedInstanceService {
        organisation_repository: Arc::new(organisation_repository),
        managed_instance_repository: Arc::new(managed_instance_repository),
        history_repository: Arc::new(history_repository),
        wallet_provider_directory: Arc::new(wallet_provider_directory),
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

    let mut verifier_provider_directory = MockVerifierProviderDirectory::new();
    verifier_provider_directory
        .expect_get_provider()
        .with(eq(verifier_provider_name))
        .return_once(|_| {
            let mut verifier_provider = MockVerifierProvider::new();
            verifier_provider
                .expect_get_registration_params()
                .return_once(|| {
                    Ok(ProviderRegistrationParams {
                        name_label: verifier_provider_name.to_string(),
                        integrity_check: IntegrityCheck {
                            enabled: false,
                            ..Default::default()
                        },
                        device_auth_leeway: Default::default(),
                        user_authentication: None,
                    })
                });

            Ok(Arc::new(verifier_provider))
        });

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_jose_alg()
        .once()
        .return_once(|_| Some((KeyAlgorithmType::Ecdsa, Arc::new(Ecdsa))));

    let mut managed_instance_repository = MockManagedInstanceRepository::new();
    managed_instance_repository
        .expect_create()
        .return_once(|wu| Ok(wu.id));

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .return_once(|_| Ok(Uuid::new_v4().into()));

    let service = ManagedInstanceService {
        organisation_repository: Arc::new(organisation_repository),
        key_algorithm_provider: Arc::new(key_algorithm_provider),
        managed_instance_repository: Arc::new(managed_instance_repository),
        history_repository: Arc::new(history_repository),
        verifier_provider_directory: Arc::new(verifier_provider_directory),
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
        attestations: Default::default(),
        version: None,
    };
    let mut managed_instance_repository = MockManagedInstanceRepository::new();
    managed_instance_repository
        .expect_get()
        .returning(move |_| Ok(wallet_unit.clone()));

    // given
    let service = ManagedInstanceService {
        managed_instance_repository: Arc::new(managed_instance_repository),
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
