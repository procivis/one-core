use std::str::FromStr;
use std::sync::{Arc, Mutex};

use assert2::let_assert;
use mockall::predicate::{always, eq};
use one_crypto::encryption::encrypt_data;
use secrecy::SecretSlice;
use serde_json::{Value, json};
use shared_types::CredentialFormat;
use similar_asserts::assert_eq;
use standardized_types::jwk::{PublicJwk, PublicJwkEc};
use time::{Duration, OffsetDateTime};
use url::Url;
use uuid::Uuid;
use wiremock::http::Method;
use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::config::core_config::{
    CoreConfig, Fields, FormatType, KeyAlgorithmType, KeySecurityLevelType,
};
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{Credential, CredentialRole, CredentialStateEnum};
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaClaim, KeyStorageSecurity, LayoutType,
};
use crate::model::did::{Did, DidType, KeyRole, RelatedKey};
use crate::model::identifier::{Identifier, IdentifierState, IdentifierType};
use crate::model::interaction::{Interaction, InteractionType};
use crate::model::key::Key;
use crate::proto::credential_schema::importer::MockCredentialSchemaImporter;
use crate::proto::http_client::reqwest_client::ReqwestClient;
use crate::proto::identifier_creator::{
    CreateLocalIdentifierRequest, IdentifierRole, MockIdentifierCreator, RemoteIdentifierRelation,
};
use crate::proto::wallet_unit::MockHolderWalletUnitProto;
use crate::provider::blob_storage_provider::MockBlobStorageProvider;
use crate::provider::caching_loader::openid_metadata::MockOpenIDMetadataFetcher;
use crate::provider::credential_formatter::MockCredentialFormatter;
use crate::provider::credential_formatter::model::{IdentifierDetails, MockSignatureProvider};
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::did_method::{DidCreated, MockDidMethod};
use crate::provider::issuance_protocol::dto::ContinueIssuanceDTO;
use crate::provider::issuance_protocol::model::{
    InvitationResponseEnum, OpenID4VCRedirectUriParams,
};
use crate::provider::issuance_protocol::openid4vci_final1_0::OpenID4VCIFinal1_0;
use crate::provider::issuance_protocol::openid4vci_final1_0::model::{
    HolderInteractionData, OpenID4VCIFinal1Params, OpenID4VCIGrants,
    OpenID4VCIPreAuthorizedCodeGrant,
};
use crate::provider::issuance_protocol::openid4vci_final1_0::service::create_credential_offer;
use crate::provider::issuance_protocol::{HolderBindingInput, IssuanceProtocol};
use crate::provider::key_algorithm::ecdsa::Ecdsa;
use crate::provider::key_algorithm::key::{
    KeyHandle, MockSignaturePrivateKeyHandle, MockSignaturePublicKeyHandle, SignatureKeyHandle,
};
use crate::provider::key_algorithm::model::GeneratedKey;
use crate::provider::key_algorithm::provider::{MockKeyAlgorithmProvider, ParsedKey};
use crate::provider::key_algorithm::{KeyAlgorithm, MockKeyAlgorithm};
use crate::provider::key_security_level::MockKeySecurityLevel;
use crate::provider::key_security_level::provider::MockKeySecurityLevelProvider;
use crate::provider::key_storage::MockKeyStorage;
use crate::provider::key_storage::model::{KeyStorageCapabilities, StorageGeneratedKey};
use crate::provider::key_storage::provider::MockKeyProvider;
use crate::provider::revocation::provider::MockRevocationMethodProvider;
use crate::repository::credential_repository::MockCredentialRepository;
use crate::repository::key_repository::MockKeyRepository;
use crate::repository::validity_credential_repository::MockValidityCredentialRepository;
use crate::service::storage_proxy::MockStorageProxy;
use crate::service::test_utilities::{
    dummy_did, dummy_identifier, dummy_key, dummy_organisation, get_dummy_date,
};

#[derive(Default)]
struct TestInputs {
    pub credential_repository: MockCredentialRepository,
    pub key_repository: MockKeyRepository,
    pub identifier_creator: MockIdentifierCreator,
    pub metadata_cache: MockOpenIDMetadataFetcher,
    pub validity_credential_repository: MockValidityCredentialRepository,
    pub formatter_provider: MockCredentialFormatterProvider,
    pub revocation_provider: MockRevocationMethodProvider,
    pub key_algorithm_provider: MockKeyAlgorithmProvider,
    pub key_provider: MockKeyProvider,
    pub did_method_provider: MockDidMethodProvider,
    pub blob_storage_provider: MockBlobStorageProvider,
    pub key_security_level_provider: MockKeySecurityLevelProvider,
    pub config: CoreConfig,
    pub params: Option<OpenID4VCIFinal1Params>,
}

fn setup_protocol(inputs: TestInputs) -> OpenID4VCIFinal1_0 {
    OpenID4VCIFinal1_0::new(
        Arc::new(ReqwestClient::default()),
        Arc::new(inputs.metadata_cache),
        Arc::new(inputs.credential_repository),
        Arc::new(inputs.key_repository),
        Arc::new(inputs.identifier_creator),
        Arc::new(MockCredentialSchemaImporter::new()),
        Arc::new(inputs.validity_credential_repository),
        Arc::new(inputs.formatter_provider),
        Arc::new(inputs.revocation_provider),
        Arc::new(inputs.did_method_provider),
        Arc::new(inputs.key_algorithm_provider),
        Arc::new(inputs.key_provider),
        Arc::new(inputs.key_security_level_provider),
        Arc::new(inputs.blob_storage_provider),
        Some("http://base_url".to_string()),
        Arc::new(inputs.config),
        inputs.params.unwrap_or(OpenID4VCIFinal1Params {
            pre_authorized_code_expires_in: Duration::seconds(10),
            token_expires_in: Duration::seconds(10),
            credential_offer_by_value: false,
            refresh_expires_in: Duration::seconds(1000),
            encryption: SecretSlice::from(vec![0; 32]),
            url_scheme: "openid-credential-offer".to_string(),
            redirect_uri: OpenID4VCRedirectUriParams {
                enabled: true,
                allowed_schemes: vec!["https".to_string()],
            },
            nonce: None,
            oauth_attestation_leeway: 60,
            key_attestation_leeway: 60,
        }),
        "OPENID4VCI_FINAL1".to_string(),
        Arc::new(MockHolderWalletUnitProto::new()),
    )
}

fn generic_credential_did() -> Credential {
    let now = OffsetDateTime::now_utc();
    let issuer_did = Did {
        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
            .unwrap()
            .into(),
        created_date: now,
        last_modified: now,
        name: "did1".to_string(),
        did: "did:example:123".parse().unwrap(),
        did_type: DidType::Remote,
        did_method: "KEY".to_string(),
        keys: None,
        deactivated: false,
        organisation: Some(dummy_organisation(None)),
        log: None,
    };
    let issuer_identifier = Identifier {
        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
            .unwrap()
            .into(),
        created_date: now,
        last_modified: now,
        name: "did1".to_string(),
        r#type: IdentifierType::Did,
        is_remote: true,
        state: IdentifierState::Active,
        deleted_at: None,
        organisation: None,
        did: Some(issuer_did),
        key: None,
        certificates: None,
    };
    generic_credential(issuer_identifier)
}

fn generic_credential_key() -> Credential {
    let now = OffsetDateTime::now_utc();
    let issuer_key = Key {
        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
            .unwrap()
            .into(),
        created_date: now,
        last_modified: now,
        public_key: vec![
            3, 74, 21, 88, 157, 81, 251, 128, 145, 27, 187, 39, 111, 10, 236, 74, 221, 234, 194,
            44, 131, 73, 67, 110, 216, 155, 241, 212, 248, 141, 174, 74, 68,
        ],
        name: "key1".to_string(),
        key_reference: None,
        storage_type: "LOCAL".to_string(),
        organisation: Some(dummy_organisation(None)),
        key_type: "ECDSA".to_string(),
    };
    let issuer_identifier = Identifier {
        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
            .unwrap()
            .into(),
        created_date: now,
        last_modified: now,
        name: "key1".to_string(),
        r#type: IdentifierType::Key,
        is_remote: true,
        state: IdentifierState::Active,
        deleted_at: None,
        organisation: None,
        did: None,
        key: Some(issuer_key),
        certificates: None,
    };
    generic_credential(issuer_identifier)
}

fn generic_credential(issuer_identifier: Identifier) -> Credential {
    let now = OffsetDateTime::now_utc();

    let claim_schema = ClaimSchema {
        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
            .unwrap()
            .into(),
        key: "NUMBER".to_string(),
        data_type: "NUMBER".to_string(),
        created_date: now,
        last_modified: now,
        array: false,
        metadata: false,
    };

    let credential_id = Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
        .unwrap()
        .into();

    Credential {
        id: credential_id,
        created_date: now,
        issuance_date: None,
        last_modified: now,
        deleted_at: None,
        protocol: "OPENID4VCI_FINAL1".to_string(),
        redirect_uri: None,
        role: CredentialRole::Issuer,
        state: CredentialStateEnum::Created,
        suspend_end_date: None,
        claims: Some(vec![Claim {
            id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
                .unwrap()
                .into(),
            credential_id,
            created_date: now,
            last_modified: now,
            value: Some("123".to_string()),
            path: claim_schema.key.to_owned(),
            selectively_disclosable: false,
            schema: Some(claim_schema.clone()),
        }]),
        issuer_certificate: issuer_identifier
            .certificates
            .as_ref()
            .and_then(|certs| certs.first().cloned()),
        issuer_identifier: Some(issuer_identifier),
        holder_identifier: None,
        schema: Some(CredentialSchema {
            id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
                .unwrap()
                .into(),
            deleted_at: None,
            imported_source_url: "CORE_URL".to_string(),
            created_date: now,
            key_storage_security: Some(KeyStorageSecurity::Basic),
            last_modified: now,
            name: "schema".to_string(),
            format: "JWT".into(),
            revocation_method: "NONE".into(),
            claim_schemas: Some(vec![CredentialSchemaClaim {
                schema: claim_schema,
                required: true,
            }]),
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_id: "CredentialSchemaId".to_owned(),
            organisation: Some(dummy_organisation(None)),
            allow_suspension: true,
            requires_app_attestation: false,
        }),
        interaction: Some(Interaction {
            id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
                .unwrap()
                .into(),
            created_date: now,
            data: Some(vec![1, 2, 3]),
            last_modified: now,
            organisation: None,
            nonce_id: None,
            interaction_type: InteractionType::Issuance,
            expires_at: None,
        }),
        key: None,
        profile: None,
        credential_blob_id: None,
        wallet_unit_attestation_blob_id: None,
        wallet_app_attestation_blob_id: None,
    }
}

fn dummy_config() -> CoreConfig {
    let mut config = CoreConfig::default();

    config.format.insert(
        "JWT".into(),
        Fields {
            r#type: FormatType::Jwt,
            display: "display".into(),
            order: None,
            priority: None,
            enabled: true,
            capabilities: None,
            params: None,
        },
    );

    config
}

#[tokio::test]
async fn test_generate_offer() {
    let protocol_base_url = "BASE_URL/ssi/openid4vci/final-1.0".to_string();
    let interaction_id = Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965").unwrap();
    let credential = generic_credential_did();

    let offer = create_credential_offer(
        &protocol_base_url,
        &credential.protocol,
        &interaction_id.to_string(),
        &credential.schema.as_ref().unwrap().id,
        &credential.schema.as_ref().unwrap().schema_id,
    )
    .unwrap();

    assert_eq!(
        json!(&offer),
        json!({
            "credential_issuer": format!("BASE_URL/ssi/openid4vci/final-1.0/{}/c322aa7f-9803-410d-b891-939b279fb965", credential.protocol),
            "credential_configuration_ids" : [
                credential.schema.as_ref().unwrap().schema_id,
            ],
            "grants": {
                "urn:ietf:params:oauth:grant-type:pre-authorized_code": { "pre-authorized_code": "c322aa7f-9803-410d-b891-939b279fb965" }
            }
        })
    )
}

#[tokio::test]
async fn test_generate_share_credentials() {
    let credential = generic_credential_did();
    let protocol = setup_protocol(Default::default());

    let result = protocol.issuer_share_credential(&credential).await.unwrap();
    assert_eq!(
        result.url,
        "openid-credential-offer://?credential_offer_uri=http%3A%2F%2Fbase_url%2Fssi%2Fopenid4vci%2Ffinal-1.0%2Fc322aa7f-9803-410d-b891-939b279fb965%2Foffer%2Fc322aa7f-9803-410d-b891-939b279fb965"
    );
}

#[tokio::test]
async fn test_generate_share_credentials_offer_by_value() {
    let credential = generic_credential_did();

    let protocol = setup_protocol(TestInputs {
        params: Some(OpenID4VCIFinal1Params {
            pre_authorized_code_expires_in: Duration::seconds(10),
            token_expires_in: Duration::seconds(10),
            credential_offer_by_value: true,
            refresh_expires_in: Duration::seconds(1000),
            encryption: SecretSlice::from(vec![0; 32]),
            url_scheme: "openid-credential-offer".to_string(),
            redirect_uri: OpenID4VCRedirectUriParams {
                enabled: true,
                allowed_schemes: vec!["https".to_string()],
            },
            nonce: None,
            oauth_attestation_leeway: 60,
            key_attestation_leeway: 60,
        }),
        ..Default::default()
    });

    let result = protocol.issuer_share_credential(&credential).await.unwrap();
    // Everything except for interaction id is here.
    // Generating token with predictable interaction id is tested somewhere else.
    assert!(
        result.url.starts_with(r#"openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22http%3A%2F%2Fbase_url%2Fssi%2Fopenid4vci%2Ffinal-1.0%2FOPENID4VCI_FINAL1%2Fc322aa7f-9803-410d-b891-939b279fb965%22%2C%22credential_configuration_ids%22%3A%5B%22CredentialSchemaId%22%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%"#)
    );
}

#[tokio::test]
async fn test_holder_accept_credential_success() {
    let mock_server = MockServer::start().await;
    let mut formatter_provider = MockCredentialFormatterProvider::default();
    let mut storage_access = MockStorageProxy::default();
    let mut key_provider = MockKeyProvider::default();

    let credential = generic_credential_did();

    let interaction_data = HolderInteractionData {
        issuer_url: mock_server.uri(),
        credential_endpoint: format!("{}/credential", mock_server.uri()),
        token_endpoint: Some(format!("{}/token", mock_server.uri())),
        nonce_endpoint: Some(format!("{}/nonce", mock_server.uri())),
        notification_endpoint: Some(format!("{}/notification", mock_server.uri())),
        challenge_endpoint: None,
        grants: Some(OpenID4VCIGrants::PreAuthorizedCode(
            OpenID4VCIPreAuthorizedCodeGrant {
                pre_authorized_code: "code".to_string(),
                tx_code: None,
                authorization_server: None,
            },
        )),
        access_token: None,
        access_token_expires_at: None,
        refresh_token: None,
        token_endpoint_auth_methods_supported: None,
        refresh_token_expires_at: None,
        cryptographic_binding_methods_supported: None,
        credential_signing_alg_values_supported: None,
        proof_types_supported: None,
        continue_issuance: None,
        credential_configuration_id: credential.schema.as_ref().unwrap().schema_id.to_owned(),
        credential_metadata: None,
        notification_id: None,
        protocol: "OPENID4VCI_FINAL1".to_string(),
        format: "jwt_vc_json".to_string(),
    };

    let interaction = Interaction {
        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
            .unwrap()
            .into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        data: Some(serde_json::to_vec(&interaction_data).unwrap()),
        organisation: credential.schema.as_ref().unwrap().organisation.to_owned(),
        nonce_id: None,
        interaction_type: InteractionType::Issuance,
        expires_at: None,
    };

    Mock::given(method(Method::POST))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "access_token": "321",
                "token_type": "bearer",
                "expires_in": OffsetDateTime::now_utc().unix_timestamp() + 3600,
                "refresh_token": "321",
                "refresh_token_expires_in": OffsetDateTime::now_utc().unix_timestamp() + 3600,
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/nonce"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "c_nonce": "123"
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/credential"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "credentials": [{"credential": "credential"}],
                "notification_id": "notification_id"
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/notification"))
        .and(body_json(json!({
            "notification_id": "notification_id",
            "event": "credential_accepted"
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut formatter = MockCredentialFormatter::new();
    formatter.expect_get_leeway().returning(|| 1000);
    formatter.expect_parse_credential().returning({
        let clone = credential.clone();
        move |_| Ok(clone.clone())
    });

    let formatter = Arc::new(formatter);
    let formatter_clone = formatter.clone();
    formatter_provider
        .expect_get_credential_formatter()
        .with(eq(CredentialFormat::from("JWT")))
        .returning(move |_| Some(formatter_clone.clone()));
    formatter_provider
        .expect_get_formatter_by_type()
        .returning(move |_| Some(("JWT".into(), formatter.clone())));

    let schema = credential.schema.as_ref().unwrap().to_owned();
    storage_access
        .expect_get_schema()
        .once()
        .returning(move |_, _| Ok(Some(schema.clone())));

    storage_access
        .expect_update_interaction()
        .once()
        .returning(move |_, _| Ok(()));

    key_provider
        .expect_get_signature_provider()
        .returning(move |_, _, _| {
            let mut mock_signature_provider = MockSignatureProvider::new();
            mock_signature_provider
                .expect_jose_alg()
                .returning(|| Some("EdDSA".to_string()));

            mock_signature_provider
                .expect_get_key_id()
                .returning(|| Some("key-id".to_string()));

            mock_signature_provider
                .expect_sign()
                .returning(|_| Ok(vec![0; 32]));

            Ok(Box::new(mock_signature_provider))
        });

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_reconstruct_key()
        .returning(|_, _, _, _| {
            let mut key_handle = MockSignaturePublicKeyHandle::default();
            key_handle.expect_as_jwk().return_once(|| {
                Ok(PublicJwk::Ec(PublicJwkEc {
                    alg: None,
                    r#use: None,
                    kid: None,
                    crv: "P-256".to_string(),
                    x: "igrFmi0whuihKnj9R3Om1SoMph72wUGeFaBbzG2vzns".to_owned(),
                    y: Some("efsX5b10x8yjyrj4ny3pGfLcY7Xby1KzgqOdqnsrJIM".to_owned()),
                }))
            });

            Ok(KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(
                Arc::new(key_handle),
            )))
        });

    let identifier = dummy_identifier();
    let mut identifier_creator = MockIdentifierCreator::new();
    identifier_creator
        .expect_get_or_create_remote_identifier()
        .once()
        .with(always(), always(), eq(IdentifierRole::Issuer))
        .return_once({
            let identifier = identifier.clone();
            move |_, _, _| Ok((identifier, RemoteIdentifierRelation::Key(dummy_key())))
        });

    let openid_provider = setup_protocol(TestInputs {
        formatter_provider,
        key_provider,
        key_algorithm_provider,
        identifier_creator,
        config: dummy_config(),
        ..Default::default()
    });

    let key = dummy_key();
    let result = openid_provider
        .holder_accept_credential(
            interaction,
            Some(HolderBindingInput {
                identifier: Identifier {
                    r#type: IdentifierType::Key,
                    key: Some(key.clone()),
                    ..dummy_identifier()
                },
                key,
            }),
            &storage_access,
            None,
            None,
        )
        .await
        .unwrap();

    let issuer_response = result.result;
    assert_eq!(issuer_response.credential, "credential");
    assert_eq!(issuer_response.notification_id.unwrap(), "notification_id");

    let create_credential = result.create_credential.unwrap();
    assert_eq!(create_credential.id, credential.id);
    assert_eq!(
        create_credential.issuer_identifier.unwrap().id,
        identifier.id
    );
}

#[tokio::test]
async fn test_holder_accept_credential_none_existing_issuer_key_id_success() {
    let mock_server = MockServer::start().await;
    let mut formatter_provider = MockCredentialFormatterProvider::default();
    let mut storage_access = MockStorageProxy::default();
    let mut key_provider = MockKeyProvider::default();

    let credential = generic_credential_key();

    let interaction_data = HolderInteractionData {
        issuer_url: mock_server.uri(),
        credential_endpoint: format!("{}/credential", mock_server.uri()),
        token_endpoint: Some(format!("{}/token", mock_server.uri())),
        nonce_endpoint: Some(format!("{}/nonce", mock_server.uri())),
        notification_endpoint: None,
        challenge_endpoint: None,
        grants: Some(OpenID4VCIGrants::PreAuthorizedCode(
            OpenID4VCIPreAuthorizedCodeGrant {
                pre_authorized_code: "code".to_string(),
                tx_code: None,
                authorization_server: None,
            },
        )),
        access_token: None,
        access_token_expires_at: None,
        token_endpoint_auth_methods_supported: None,
        refresh_token: None,
        refresh_token_expires_at: None,
        cryptographic_binding_methods_supported: None,
        credential_signing_alg_values_supported: None,
        proof_types_supported: None,
        continue_issuance: None,
        credential_configuration_id: credential.schema.as_ref().unwrap().schema_id.to_owned(),
        credential_metadata: None,
        notification_id: None,
        protocol: "OPENID4VCI_FINAL1".to_string(),
        format: "jwt_vc_json".to_string(),
    };

    let interaction = Interaction {
        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
            .unwrap()
            .into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        data: Some(serde_json::to_vec(&interaction_data).unwrap()),
        organisation: credential.schema.as_ref().unwrap().organisation.to_owned(),
        nonce_id: None,
        interaction_type: InteractionType::Issuance,
        expires_at: None,
    };

    Mock::given(method(Method::POST))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "access_token": "321",
                "token_type": "bearer",
                "expires_in": OffsetDateTime::now_utc().unix_timestamp() + 3600,
                "refresh_token": "321",
                "refresh_token_expires_in": OffsetDateTime::now_utc().unix_timestamp() + 3600,
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/nonce"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "c_nonce": "123"
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/credential"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "credentials": [{"credential": "credential"}],
                "notification_id": "notification_id"
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut formatter = MockCredentialFormatter::new();
    formatter.expect_get_leeway().returning(|| 1000);
    formatter.expect_parse_credential().returning({
        let clone = credential.clone();
        move |_| Ok(clone.clone())
    });
    let formatter = Arc::new(formatter);
    let formatter_clone = formatter.clone();
    formatter_provider
        .expect_get_credential_formatter()
        .with(eq(CredentialFormat::from("JWT")))
        .returning(move |_| Some(formatter_clone.clone()));
    formatter_provider
        .expect_get_formatter_by_type()
        .returning(move |_| Some(("JWT".into(), formatter.clone())));

    let schema = credential.schema.as_ref().unwrap().to_owned();
    storage_access
        .expect_get_schema()
        .once()
        .returning(move |_, _| Ok(Some(schema.clone())));

    storage_access
        .expect_update_interaction()
        .once()
        .returning(move |_, _| Ok(()));

    key_provider
        .expect_get_signature_provider()
        .returning(move |_, _, _| {
            let mut mock_signature_provider = MockSignatureProvider::new();
            mock_signature_provider
                .expect_jose_alg()
                .returning(|| Some("EdDSA".to_string()));

            mock_signature_provider
                .expect_get_key_id()
                .returning(|| Some("key-id".to_string()));

            mock_signature_provider
                .expect_sign()
                .returning(|_| Ok(vec![0; 32]));

            Ok(Box::new(mock_signature_provider))
        });

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider.expect_parse_jwk().returning(|k| {
        let key = Ecdsa.parse_jwk(k).unwrap();
        Ok(ParsedKey {
            key,
            algorithm_type: KeyAlgorithmType::Ecdsa,
        })
    });

    let jwk = PublicJwk::Ec(PublicJwkEc {
        alg: None,
        r#use: None,
        kid: None,
        crv: "P-256".to_string(),
        x: "igrFmi0whuihKnj9R3Om1SoMph72wUGeFaBbzG2vzns".to_owned(),
        y: Some("efsX5b10x8yjyrj4ny3pGfLcY7Xby1KzgqOdqnsrJIM".to_owned()),
    });
    key_algorithm_provider.expect_reconstruct_key().returning({
        let jwk = jwk.clone();
        move |_, _, _, _| {
            let jwk = jwk.clone();
            let mut key_handle = MockSignaturePublicKeyHandle::default();
            key_handle.expect_as_jwk().return_once(|| Ok(jwk));

            Ok(KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(
                Arc::new(key_handle),
            )))
        }
    });

    let mut identifier_creator = MockIdentifierCreator::new();
    identifier_creator
        .expect_get_or_create_remote_identifier()
        .once()
        .with(
            always(),
            eq(IdentifierDetails::Key(jwk)),
            eq(IdentifierRole::Issuer),
        )
        .returning(|_, _, _| {
            Ok((
                dummy_identifier(),
                RemoteIdentifierRelation::Key(dummy_key()),
            ))
        });

    let openid_provider = setup_protocol(TestInputs {
        formatter_provider,
        key_provider,
        key_algorithm_provider,
        identifier_creator,
        config: dummy_config(),
        ..Default::default()
    });

    let key = Key {
        id: Uuid::new_v4().into(),
        ..dummy_key()
    };
    let result = openid_provider
        .holder_accept_credential(
            interaction,
            Some(HolderBindingInput {
                identifier: Identifier {
                    r#type: IdentifierType::Did,
                    did: Some(Did {
                        keys: Some(vec![RelatedKey {
                            role: KeyRole::Authentication,
                            key: key.to_owned(),
                            reference: "ref".to_string(),
                        }]),
                        ..dummy_did()
                    }),
                    ..dummy_identifier()
                },
                key,
            }),
            &storage_access,
            None,
            None,
        )
        .await
        .unwrap();

    let issuer_response = result.result;
    assert_eq!(issuer_response.credential, "credential");
    assert_eq!(issuer_response.notification_id.unwrap(), "notification_id");

    let create_credential = result.create_credential.unwrap();
    assert_eq!(create_credential.id, credential.id);
}

#[tokio::test]
async fn test_holder_accept_credential_autogenerate_holder_binding() {
    let mock_server = MockServer::start().await;
    let mut formatter_provider = MockCredentialFormatterProvider::default();
    let mut storage_access = MockStorageProxy::default();
    let mut key_provider = MockKeyProvider::default();

    let credential = generic_credential_did();

    let interaction_data = HolderInteractionData {
        issuer_url: mock_server.uri(),
        credential_endpoint: format!("{}/credential", mock_server.uri()),
        token_endpoint: Some(format!("{}/token", mock_server.uri())),
        nonce_endpoint: Some(format!("{}/nonce", mock_server.uri())),
        notification_endpoint: Some(format!("{}/notification", mock_server.uri())),
        challenge_endpoint: None,
        grants: Some(OpenID4VCIGrants::PreAuthorizedCode(
            OpenID4VCIPreAuthorizedCodeGrant {
                pre_authorized_code: "code".to_string(),
                tx_code: None,
                authorization_server: None,
            },
        )),
        access_token: None,
        access_token_expires_at: None,
        refresh_token: None,
        token_endpoint_auth_methods_supported: None,
        refresh_token_expires_at: None,
        cryptographic_binding_methods_supported: None,
        credential_signing_alg_values_supported: None,
        proof_types_supported: None,
        continue_issuance: None,
        credential_configuration_id: credential.schema.as_ref().unwrap().schema_id.to_owned(),
        credential_metadata: None,
        notification_id: None,
        protocol: "OPENID4VCI_FINAL1".to_string(),
        format: "jwt_vc_json".to_string(),
    };

    let interaction = Interaction {
        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
            .unwrap()
            .into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        data: Some(serde_json::to_vec(&interaction_data).unwrap()),
        organisation: credential.schema.as_ref().unwrap().organisation.to_owned(),
        nonce_id: None,
        interaction_type: InteractionType::Issuance,
        expires_at: None,
    };

    Mock::given(method(Method::POST))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "access_token": "321",
                "token_type": "bearer",
                "expires_in": OffsetDateTime::now_utc().unix_timestamp() + 3600,
                "refresh_token": "321",
                "refresh_token_expires_in": OffsetDateTime::now_utc().unix_timestamp() + 3600,
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/nonce"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "c_nonce": "123"
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/credential"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "credentials": [{"credential": "credential"}],
                "notification_id": "notification_id"
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/notification"))
        .and(body_json(json!({
            "notification_id": "notification_id",
            "event": "credential_accepted"
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut formatter = MockCredentialFormatter::new();
    formatter.expect_get_leeway().returning(|| 1000);
    formatter.expect_parse_credential().returning({
        let clone = credential.clone();
        move |_| Ok(clone.clone())
    });

    let formatter = Arc::new(formatter);
    let formatter_clone = formatter.clone();
    formatter_provider
        .expect_get_credential_formatter()
        .with(eq(CredentialFormat::from("JWT")))
        .returning(move |_| Some(formatter_clone.clone()));
    formatter_provider
        .expect_get_formatter_by_type()
        .returning(move |_| Some(("JWT".into(), formatter.clone())));

    let schema = credential.schema.as_ref().unwrap().to_owned();
    storage_access
        .expect_get_schema()
        .once()
        .returning(move |_, _| Ok(Some(schema.clone())));

    storage_access
        .expect_update_interaction()
        .once()
        .returning(move |_, _| Ok(()));

    key_provider
        .expect_get_signature_provider()
        .returning(move |_, _, _| {
            let mut mock_signature_provider = MockSignatureProvider::new();
            mock_signature_provider
                .expect_jose_alg()
                .returning(|| Some("EdDSA".to_string()));

            mock_signature_provider
                .expect_get_key_id()
                .returning(|| Some("key-id".to_string()));

            mock_signature_provider
                .expect_sign()
                .returning(|_| Ok(vec![0; 32]));

            Ok(Box::new(mock_signature_provider))
        });
    key_provider.expect_get_key_storage().returning(move |_| {
        let mut storage = MockKeyStorage::new();
        storage
            .expect_get_capabilities()
            .returning(|| KeyStorageCapabilities {
                features: vec![],
                algorithms: vec![KeyAlgorithmType::Ecdsa],
            });

        storage.expect_generate().returning(|_, _| {
            Ok(StorageGeneratedKey {
                public_key: vec![],
                key_reference: Some(vec![]),
            })
        });

        Some(Arc::new(storage))
    });

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_reconstruct_key()
        .returning(|_, _, _, _| {
            let mut key_handle = MockSignaturePublicKeyHandle::default();
            key_handle.expect_as_jwk().return_once(|| {
                Ok(PublicJwk::Ec(PublicJwkEc {
                    alg: None,
                    r#use: None,
                    kid: None,
                    crv: "P-256".to_string(),
                    x: "igrFmi0whuihKnj9R3Om1SoMph72wUGeFaBbzG2vzns".to_owned(),
                    y: Some("efsX5b10x8yjyrj4ny3pGfLcY7Xby1KzgqOdqnsrJIM".to_owned()),
                }))
            });

            Ok(KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(
                Arc::new(key_handle),
            )))
        });
    key_algorithm_provider
        .expect_ordered_by_holder_priority()
        .returning(|| vec![(KeyAlgorithmType::Ecdsa, Arc::new(MockKeyAlgorithm::new()))]);

    let mut key_security_level_provider = MockKeySecurityLevelProvider::new();
    key_security_level_provider
        .expect_ordered_by_priority()
        .once()
        .returning(|| {
            let mut security = MockKeySecurityLevel::new();
            security
                .expect_get_key_storages()
                .return_const(vec!["INTERNAL".to_string()]);
            vec![(KeySecurityLevelType::Basic, Arc::new(security))]
        });

    let mut key_repository = MockKeyRepository::new();
    key_repository
        .expect_create_key()
        .once()
        .returning(|key| Ok(key.id));

    let mut identifier_creator = MockIdentifierCreator::new();
    identifier_creator
        .expect_create_local_identifier()
        .once()
        .returning(|_, request, _| {
            let_assert!(CreateLocalIdentifierRequest::Key(key) = request);
            Ok(Identifier {
                r#type: IdentifierType::Key,
                key: Some(key),
                ..dummy_identifier()
            })
        });

    let issuer_identifier = dummy_identifier();
    identifier_creator
        .expect_get_or_create_remote_identifier()
        .once()
        .with(always(), always(), eq(IdentifierRole::Issuer))
        .return_once({
            let identifier = issuer_identifier.clone();
            move |_, _, _| Ok((identifier, RemoteIdentifierRelation::Key(dummy_key())))
        });

    let openid_provider = setup_protocol(TestInputs {
        formatter_provider,
        key_provider,
        key_repository,
        identifier_creator,
        key_algorithm_provider,
        key_security_level_provider,
        config: dummy_config(),
        ..Default::default()
    });

    let result = openid_provider
        .holder_accept_credential(interaction, None, &storage_access, None, None)
        .await
        .unwrap();

    let issuer_response = result.result;
    assert_eq!(issuer_response.credential, "credential");
    assert_eq!(issuer_response.notification_id.unwrap(), "notification_id");

    let create_credential = result.create_credential.unwrap();
    assert_eq!(create_credential.id, credential.id);
    assert_eq!(
        create_credential.issuer_identifier.unwrap().id,
        issuer_identifier.id
    );
}

#[tokio::test]
async fn test_holder_reject_credential() {
    let mock_server = MockServer::start().await;
    let mut storage_access = MockStorageProxy::default();
    let mut did_method_provider = MockDidMethodProvider::default();
    let mut key_algorithm_provider = MockKeyAlgorithmProvider::default();

    let encryption = SecretSlice::from(vec![0; 32]);

    let credential = {
        let mut credential = generic_credential_did();
        credential.state = CredentialStateEnum::Accepted;

        let interaction_data = HolderInteractionData {
            issuer_url: mock_server.uri(),
            credential_endpoint: format!("{}/credential", mock_server.uri()),
            token_endpoint: Some(format!("{}/token", mock_server.uri())),
            nonce_endpoint: Some(format!("{}/nonce", mock_server.uri())),
            notification_endpoint: Some(format!("{}/notification", mock_server.uri())),
            challenge_endpoint: None,
            grants: Some(OpenID4VCIGrants::PreAuthorizedCode(
                OpenID4VCIPreAuthorizedCodeGrant {
                    pre_authorized_code: "code".to_string(),
                    tx_code: None,
                    authorization_server: None,
                },
            )),
            access_token: None,
            access_token_expires_at: None,
            refresh_token: Some(
                encrypt_data(&SecretSlice::from(vec![0; 32]), &encryption).unwrap(),
            ),
            refresh_token_expires_at: None,
            token_endpoint_auth_methods_supported: None,
            cryptographic_binding_methods_supported: None,
            proof_types_supported: None,
            credential_signing_alg_values_supported: None,
            continue_issuance: None,
            credential_configuration_id: credential.schema.as_ref().unwrap().schema_id.to_owned(),
            credential_metadata: None,
            notification_id: Some("notification_id".to_string()),
            protocol: "OPENID4VCI_FINAL1".to_string(),
            format: "jwt_vc_json".to_string(),
        };

        credential.interaction = Some(Interaction {
            id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
                .unwrap()
                .into(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            data: Some(serde_json::to_vec(&interaction_data).unwrap()),
            organisation: None,
            nonce_id: None,
            interaction_type: InteractionType::Issuance,
            expires_at: None,
        });

        credential
    };

    Mock::given(method(Method::POST))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "access_token": "321",
                "token_type": "bearer",
                "expires_in": OffsetDateTime::now_utc().unix_timestamp() + 3600,
                "refresh_token": "321",
                "refresh_token_expires_in": OffsetDateTime::now_utc().unix_timestamp() + 3600,
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/notification"))
        .and(body_json(json!({
            "notification_id": "notification_id",
            "event": "credential_deleted"
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&mock_server)
        .await;

    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .returning(|_| {
            let mut algorithm = MockKeyAlgorithm::new();
            algorithm.expect_generate_key().returning(|| {
                let mut private_key = MockSignaturePrivateKeyHandle::default();

                private_key
                    .expect_sign()
                    .returning(|_| Ok("signature".as_bytes().to_vec()));

                let mut public_key = MockSignaturePublicKeyHandle::default();
                public_key.expect_as_jwk().return_once(|| {
                    Ok(PublicJwk::Ec(PublicJwkEc {
                        alg: None,
                        r#use: None,
                        kid: None,
                        crv: "P-256".to_string(),
                        x: "igrFmi0whuihKnj9R3Om1SoMph72wUGeFaBbzG2vzns".to_owned(),
                        y: Some("efsX5b10x8yjyrj4ny3pGfLcY7Xby1KzgqOdqnsrJIM".to_owned()),
                    }))
                });

                Ok(GeneratedKey {
                    key: KeyHandle::SignatureOnly(SignatureKeyHandle::WithPrivateKey {
                        private: Arc::new(private_key),
                        public: Arc::new(public_key),
                    }),
                    public: vec![],
                    private: vec![].into(),
                })
            });

            algorithm
                .expect_issuance_jose_alg_id()
                .returning(|| Some("ES256".to_string()));

            Some(Arc::new(algorithm))
        });

    did_method_provider.expect_get_did_method().returning(|_| {
        let mut method = MockDidMethod::new();
        method.expect_create().returning(|_, _, _| {
            Ok(DidCreated {
                did: dummy_did().did,
                log: None,
            })
        });
        method
            .expect_get_reference_for_key()
            .return_once(|_| Ok("1".to_string()));

        Some(Arc::new(method))
    });

    storage_access
        .expect_update_interaction()
        .once()
        .returning(move |_, _| Ok(()));

    let openid_provider = setup_protocol(TestInputs {
        did_method_provider,
        key_algorithm_provider,
        config: dummy_config(),
        params: Some(OpenID4VCIFinal1Params {
            pre_authorized_code_expires_in: Duration::seconds(10),
            token_expires_in: Duration::seconds(10),
            credential_offer_by_value: true,
            refresh_expires_in: Duration::seconds(1000),
            encryption,
            url_scheme: "openid-credential-offer".to_string(),
            redirect_uri: OpenID4VCRedirectUriParams {
                enabled: true,
                allowed_schemes: vec!["https".to_string()],
            },
            nonce: None,
            oauth_attestation_leeway: 60,
            key_attestation_leeway: 60,
        }),
        ..Default::default()
    });

    openid_provider
        .holder_reject_credential(credential, &storage_access)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_handle_invitation_credential_by_ref_with_did_success() {
    inner_test_handle_invitation_credential_by_ref_success(
        MockStorageProxy::default(),
        generic_credential_did(),
        Some("did:example:123".to_string()),
    )
    .await;
}

#[tokio::test]
async fn test_handle_invitation_credential_by_ref_without_did_success() {
    inner_test_handle_invitation_credential_by_ref_success(
        MockStorageProxy::default(),
        generic_credential_did(),
        None,
    )
    .await;
}

async fn inner_test_handle_invitation_credential_by_ref_success(
    mut storage_proxy: MockStorageProxy,
    credential: Credential,
    issuer_did: Option<String>,
) {
    let mock_server = MockServer::start().await;
    let issuer_url = Url::from_str(&mock_server.uri()).unwrap();

    let credential_schema_id = credential.schema.clone().unwrap().id;
    let credential_issuer = format!("{issuer_url}ssi/openid4vci/final-1.0/{credential_schema_id}");

    let mut credential_offer = json!({
        "credential_issuer": credential_issuer,
        "credential_configuration_ids" : [credential_schema_id],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": { "pre-authorized_code": "c322aa7f-9803-410d-b891-939b279fb965" }
        },
        "credential_subject": {
            "keys": {
                "NUMBER": {
                    "value": "123",
                }
            },
        }
    });
    if let Some(ref issuer_did) = issuer_did {
        credential_offer
            .as_object_mut()
            .unwrap()
            .insert("issuer_did".into(), Value::String(issuer_did.to_owned()));
    };

    Mock::given(method(Method::GET))
        .and(path(format!(
            "/ssi/openid4vci/final-1.0/{}/offer/{}",
            credential_schema_id, credential.id
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(credential_offer))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut metadata_cache = MockOpenIDMetadataFetcher::new();
    metadata_cache
            .expect_get()
            .with(eq(format!(
                "{issuer_url}.well-known/oauth-authorization-server/ssi/openid4vci/final-1.0/{credential_schema_id}"
            )))
            .once()
            .returning({
                    let credential_issuer = credential_issuer.clone();
                    move |_| Ok(json!({
                        "authorization_endpoint": format!("{credential_issuer}/authorize"),
                        "grant_types_supported": [
                            "urn:ietf:params:oauth:grant-type:pre-authorized_code"
                        ],
                        "id_token_signing_alg_values_supported": [],
                        "issuer": credential_issuer,
                        "jwks_uri": format!("{credential_issuer}/jwks"),
                        "response_types_supported": [
                            "token"
                        ],
                        "subject_types_supported": [
                            "public"
                        ],
                        "token_endpoint": format!("{credential_issuer}/token")
                    }).to_string().into_bytes())
                });

    metadata_cache
        .expect_get()
        .with(eq(format!(
            "{issuer_url}.well-known/openid-credential-issuer/ssi/openid4vci/final-1.0/{credential_schema_id}"
        )))
        .once()
        .returning(move |_| Ok(json!({
            "credential_endpoint": format!("{credential_issuer}/credential"),
            "credential_issuer": credential_issuer,
            "nonce_endpoint": format!("{credential_issuer}/nonce"),
            "credential_configurations_supported": {
                credential_schema_id.to_string(): {
                    "credential_definition": {
                        "type": [
                            "VerifiableCredential"
                        ],
                        "credentialSubject" : {
                            "address": {
                                "value_type": "STRING",
                            }
                        }
                    },
                    "format": "vc+sd-jwt",
                }
            }
        }).to_string().into_bytes()));

    let capture_integration_id = Arc::new(Mutex::new(None));
    storage_proxy
        .expect_create_interaction()
        .times(1)
        .returning({
            let capture_integration_id = capture_integration_id.clone();
            move |i: Interaction| {
                let mut guard = capture_integration_id.lock().unwrap();
                *guard = Some(i.id);
                Ok(i.id)
            }
        });

    let url = Url::parse(&format!("openid-credential-offer://?credential_offer_uri=http%3A%2F%2F{}%2Fssi%2Fopenid4vci%2Ffinal-1.0%2F{}%2Foffer%2F{}", issuer_url.authority(), credential_schema_id, credential.id)).unwrap();

    let protocol = setup_protocol(TestInputs {
        metadata_cache,
        ..Default::default()
    });
    let result = protocol
        .holder_handle_invitation(url, dummy_organisation(None), &storage_proxy, None)
        .await
        .unwrap();

    let InvitationResponseEnum::Credential {
        interaction_id,
        key_storage_security,
        ..
    } = result
    else {
        panic!("Invalid response type");
    };

    assert_eq!(
        capture_integration_id.lock().unwrap().unwrap(),
        interaction_id
    );
    assert_eq!(key_storage_security, None);
}

#[tokio::test]
async fn test_continue_issuance_with_scope_success() {
    inner_continue_issuance_test(true, false).await;
}

#[tokio::test]
async fn test_continue_issuance_with_credential_configuration_ids_success() {
    inner_continue_issuance_test(false, true).await;
}

#[tokio::test]
async fn test_continue_issuance_with_scope_and_credential_configuration_ids_success() {
    inner_continue_issuance_test(true, true).await;
}

async fn inner_continue_issuance_test(with_scope: bool, with_credential_configuration_ids: bool) {
    let mut storage_proxy = MockStorageProxy::default();
    let credential = generic_credential_did();

    let credential_schema_id = credential.schema.clone().unwrap().id;
    let credential_issuer =
        format!("http://issuer/ssi/openid4vci/final-1.0/{credential_schema_id}");

    let mut metadata_cache = MockOpenIDMetadataFetcher::new();

    metadata_cache
        .expect_get()
        .with(eq(format!("http://issuer/.well-known/oauth-authorization-server/ssi/openid4vci/final-1.0/{credential_schema_id}")))
        .once()
        .returning({
            let credential_issuer = credential_issuer.clone();
            move |_| {
                Ok(json!({
                    "authorization_endpoint": format!("{credential_issuer}/authorize"),
                    "grant_types_supported": [
                        "urn:ietf:params:oauth:grant-type:pre-authorized_code"
                    ],
                    "id_token_signing_alg_values_supported": [],
                    "issuer": credential_issuer,
                    "jwks_uri": format!("{credential_issuer}/jwks"),
                    "response_types_supported": [
                        "token"
                    ],
                    "subject_types_supported": [
                        "public"
                    ],
                    "token_endpoint": format!("{credential_issuer}/token")
                })
                .to_string()
                .into_bytes())
            }
        });

    metadata_cache
        .expect_get()
        .with(eq(format!(
            "http://issuer/.well-known/openid-credential-issuer/ssi/openid4vci/final-1.0/{credential_schema_id}"
        )))
        .once()
        .returning({
            let credential_issuer = credential_issuer.clone();
            move |_| {
                Ok(json!({
                    "credential_endpoint": format!("{credential_issuer}/credential"),
                    "credential_issuer": credential_issuer,
                    "nonce_endpoint": format!("{credential_issuer}/nonce"),
                    "credential_configurations_supported": {
                        credential_schema_id.to_string(): {
                            "credential_definition": {
                                "type": [
                                    "VerifiableCredential"
                                ],
                                "credentialSubject" : {
                                    "address": {
                                        "value_type": "STRING",
                                    }
                                }
                            },
                            "format": "vc+sd-jwt",
                            "scope": "testScope",
                        }
                  }
                })
                .to_string()
                .into_bytes())
            }
        });

    let capture_integration_id = Arc::new(Mutex::new(None));
    storage_proxy
        .expect_create_interaction()
        .times(1)
        .returning({
            let capture_integration_id = capture_integration_id.clone();
            move |i: Interaction| {
                let mut guard = capture_integration_id.lock().unwrap();
                *guard = Some(i.id);
                Ok(i.id)
            }
        });
    let protocol = setup_protocol(TestInputs {
        metadata_cache,
        ..Default::default()
    });

    // when

    let scope = if with_scope {
        vec!["testScope".to_string()]
    } else {
        Vec::new()
    };

    let credential_configuration_ids = if with_credential_configuration_ids {
        vec![credential_schema_id.to_string()]
    } else {
        Vec::new()
    };

    let result = protocol
        .holder_continue_issuance(
            ContinueIssuanceDTO {
                credential_issuer,
                authorization_code: "authorization_code".to_string(),
                client_id: "testClientId".to_string(),
                redirect_uri: None,
                scope,
                credential_configuration_ids,
                code_verifier: None,
                authorization_server: None,
            },
            dummy_organisation(None),
            &storage_proxy,
        )
        .await
        .unwrap();

    assert_eq!(
        capture_integration_id.lock().unwrap().unwrap(),
        result.interaction_id
    );
}

fn dummy_issuer_metadata() -> Vec<u8> {
    json!({
        "credential_endpoint": "http://base_url/credential",
        "credential_issuer": "http://base_url",
        "credential_configurations_supported": {
            "id": {
                "credential_definition": {
                    "type": [
                        "VerifiableCredential"
                    ],
                    "credentialSubject" : {
                        "address": {
                            "value_type": "STRING",
                        }
                    }
                },
                "format": "vc+sd-jwt",
            }
      }
    })
    .to_string()
    .into_bytes()
}

#[tokio::test]
async fn test_can_handle_issuance_success_with_custom_url_scheme() {
    let url_scheme = "my-custom-scheme";

    let mock_server = MockServer::start().await;
    let issuer_url = Url::from_str(&mock_server.uri()).unwrap();

    Mock::given(method(Method::GET))
        .and(path(
            "ssi/oidc-issuer/v1/c322aa7f-9803-410d-b891-939b279fb965/offer/c322aa7f-9803-410d-b891-939b279fb965"
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "credential_issuer": "http://base_url",
            "credential_configuration_ids" : ["id"],
            "grants": {
                "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                    "pre-authorized_code": "c322aa7f-9803-410d-b891-939b279fb965"
                }
            },
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut metadata_cache = MockOpenIDMetadataFetcher::new();
    metadata_cache
        .expect_get()
        .with(eq("http://base_url/.well-known/openid-credential-issuer"))
        .returning(|_| Ok(dummy_issuer_metadata()));

    let protocol = setup_protocol(TestInputs {
        params: Some(test_params(url_scheme)),
        metadata_cache,
        ..Default::default()
    });

    let test_url = format!(
        "{url_scheme}://?credential_offer_uri=http%3A%2F%2F{}%2Fssi%2Foidc-issuer%2Fv1%2Fc322aa7f-9803-410d-b891-939b279fb965%2Foffer%2Fc322aa7f-9803-410d-b891-939b279fb965",
        issuer_url.authority(),
    );
    assert!(protocol.holder_can_handle(&test_url.parse().unwrap()).await)
}

#[tokio::test]
async fn test_can_handle_issuance_fail_with_custom_url_scheme() {
    let url_scheme = "my-custom-scheme";
    let other_url_scheme = "my-different-scheme";

    let protocol = setup_protocol(TestInputs {
        params: Some(test_params(url_scheme)),
        ..Default::default()
    });

    let test_url = format!(
        "{other_url_scheme}://?credential_offer_uri=http%3A%2F%2Fbase_url%2Fssi%2Foidc-issuer%2Fv1%2Fc322aa7f-9803-410d-b891-939b279fb965%2Foffer%2Fc322aa7f-9803-410d-b891-939b279fb965"
    );
    assert!(!protocol.holder_can_handle(&test_url.parse().unwrap()).await)
}

#[tokio::test]
async fn test_can_handle_presentation_fail_with_custom_url_scheme() {
    let other_url_scheme = "my-different-scheme";

    let protocol = setup_protocol(TestInputs {
        params: Some(test_params("issuance-url-scheme")),
        ..Default::default()
    });

    let test_url = format!(
        "{other_url_scheme}://?credential_offer_uri=http%3A%2F%2Fbase_url%2Fssi%2Foidc-issuer%2Fv1%2Fc322aa7f-9803-410d-b891-939b279fb965%2Foffer%2Fc322aa7f-9803-410d-b891-939b279fb965"
    );
    assert!(!protocol.holder_can_handle(&test_url.parse().unwrap()).await)
}

#[tokio::test]
async fn test_generate_share_credentials_custom_scheme() {
    let credential = generic_credential_did();
    let url_scheme = "my-custom-scheme";
    let protocol = setup_protocol(TestInputs {
        params: Some(test_params(url_scheme)),
        ..Default::default()
    });

    let result = protocol.issuer_share_credential(&credential).await.unwrap();
    assert!(result.url.starts_with(url_scheme));
}

fn test_params(issuance_url_scheme: &str) -> OpenID4VCIFinal1Params {
    OpenID4VCIFinal1Params {
        pre_authorized_code_expires_in: Duration::seconds(10),
        token_expires_in: Duration::seconds(10),
        credential_offer_by_value: true,
        refresh_expires_in: Duration::seconds(1000),
        encryption: SecretSlice::from(vec![0; 32]),
        url_scheme: issuance_url_scheme.to_string(),
        redirect_uri: OpenID4VCRedirectUriParams {
            enabled: true,
            allowed_schemes: vec!["https".to_string()],
        },
        nonce: None,
        oauth_attestation_leeway: 60,
        key_attestation_leeway: 60,
    }
}
