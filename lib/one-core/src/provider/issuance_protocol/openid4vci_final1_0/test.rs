use std::str::FromStr;
use std::sync::{Arc, Mutex};

use assert2::let_assert;
use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use indexmap::IndexMap;
use mockall::predicate::{always, eq};
use one_crypto::encryption::encrypt_data;
use one_crypto::jwe::{Header, build_jwe, decrypt_jwe_payload};
use secrecy::SecretSlice;
use serde_json::{Value, json};
use shared_types::CredentialFormat;
use similar_asserts::assert_eq;
use standardized_types::etsi_119_472::disclosure_policy::{DisclosurePolicy, PolicyType};
use standardized_types::iana::{EncryptionAlgorithm, EncryptionKeyManagementAlgorithm};
use standardized_types::jwe::CompressionAlgorithm;
use standardized_types::jwk::{Jwks, PublicJwk, PublicJwkEc};
use standardized_types::openid4vci::{
    ClaimDisplay, ClaimMetadata, CredentialDisplay, CredentialIssuerMetadata, CredentialMetadata,
    CredentialRequest, CredentialRequestEncryption, CredentialRequestIdentifier,
    CredentialResponseEncryption, Grants, Image, IssuerDisplay, KeyAttestationsRequired,
    KeyStorageSecurityLevel, PreAuthorizedCodeGrant, ProofTypeSupported, Proofs,
};
use time::Duration;
use url::Url;
use uuid::Uuid;
use wiremock::http::Method;
use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::OpenID4VCIFinal1_0;
use super::attestations::AttestationType;
use super::model::{
    HolderBinding, HolderCredentialConfiguration, HolderInteractionData,
    OpenID4VCIIssuerInteractionDataDTO, RequestedCredential,
};
use super::service::{build_issuer_display, create_credential_offer};
use crate::clock::now_utc;
use crate::config::core_config::{
    CoreConfig, Fields, FormatType, KeyAlgorithmType, KeySecurityLevelType,
};
use crate::error::ErrorCodeMixinExt;
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{Credential, CredentialRole, CredentialStateEnum, CredentialType};
use crate::model::credential_schema::{CredentialSchema, KeyStorageSecurity};
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::credential_schema_format_claim_schema::CredentialSchemaFormatClaimSchema;
use crate::model::did::{Did, DidType, KeyRole, RelatedKey};
use crate::model::identifier::{Identifier, IdentifierData, IdentifierState};
use crate::model::instance::{Instance, InstanceRole, InstanceStatus, WalletProviderType};
use crate::model::interaction::{Interaction, InteractionType};
use crate::model::key::Key;
use crate::model::localized_text::{LocalizedText, LocalizedTextEntityType, LocalizedTextField};
use crate::model::organisation::{Organisation, OrganisationConfiguration};
use crate::model::relation::Related;
use crate::proto::certificate_validator::{MockCertificateValidator, ParsedCertificate};
use crate::proto::credential_schema::importer::MockCredentialSchemaImporter;
use crate::proto::http_client::reqwest_client::ReqwestClient;
use crate::proto::http_client::{MockHttpClient, Request, RequestBuilder, Response, StatusCode};
use crate::proto::identifier_creator::{
    CreateLocalIdentifierRequestType, IdentifierName, IdentifierRole, MockIdentifierCreator,
    RemoteIdentifierRelation,
};
use crate::proto::session_provider::NoSessionProvider;
use crate::proto::wallet_instance::{
    IssueWalletAttestationRequest, IssuedWalletUnitAttestations, MockHolderWalletUnitProto,
    WUARequestParams,
};
use crate::provider::blob_storage::provider::MockBlobStorageProvider;
use crate::provider::caching_loader::openid_metadata::MockOpenIDMetadataFetcher;
use crate::provider::credential_formatter::MockCredentialFormatter;
use crate::provider::credential_formatter::model::{IdentifierDetails, MockSignatureProvider};
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::did_method::{DidCreated, MockDidMethod};
use crate::provider::issuance_protocol::dto::ContinueIssuanceDTO;
use crate::provider::issuance_protocol::model::InvitationResponseEnum;
use crate::provider::issuance_protocol::{HolderBindingInput, IssuanceProtocol};
use crate::provider::key_algorithm::ecdsa::Ecdsa;
use crate::provider::key_algorithm::key::{
    KeyHandle, MockSignaturePrivateKeyHandle, MockSignaturePublicKeyHandle, SignatureKeyHandle,
};
use crate::provider::key_algorithm::model::GeneratedKey;
use crate::provider::key_algorithm::provider::{MockKeyAlgorithmProvider, ParsedKey};
use crate::provider::key_algorithm::{KeyAlgorithm, MockKeyAlgorithm};
use crate::provider::key_security_level::MockKeySecurityLevel;
use crate::provider::key_security_level::dto::KeySecurityLevelCapabilities;
use crate::provider::key_security_level::provider::MockKeySecurityLevelProvider;
use crate::provider::key_storage::MockKeyStorage;
use crate::provider::key_storage::model::{KeyStorageCapabilities, StorageGeneratedKey};
use crate::provider::key_storage::provider::MockKeyProvider;
use crate::provider::revocation::provider::MockRevocationMethodProvider;
use crate::repository::credential_repository::MockCredentialRepository;
use crate::repository::credential_schema_repository::MockCredentialSchemaRepository;
use crate::repository::history_repository::MockHistoryRepository;
use crate::repository::identifier_repository::MockIdentifierRepository;
use crate::repository::instance_repository::MockInstanceRepository;
use crate::repository::interaction_repository::MockInteractionRepository;
use crate::repository::key_repository::MockKeyRepository;
use crate::service::certificate::dto::CertificateX509AttributesDTO;
use crate::service::managed_instance::dto::IssueWalletUnitAttestationResponseDTO;
use crate::service::test_utilities::{
    dummy_did, dummy_identifier, dummy_key, dummy_organisation, get_dummy_date,
};

#[derive(Default)]
struct TestInputs {
    pub credential_repository: MockCredentialRepository,
    pub key_repository: MockKeyRepository,
    pub identifier_creator: MockIdentifierCreator,
    pub metadata_cache: MockOpenIDMetadataFetcher,
    pub credential_schema_repository: MockCredentialSchemaRepository,
    pub credential_schema_importer: Option<MockCredentialSchemaImporter>,
    pub formatter_provider: MockCredentialFormatterProvider,
    pub revocation_provider: MockRevocationMethodProvider,
    pub key_algorithm_provider: MockKeyAlgorithmProvider,
    pub key_provider: MockKeyProvider,
    pub did_method_provider: MockDidMethodProvider,
    pub blob_storage_provider: MockBlobStorageProvider,
    pub key_security_level_provider: MockKeySecurityLevelProvider,
    pub certificate_validator: MockCertificateValidator,
    pub holder_wallet_unit_proto: MockHolderWalletUnitProto,
    pub holder_wallet_unit_repository: MockInstanceRepository,
    pub history_repository: MockHistoryRepository,
    pub interaction_repository: MockInteractionRepository,
    pub identifier_repository: MockIdentifierRepository,
    pub config: CoreConfig,
    pub params: Option<serde_json::Value>,
    pub client: Option<MockHttpClient>,
}

fn setup_protocol(inputs: TestInputs) -> OpenID4VCIFinal1_0 {
    OpenID4VCIFinal1_0::new(
        inputs
            .client
            .map(|mock| Arc::new(mock) as _)
            .unwrap_or(Arc::new(ReqwestClient::default())),
        Arc::new(inputs.metadata_cache),
        Arc::new(inputs.credential_repository),
        Arc::new(inputs.key_repository),
        Arc::new(inputs.identifier_creator),
        inputs
            .credential_schema_importer
            .map(|m| Arc::new(m) as _)
            .unwrap_or_else(|| Arc::new(MockCredentialSchemaImporter::new())),
        Arc::new(inputs.credential_schema_repository),
        Arc::new(inputs.formatter_provider),
        Arc::new(inputs.revocation_provider),
        Arc::new(inputs.did_method_provider),
        Arc::new(inputs.key_algorithm_provider),
        Arc::new(inputs.key_provider),
        Arc::new(inputs.key_security_level_provider),
        Arc::new(inputs.blob_storage_provider),
        Some("http://base_url".to_string()),
        Arc::new(inputs.config),
        inputs.params.unwrap_or({
            let mut params = test_params("openid-credential-offer");
            params["credentialOfferByValue"] = json!(false);
            params
        }),
        "OPENID4VCI_FINAL1".to_string(),
        Arc::new(inputs.holder_wallet_unit_proto),
        Arc::new(inputs.holder_wallet_unit_repository),
        Arc::new(inputs.certificate_validator),
        Arc::new(inputs.history_repository),
        Arc::new(NoSessionProvider),
        Arc::new(inputs.interaction_repository),
        Arc::new(inputs.identifier_repository),
    )
    .unwrap()
}

fn generic_credential_did() -> Credential {
    let now = crate::clock::now_utc();
    let issuer_did = Did {
        deleted_at: None,
        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
            .unwrap()
            .into(),
        created_date: now,
        last_modified: now,
        name: "did1".to_string(),
        did: "did:example:123".parse().unwrap(),
        did_type: DidType::Remote,
        did_method: "KEY".into(),
        keys: Default::default(),
        deactivated: false,
        organisation: dummy_organisation(None).into(),
        log: None,
    };
    let issuer_identifier = Identifier {
        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
            .unwrap()
            .into(),
        created_date: now,
        last_modified: now,
        name: "did1".to_string(),
        data: IdentifierData::Did((issuer_did).into()),
        is_remote: true,
        state: IdentifierState::Active,
        deleted_at: None,
        autogenerated: false,
        organisation: dummy_organisation(Some(uuid::Uuid::new_v4().into())).into(),
        trust_information: Default::default(),
        logo: None,
        translations: Default::default(),
    };
    generic_credential(issuer_identifier)
}

fn generic_credential_did_with_holder_identifier() -> Credential {
    let now = crate::clock::now_utc();
    let mut credential = generic_credential_did();
    credential.holder_identifier = Some(
        Identifier {
            id: Uuid::from_str("a322aa7f-9803-410d-b891-939b279fb965")
                .unwrap()
                .into(),
            created_date: now,
            last_modified: now,
            name: "holder identifier".to_string(),
            data: IdentifierData::Key(Related::from(Key {
                key_type: "ECDSA".to_string(),
                ..dummy_key()
            })),
            is_remote: true,
            state: IdentifierState::Active,
            deleted_at: None,
            autogenerated: false,
            organisation: dummy_organisation(Some(uuid::Uuid::new_v4().into())).into(),
            trust_information: Default::default(),
            logo: None,
            translations: Default::default(),
        }
        .into(),
    );
    credential
}

fn generic_credential_key() -> Credential {
    let now = crate::clock::now_utc();
    let issuer_key = Key {
        autogenerated: false,
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
        organisation: dummy_organisation(None).into(),
        key_type: "ECDSA".to_string(),
    };
    let issuer_identifier = Identifier {
        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
            .unwrap()
            .into(),
        created_date: now,
        last_modified: now,
        name: "key1".to_string(),
        data: IdentifierData::Key(Related::from(issuer_key)),
        is_remote: true,
        state: IdentifierState::Active,
        deleted_at: None,
        autogenerated: false,
        organisation: dummy_organisation(Some(uuid::Uuid::new_v4().into())).into(),
        trust_information: Default::default(),
        logo: None,
        translations: Default::default(),
    };
    let mut credential = generic_credential(issuer_identifier);
    let holder_identifier = Identifier {
        id: Uuid::from_str("a322aa7f-9803-410d-b891-939b279fb965")
            .unwrap()
            .into(),
        created_date: now,
        last_modified: now,
        name: "holder identifier".to_string(),
        data: IdentifierData::Key(Related::from(dummy_key())),
        is_remote: true,
        state: IdentifierState::Active,
        deleted_at: None,
        autogenerated: false,
        organisation: dummy_organisation(Some(uuid::Uuid::new_v4().into())).into(),
        trust_information: Default::default(),
        logo: None,
        translations: Default::default(),
    };
    credential.holder_identifier = Some(holder_identifier.into());
    credential
}

fn generic_credential(issuer_identifier: Identifier) -> Credential {
    let now = crate::clock::now_utc();

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
        required: true,
        translations: Default::default(),
    };

    let credential_schema_format_id = Uuid::new_v4().into();
    let claim_schema_mapping = CredentialSchemaFormatClaimSchema {
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
        credential_schema_format_id,
        claim_schema_id: claim_schema.id,
        technical_key: "NUMBER".to_string(),
        namespace: None,
    };

    let credential_id = Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
        .unwrap()
        .into();

    let credential_schema_id = Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
        .unwrap()
        .into();
    let format = CredentialSchemaFormat {
        id: credential_schema_format_id,
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        credential_schema_id,
        format: "JWT".into(),
        ecosystem_schema_id: "CredentialSchemaId".to_owned(),
        claim_mappings: vec![claim_schema_mapping].into(),
    };
    Credential {
        expires_at: None,
        ecosystem: None,
        id: credential_id,
        created_date: now,
        issuance_date: None,
        last_modified: now,
        deleted_at: None,
        consumed_at: None,
        protocol: "OPENID4VCI_FINAL1".to_string(),
        redirect_uri: None,
        role: CredentialRole::Issuer,
        r#type: CredentialType::Single,
        state: CredentialStateEnum::Created,
        suspend_end_date: None,
        claims: vec![Claim {
            id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
                .unwrap()
                .into(),
            credential_id,
            created_date: now,
            last_modified: now,
            value: Some("123".to_string()),
            path: claim_schema.key.to_owned(),
            selectively_disclosable: false,
            schema: claim_schema.clone().into(),
        }]
        .into(),
        // Callers only pass did/key identifiers (no certificates).
        issuer_certificate: None,
        issuer_identifier: Some(issuer_identifier.into()),
        holder_identifier: None,
        schema: CredentialSchema {
            expiration: None,
            ecosystem: None,
            batch_size: None,
            allow_revocation: false,
            id: credential_schema_id,
            deleted_at: None,
            imported_source_url: "CORE_URL".to_string(),
            created_date: now,
            key_storage_security: Some(KeyStorageSecurity::Basic),
            last_modified: now,
            name: "schema".to_string(),
            formats: vec![format.clone()].into(),
            claim_schemas: vec![claim_schema].into(),
            layout_properties: None,
            organisation: dummy_organisation(None).into(),
            allow_suspension: true,
            requires_wallet_instance_attestation: false,
            transaction_code: None,
            translations: Default::default(),
            embedded_disclosure_policy: None,
        }
        .into(),
        interaction: Some(
            Interaction {
                id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
                    .unwrap()
                    .into(),
                created_date: now,
                data: Some(vec![1, 2, 3]),
                last_modified: now,
                organisation: dummy_organisation(None).into(),
                nonce_id: None,
                interaction_type: InteractionType::Issuance,
                expires_at: None,
                ecosystem: None,
                ecosystem_data: Default::default(),
            }
            .into(),
        ),
        key: None,
        profile: None,
        credential_blob_id: None,
        wallet_unit_attestation_blob_id: None,
        wallet_instance_attestation_blob_id: None,
        webhook_url: None,
        parent: None,
        embedded_disclosure_policy: None,
        subscriber_information: None,
        format: Some(format.into()),
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
    let issuer_identifier_id = credential.issuer_identifier.as_ref().unwrap().id();

    let credential_schema = credential.schema.as_ref().await.unwrap();
    let offer = create_credential_offer(
        &protocol_base_url,
        &credential.protocol,
        &interaction_id.to_string(),
        &credential_schema,
        &credential_schema.formats.as_ref().await.unwrap(),
        issuer_identifier_id,
    )
    .unwrap();

    assert_eq!(
        json!(&offer),
        json!({
            "credential_issuer": format!("BASE_URL/ssi/openid4vci/final-1.0/{}/{issuer_identifier_id}/c322aa7f-9803-410d-b891-939b279fb965", credential.protocol),
            "credential_configuration_ids" : [
                credential.schema.as_ref().await.unwrap().schema_id().await.unwrap(),
            ],
            "grants": {
                "urn:ietf:params:oauth:grant-type:pre-authorized_code": { "pre-authorized_code": "c322aa7f-9803-410d-b891-939b279fb965" }
            }
        })
    )
}

#[test]
fn test_issuer_interaction_data_deserializes_legacy_notification_id() {
    let data: OpenID4VCIIssuerInteractionDataDTO = serde_json::from_value(json!({
        "pre_authorized_code_used": true,
        "access_token_hash": [1, 2, 3],
        "transaction_code": null,
        "notification_id": "notification"
    }))
    .unwrap();

    let_assert!([entry] = data.notification_ids.as_slice());
    assert_eq!(entry.notification_id, "notification");
    assert!(entry.format.is_none());
}

#[test]
fn test_holder_interaction_data_deserializes_legacy_single_configuration() {
    let data: HolderInteractionData = serde_json::from_value(json!({
        "issuer_url": "https://issuer.example.com",
        "credential_endpoint": "https://issuer.example.com/credential",
        "protocol": "OPENID4VCI_FINAL1",
        "credential_configuration_id": "configuration",
        "format": "dc+sd-jwt",
        "notification_id": "notification"
    }))
    .unwrap();

    let_assert!([configuration] = data.credential_configurations.as_slice());
    assert_eq!(configuration.credential_configuration_id, "configuration");
    assert_eq!(configuration.format, "dc+sd-jwt");
    assert_eq!(
        configuration.notification_id.as_deref(),
        Some("notification")
    );
    assert!(configuration.credential_id.is_none());
    assert!(
        data.configuration_for_credential(Uuid::new_v4().into())
            .is_some()
    );

    let serialized = serde_json::to_value(&data).unwrap();
    assert!(serialized.get("credential_configuration_id").is_none());
    assert_eq!(
        serialized["credential_configurations"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn test_generate_share_credentials() {
    let mut credential = generic_credential_did();
    credential.interaction = None;
    let protocol = setup_protocol(Default::default());

    let result = protocol.issuer_share_credential(&credential).await.unwrap();
    assert_eq!(
        result.url,
        "openid-credential-offer://?credential_offer_uri=http%3A%2F%2Fbase_url%2Fssi%2Fopenid4vci%2Ffinal-1.0%2Fc322aa7f-9803-410d-b891-939b279fb965%2Foffer%2Fc322aa7f-9803-410d-b891-939b279fb965"
    );
}

#[tokio::test]
async fn test_generate_share_credentials_offer_by_value() {
    let mut credential = generic_credential_did();
    credential.interaction = None;

    let protocol = setup_protocol(TestInputs {
        params: Some(test_params("openid-credential-offer")),
        ..Default::default()
    });

    let result = protocol.issuer_share_credential(&credential).await.unwrap();
    // Everything except for interaction id is here.
    // Generating token with predictable interaction id is tested somewhere else.
    assert!(
        result.url.starts_with(r#"openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22http%3A%2F%2Fbase_url%2Fssi%2Fopenid4vci%2Ffinal-1.0%2FOPENID4VCI_FINAL1%2Fc322aa7f-9803-410d-b891-939b279fb965%2Fc322aa7f-9803-410d-b891-939b279fb965%22%2C%22credential_configuration_ids%22%3A%5B%22CredentialSchemaId%22%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%"#)
    );
}

#[tokio::test]
async fn test_holder_accept_credential_success() {
    let mock_server = MockServer::start().await;
    let mut formatter_provider = MockCredentialFormatterProvider::default();
    let mut key_provider = MockKeyProvider::default();

    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();

    let key = dummy_key();
    let mut credential = generic_credential_did_with_holder_identifier();
    credential
        .holder_identifier
        .as_mut()
        .unwrap()
        .as_mut()
        .await
        .unwrap()
        .data = IdentifierData::Key(Related::from(key.clone()));

    let interaction_data = HolderInteractionData {
        issuer_url: mock_server.uri(),
        credential_endpoint: format!("{}/credential", mock_server.uri()),
        token_endpoint: Some(format!("{}/token", mock_server.uri())),
        nonce_endpoint: Some(format!("{}/nonce", mock_server.uri())),
        notification_endpoint: Some(format!("{}/notification", mock_server.uri())),
        challenge_endpoint: None,
        grants: Some(Grants::PreAuthorizedCode(PreAuthorizedCodeGrant {
            pre_authorized_code: "code".to_string(),
            tx_code: None,
            authorization_server: None,
        })),
        batch_size: None,
        access_token: None,
        access_token_expires_at: None,
        refresh_token: None,
        token_endpoint_auth_methods_supported: None,
        client_attestation_pop_signing_alg_values_supported: None,
        refresh_token_expires_at: None,
        continue_issuance: None,
        issuer_display: None,
        protocol: "OPENID4VCI_FINAL1".to_string(),
        credential_request_encryption: None,
        credential_response_encryption: None,
        credential_configurations: vec![HolderCredentialConfiguration {
            credential_configuration_id: credential
                .schema
                .as_ref()
                .await
                .unwrap()
                .schema_id()
                .await
                .unwrap(),
            format: "jwt_vc_json".to_string(),
            cryptographic_binding_methods_supported: Some(vec!["jwk".to_string()]),
            credential_signing_alg_values_supported: None,
            proof_types_supported: None,
            credential_metadata: None,
            disclosure_policy: None,
            notification_id: None,
            credential_id: None,
        }],
    };

    let interaction = Interaction {
        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
            .unwrap()
            .into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        data: Some(serde_json::to_vec(&interaction_data).unwrap()),
        organisation: credential
            .schema
            .as_ref()
            .await
            .unwrap()
            .organisation
            .to_owned(),
        nonce_id: None,
        interaction_type: InteractionType::Issuance,
        expires_at: None,
        ecosystem: None,
        ecosystem_data: Default::default(),
    };

    Mock::given(method(Method::POST))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "access_token": "321",
                "token_type": "Bearer",
                "expires_in": crate::clock::now_utc().unix_timestamp() + 3600,
                "refresh_token": "321",
                "refresh_token_expires_in": crate::clock::now_utc().unix_timestamp() + 3600,
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
    formatter
        .expect_get_leeway()
        .return_const(Duration::seconds(1000));
    formatter.expect_parse_credential().returning({
        let clone = credential.clone();
        move |_, _, _| Ok(clone.clone())
    });

    let formatter = Arc::new(formatter);
    let formatter_clone = formatter.clone();
    formatter_provider
        .expect_get_credential_formatter()
        .with(eq(CredentialFormat::from("JWT")))
        .returning(move |_| Ok(formatter_clone.clone()));
    formatter_provider
        .expect_get_formatter_by_type()
        .returning(move |_| Some(("JWT".into(), formatter.clone())));

    let schema = credential.schema.as_ref().await.unwrap().to_owned();
    credential_schema_repository
        .expect_get_by_schema_id_and_organisation()
        .once()
        .returning(move |_, _| Ok(Some(schema.clone())));

    interaction_repository
        .expect_update_interaction()
        .once()
        .returning(move |_, _| Ok(()));

    key_provider
        .expect_get_signature_provider()
        .returning(move |_, _, _| {
            let mut mock_signature_provider = MockSignatureProvider::new();
            mock_signature_provider
                .expect_jose_alg()
                .returning(|| Ok("EdDSA".to_string()));

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
        .with(
            always(),
            always(),
            eq(IdentifierName::PrefixForId(
                IdentifierRole::Issuer.to_string(),
            )),
            eq(true),
            always(),
            always(),
        )
        .return_once({
            let identifier = identifier.clone();
            move |_, _, _, _, _, _| Ok((identifier, RemoteIdentifierRelation::Key(dummy_key())))
        });

    let mut holder_wallet_unit_repository = MockInstanceRepository::new();
    holder_wallet_unit_repository
        .expect_get_by_role()
        .once()
        .return_once(|_, _| Ok(None));

    let openid_provider = setup_protocol(TestInputs {
        formatter_provider,
        key_provider,
        key_algorithm_provider,
        identifier_creator,
        credential_schema_repository,
        holder_wallet_unit_repository,
        interaction_repository,
        config: dummy_config(),
        ..Default::default()
    });
    let configuration_ids = configuration_ids(&interaction);
    let issuer_response = openid_provider
        .holder_accept_credential(
            interaction,
            Some(HolderBindingInput {
                identifier: Identifier {
                    data: IdentifierData::Key(Related::from(key.clone())),
                    ..dummy_identifier()
                },
                key,
            }),
            None,
            configuration_ids,
        )
        .await
        .unwrap()
        .issued
        .pop()
        .unwrap();
    assert_eq!(
        issuer_response.main_credential.serialized,
        Some("credential".into())
    );

    assert!(issuer_response.batch_items.is_empty());

    let single_credential = issuer_response.main_credential.credential;
    assert_eq!(single_credential.id, credential.id);
    assert_eq!(
        single_credential.issuer_identifier.as_ref().unwrap().id(),
        identifier.id
    );
}

#[tokio::test]
async fn test_holder_accept_credential_none_existing_issuer_key_id_success() {
    let mock_server = MockServer::start().await;
    let mut formatter_provider = MockCredentialFormatterProvider::default();
    let mut key_provider = MockKeyProvider::default();

    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();

    let credential = generic_credential_key();

    let interaction_data = HolderInteractionData {
        issuer_url: mock_server.uri(),
        credential_endpoint: format!("{}/credential", mock_server.uri()),
        token_endpoint: Some(format!("{}/token", mock_server.uri())),
        nonce_endpoint: Some(format!("{}/nonce", mock_server.uri())),
        notification_endpoint: None,
        challenge_endpoint: None,
        grants: Some(Grants::PreAuthorizedCode(PreAuthorizedCodeGrant {
            pre_authorized_code: "code".to_string(),
            tx_code: None,
            authorization_server: None,
        })),
        batch_size: None,
        access_token: None,
        access_token_expires_at: None,
        token_endpoint_auth_methods_supported: None,
        client_attestation_pop_signing_alg_values_supported: None,
        refresh_token: None,
        refresh_token_expires_at: None,
        continue_issuance: None,
        issuer_display: None,
        protocol: "OPENID4VCI_FINAL1".to_string(),
        credential_request_encryption: None,
        credential_response_encryption: None,
        credential_configurations: vec![HolderCredentialConfiguration {
            credential_configuration_id: credential
                .schema
                .as_ref()
                .await
                .unwrap()
                .schema_id()
                .await
                .unwrap(),
            format: "jwt_vc_json".to_string(),
            cryptographic_binding_methods_supported: Some(vec!["jwk".to_string()]),
            credential_signing_alg_values_supported: None,
            proof_types_supported: None,
            credential_metadata: None,
            disclosure_policy: None,
            notification_id: None,
            credential_id: None,
        }],
    };

    let interaction = Interaction {
        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
            .unwrap()
            .into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        data: Some(serde_json::to_vec(&interaction_data).unwrap()),
        organisation: credential
            .schema
            .as_ref()
            .await
            .unwrap()
            .organisation
            .to_owned(),
        nonce_id: None,
        interaction_type: InteractionType::Issuance,
        expires_at: None,
        ecosystem: None,
        ecosystem_data: Default::default(),
    };

    Mock::given(method(Method::POST))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "access_token": "321",
                "token_type": "Bearer",
                "expires_in": crate::clock::now_utc().unix_timestamp() + 3600,
                "refresh_token": "321",
                "refresh_token_expires_in": crate::clock::now_utc().unix_timestamp() + 3600,
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
    formatter
        .expect_get_leeway()
        .return_const(Duration::seconds(1000));
    formatter.expect_parse_credential().returning({
        let clone = credential.clone();
        move |_, _, _| Ok(clone.clone())
    });
    let formatter = Arc::new(formatter);
    let formatter_clone = formatter.clone();
    formatter_provider
        .expect_get_credential_formatter()
        .with(eq(CredentialFormat::from("JWT")))
        .returning(move |_| Ok(formatter_clone.clone()));
    formatter_provider
        .expect_get_formatter_by_type()
        .returning(move |_| Some(("JWT".into(), formatter.clone())));

    let schema = credential.schema.as_ref().await.unwrap().to_owned();
    credential_schema_repository
        .expect_get_by_schema_id_and_organisation()
        .once()
        .returning(move |_, _| Ok(Some(schema.clone())));

    interaction_repository
        .expect_update_interaction()
        .once()
        .returning(move |_, _| Ok(()));

    key_provider
        .expect_get_signature_provider()
        .returning(move |_, _, _| {
            let mut mock_signature_provider = MockSignatureProvider::new();
            mock_signature_provider
                .expect_jose_alg()
                .returning(|| Ok("EdDSA".to_string()));

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
            eq(IdentifierName::PrefixForId(
                IdentifierRole::Issuer.to_string(),
            )),
            eq(true),
            always(),
            always(),
        )
        .returning(|_, _, _, _, _, _| {
            Ok((
                dummy_identifier(),
                RemoteIdentifierRelation::Key(dummy_key()),
            ))
        });

    let mut holder_wallet_unit_repository = MockInstanceRepository::new();
    holder_wallet_unit_repository
        .expect_get_by_role()
        .once()
        .return_once(|_, _| Ok(None));

    let openid_provider = setup_protocol(TestInputs {
        formatter_provider,
        key_provider,
        key_algorithm_provider,
        identifier_creator,
        credential_schema_repository,
        holder_wallet_unit_repository,
        interaction_repository,
        config: dummy_config(),
        ..Default::default()
    });

    let key = Key {
        id: Uuid::new_v4().into(),
        ..dummy_key()
    };
    let configuration_ids = configuration_ids(&interaction);
    let issuer_response = openid_provider
        .holder_accept_credential(
            interaction,
            Some(HolderBindingInput {
                identifier: Identifier {
                    data: IdentifierData::Did(
                        (Did {
                            keys: vec![RelatedKey {
                                role: KeyRole::Authentication,
                                key: key.to_owned(),
                                reference: "ref".to_string(),
                            }]
                            .into(),
                            ..dummy_did()
                        })
                        .into(),
                    ),
                    ..dummy_identifier()
                },
                key,
            }),
            None,
            configuration_ids,
        )
        .await
        .unwrap()
        .issued
        .pop()
        .unwrap();

    assert_eq!(
        issuer_response.main_credential.serialized,
        Some("credential".into())
    );
    assert!(issuer_response.batch_items.is_empty());

    let single_credential = issuer_response.main_credential.credential;
    assert_eq!(single_credential.id, credential.id);
}

#[tokio::test]
async fn test_holder_accept_credential_autogenerate_holder_binding() {
    let mock_server = MockServer::start().await;
    let mut formatter_provider = MockCredentialFormatterProvider::default();
    let mut key_provider = MockKeyProvider::default();

    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();

    let credential = generic_credential_did_with_holder_identifier();

    let interaction_data = HolderInteractionData {
        issuer_url: mock_server.uri(),
        credential_endpoint: format!("{}/credential", mock_server.uri()),
        token_endpoint: Some(format!("{}/token", mock_server.uri())),
        nonce_endpoint: Some(format!("{}/nonce", mock_server.uri())),
        notification_endpoint: Some(format!("{}/notification", mock_server.uri())),
        challenge_endpoint: None,
        grants: Some(Grants::PreAuthorizedCode(PreAuthorizedCodeGrant {
            pre_authorized_code: "code".to_string(),
            tx_code: None,
            authorization_server: None,
        })),
        access_token: None,
        batch_size: None,
        access_token_expires_at: None,
        refresh_token: None,
        token_endpoint_auth_methods_supported: None,
        client_attestation_pop_signing_alg_values_supported: None,
        refresh_token_expires_at: None,
        continue_issuance: None,
        issuer_display: None,
        protocol: "OPENID4VCI_FINAL1".to_string(),
        credential_request_encryption: None,
        credential_response_encryption: None,
        credential_configurations: vec![HolderCredentialConfiguration {
            credential_configuration_id: credential
                .schema
                .as_ref()
                .await
                .unwrap()
                .schema_id()
                .await
                .unwrap(),
            format: "jwt_vc_json".to_string(),
            cryptographic_binding_methods_supported: Some(vec!["jwk".to_string()]),
            credential_signing_alg_values_supported: None,
            proof_types_supported: None,
            credential_metadata: None,
            disclosure_policy: None,
            notification_id: None,
            credential_id: None,
        }],
    };

    let interaction = Interaction {
        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
            .unwrap()
            .into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        data: Some(serde_json::to_vec(&interaction_data).unwrap()),
        organisation: credential
            .schema
            .as_ref()
            .await
            .unwrap()
            .organisation
            .to_owned(),
        nonce_id: None,
        interaction_type: InteractionType::Issuance,
        expires_at: None,
        ecosystem: None,
        ecosystem_data: Default::default(),
    };

    Mock::given(method(Method::POST))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "access_token": "321",
                "token_type": "Bearer",
                "expires_in": crate::clock::now_utc().unix_timestamp() + 3600,
                "refresh_token": "321",
                "refresh_token_expires_in": crate::clock::now_utc().unix_timestamp() + 3600,
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
    formatter
        .expect_get_leeway()
        .return_const(Duration::seconds(1000));
    formatter.expect_parse_credential().returning({
        let clone = credential.clone();
        move |_, _, _| Ok(clone.clone())
    });

    let formatter = Arc::new(formatter);
    let formatter_clone = formatter.clone();
    formatter_provider
        .expect_get_credential_formatter()
        .with(eq(CredentialFormat::from("JWT")))
        .returning(move |_| Ok(formatter_clone.clone()));
    formatter_provider
        .expect_get_formatter_by_type()
        .returning(move |_| Some(("JWT".into(), formatter.clone())));

    let schema = credential.schema.as_ref().await.unwrap().to_owned();
    credential_schema_repository
        .expect_get_by_schema_id_and_organisation()
        .once()
        .returning(move |_, _| Ok(Some(schema.clone())));

    interaction_repository
        .expect_update_interaction()
        .once()
        .returning(move |_, _| Ok(()));

    key_provider
        .expect_get_signature_provider()
        .returning(move |_, _, _| {
            let mut mock_signature_provider = MockSignatureProvider::new();
            mock_signature_provider
                .expect_jose_alg()
                .returning(|| Ok("EdDSA".to_string()));

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

        storage.expect_generate().returning(|_, _, _| {
            Ok(StorageGeneratedKey {
                public_key: vec![],
                key_reference: Some(vec![]),
            })
        });

        Ok(Arc::new(storage))
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
        .returning(|_, request| {
            let_assert!(CreateLocalIdentifierRequestType::Key(key) = request);
            Ok(Identifier {
                data: IdentifierData::Key(Related::from(key)),
                ..dummy_identifier()
            })
        });

    let issuer_identifier = dummy_identifier();
    identifier_creator
        .expect_get_or_create_remote_identifier()
        .once()
        .with(
            always(),
            always(),
            eq(IdentifierName::PrefixForId(
                IdentifierRole::Issuer.to_string(),
            )),
            eq(true),
            always(),
            always(),
        )
        .return_once({
            let identifier = issuer_identifier.clone();
            move |_, _, _, _, _, _| Ok((identifier, RemoteIdentifierRelation::Key(dummy_key())))
        });

    let mut holder_wallet_unit_repository = MockInstanceRepository::new();
    holder_wallet_unit_repository
        .expect_get_by_role()
        .once()
        .return_once(|_, _| Ok(None));

    let openid_provider = setup_protocol(TestInputs {
        formatter_provider,
        key_provider,
        key_repository,
        identifier_creator,
        key_algorithm_provider,
        key_security_level_provider,
        credential_schema_repository,
        holder_wallet_unit_repository,
        interaction_repository,
        config: dummy_config(),
        ..Default::default()
    });

    let configuration_ids = configuration_ids(&interaction);
    let issuer_response = openid_provider
        .holder_accept_credential(interaction, None, None, configuration_ids)
        .await
        .unwrap()
        .issued
        .pop()
        .unwrap();

    assert_eq!(
        issuer_response.main_credential.serialized,
        Some("credential".into())
    );
    assert!(issuer_response.batch_items.is_empty());

    let create_credential = issuer_response.main_credential.credential;
    assert_eq!(create_credential.id, credential.id);
    assert_eq!(create_credential.r#type, CredentialType::Single);
    assert_eq!(
        create_credential.issuer_identifier.as_ref().unwrap().id(),
        issuer_identifier.id
    );
}

#[tokio::test]
async fn test_holder_accept_credential_batch_autogenerated_binding() {
    let mock_server = MockServer::start().await;
    let mut formatter_provider = MockCredentialFormatterProvider::default();
    let mut key_provider = MockKeyProvider::default();

    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();

    let credential = generic_credential_did();

    let interaction_data = HolderInteractionData {
        issuer_url: mock_server.uri(),
        credential_endpoint: format!("{}/credential", mock_server.uri()),
        token_endpoint: Some(format!("{}/token", mock_server.uri())),
        nonce_endpoint: Some(format!("{}/nonce", mock_server.uri())),
        notification_endpoint: Some(format!("{}/notification", mock_server.uri())),
        challenge_endpoint: None,
        grants: Some(Grants::PreAuthorizedCode(PreAuthorizedCodeGrant {
            pre_authorized_code: "code".to_string(),
            tx_code: None,
            authorization_server: None,
        })),
        access_token: None,
        batch_size: Some(2),
        access_token_expires_at: None,
        refresh_token: None,
        token_endpoint_auth_methods_supported: None,
        client_attestation_pop_signing_alg_values_supported: None,
        refresh_token_expires_at: None,
        continue_issuance: None,
        issuer_display: None,
        protocol: "OPENID4VCI_FINAL1".to_string(),
        credential_request_encryption: None,
        credential_response_encryption: None,
        credential_configurations: vec![HolderCredentialConfiguration {
            credential_configuration_id: credential
                .schema
                .as_ref()
                .await
                .unwrap()
                .schema_id()
                .await
                .unwrap(),
            format: "jwt_vc_json".to_string(),
            cryptographic_binding_methods_supported: Some(vec!["jwk".to_string()]),
            credential_signing_alg_values_supported: None,
            proof_types_supported: None,
            credential_metadata: None,
            disclosure_policy: None,
            notification_id: None,
            credential_id: None,
        }],
    };

    let interaction = Interaction {
        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
            .unwrap()
            .into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        data: Some(serde_json::to_vec(&interaction_data).unwrap()),
        organisation: credential
            .schema
            .as_ref()
            .await
            .unwrap()
            .organisation
            .to_owned(),
        nonce_id: None,
        interaction_type: InteractionType::Issuance,
        expires_at: None,
        ecosystem: None,
        ecosystem_data: Default::default(),
    };

    Mock::given(method(Method::POST))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "access_token": "321",
                "token_type": "Bearer",
                "expires_in": crate::clock::now_utc().unix_timestamp() + 3600,
                "refresh_token": "321",
                "refresh_token_expires_in": crate::clock::now_utc().unix_timestamp() + 3600,
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
                "credentials": [
                    { "credential": "credential1"},
                    { "credential": "credential2"}
                ],
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

    let holder_keys = Arc::new(Mutex::new(vec![]));

    let mut identifier_creator = MockIdentifierCreator::new();
    identifier_creator
        .expect_create_local_identifier()
        .times(2)
        .returning({
            let holder_keys = holder_keys.clone();
            move |_, request| {
                let_assert!(CreateLocalIdentifierRequestType::Key(key) = request);

                let mut guard = holder_keys.lock().unwrap();
                guard.push(key.clone());

                Ok(Identifier {
                    data: IdentifierData::Key(Related::from(key)),
                    ..dummy_identifier()
                })
            }
        });

    let issuer_identifier = credential
        .issuer_identifier
        .as_ref()
        .unwrap()
        .as_ref()
        .await
        .unwrap()
        .to_owned();
    identifier_creator
        .expect_get_or_create_remote_identifier()
        .times(2)
        .with(
            always(),
            always(),
            eq(IdentifierName::PrefixForId(
                IdentifierRole::Issuer.to_string(),
            )),
            eq(true),
            always(),
            always(),
        )
        .returning({
            let identifier = issuer_identifier.clone();
            move |_, _, _, _, _, _| {
                Ok((
                    identifier.clone(),
                    RemoteIdentifierRelation::Key(dummy_key()),
                ))
            }
        });

    let mut formatter = MockCredentialFormatter::new();
    formatter
        .expect_get_leeway()
        .return_const(Duration::seconds(1000));
    formatter.expect_parse_credential().times(2).returning({
        let clone = credential.clone();
        let holder_keys = holder_keys.clone();
        move |_, _, _| {
            let mut guard = holder_keys.lock().unwrap();
            let key = guard.pop().unwrap();

            Ok(Credential {
                id: Uuid::new_v4().into(),
                holder_identifier: Some(
                    Identifier {
                        data: IdentifierData::Key(Related::from(key)),
                        ..dummy_identifier()
                    }
                    .into(),
                ),
                ..clone.clone()
            })
        }
    });

    let formatter = Arc::new(formatter);
    let formatter_clone = formatter.clone();
    formatter_provider
        .expect_get_credential_formatter()
        .with(eq(CredentialFormat::from("JWT")))
        .returning(move |_| Ok(formatter_clone.clone()));
    formatter_provider
        .expect_get_formatter_by_type()
        .returning(move |_| Some(("JWT".into(), formatter.clone())));

    let schema = credential.schema.as_ref().await.unwrap().to_owned();
    credential_schema_repository
        .expect_get_by_schema_id_and_organisation()
        .once()
        .returning(move |_, _| Ok(Some(schema.clone())));

    interaction_repository
        .expect_update_interaction()
        .once()
        .returning(move |_, _| Ok(()));

    key_provider
        .expect_get_signature_provider()
        .returning(move |_, _, _| {
            let mut mock_signature_provider = MockSignatureProvider::new();
            mock_signature_provider
                .expect_jose_alg()
                .returning(|| Ok("EdDSA".to_string()));

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

        storage.expect_generate().returning(|_, _, _| {
            Ok(StorageGeneratedKey {
                public_key: vec![],
                key_reference: Some(vec![]),
            })
        });

        Ok(Arc::new(storage))
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
        .times(2)
        .returning(|key| Ok(key.id));

    let mut holder_wallet_unit_repository = MockInstanceRepository::new();
    holder_wallet_unit_repository
        .expect_get_by_role()
        .once()
        .return_once(|_, _| Ok(None));

    let openid_provider = setup_protocol(TestInputs {
        formatter_provider,
        key_provider,
        key_repository,
        identifier_creator,
        key_algorithm_provider,
        key_security_level_provider,
        credential_schema_repository,
        holder_wallet_unit_repository,
        interaction_repository,
        config: dummy_config(),
        ..Default::default()
    });

    let configuration_ids = configuration_ids(&interaction);
    let issuer_response = openid_provider
        .holder_accept_credential(interaction, None, None, configuration_ids)
        .await
        .unwrap()
        .issued
        .pop()
        .unwrap();
    let main_credential = &issuer_response.main_credential;
    assert_eq!(
        main_credential.credential.r#type,
        CredentialType::BatchParent
    );
    assert_eq!(main_credential.serialized, None);

    let credentials = &issuer_response.batch_items;
    assert_eq!(credentials.len(), 2);
    assert_eq!(credentials[0].serialized, Some("credential1".into()));
    assert_eq!(credentials[1].serialized, Some("credential2".into()));
    assert_eq!(credentials[0].credential.r#type, CredentialType::BatchItem);
    assert_eq!(credentials[1].credential.r#type, CredentialType::BatchItem);
    assert_eq!(
        credentials[0]
            .credential
            .issuer_identifier
            .as_ref()
            .unwrap()
            .id(),
        issuer_identifier.id
    );
    assert_eq!(
        credentials[1]
            .credential
            .issuer_identifier
            .as_ref()
            .unwrap()
            .id(),
        issuer_identifier.id
    );
}

#[tokio::test]
async fn test_holder_accept_credential_batch_manual_binding() {
    let mock_server = MockServer::start().await;
    let mut formatter_provider = MockCredentialFormatterProvider::default();
    let mut key_provider = MockKeyProvider::default();

    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();

    let key = Key {
        storage_type: "INTERNAL".to_string(),
        ..dummy_key()
    };
    let mut credential = generic_credential_did_with_holder_identifier();
    credential
        .holder_identifier
        .as_mut()
        .unwrap()
        .as_mut()
        .await
        .unwrap()
        .data = IdentifierData::Key(Related::from(key.clone()));

    let credential_configuration_id = credential
        .schema
        .as_ref()
        .await
        .unwrap()
        .schema_id()
        .await
        .unwrap();
    let interaction_data = HolderInteractionData {
        issuer_url: mock_server.uri(),
        credential_endpoint: format!("{}/credential", mock_server.uri()),
        token_endpoint: Some(format!("{}/token", mock_server.uri())),
        nonce_endpoint: Some(format!("{}/nonce", mock_server.uri())),
        notification_endpoint: Some(format!("{}/notification", mock_server.uri())),
        challenge_endpoint: None,
        grants: Some(Grants::PreAuthorizedCode(PreAuthorizedCodeGrant {
            pre_authorized_code: "code".to_string(),
            tx_code: None,
            authorization_server: None,
        })),
        access_token: None,
        batch_size: Some(2),
        access_token_expires_at: None,
        refresh_token: None,
        token_endpoint_auth_methods_supported: None,
        client_attestation_pop_signing_alg_values_supported: None,
        refresh_token_expires_at: None,
        issuer_display: None,
        continue_issuance: None,
        protocol: "OPENID4VCI_FINAL1".to_string(),
        credential_request_encryption: None,
        credential_response_encryption: None,
        credential_configurations: vec![HolderCredentialConfiguration {
            credential_configuration_id: credential_configuration_id.clone(),
            format: "jwt_vc_json".to_string(),
            cryptographic_binding_methods_supported: Some(vec!["jwk".to_string()]),
            credential_signing_alg_values_supported: None,
            proof_types_supported: None,
            credential_metadata: None,
            disclosure_policy: None,
            notification_id: None,
            credential_id: None,
        }],
    };

    let interaction = Interaction {
        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
            .unwrap()
            .into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        data: Some(serde_json::to_vec(&interaction_data).unwrap()),
        organisation: credential
            .schema
            .as_ref()
            .await
            .unwrap()
            .organisation
            .to_owned(),
        nonce_id: None,
        interaction_type: InteractionType::Issuance,
        expires_at: None,
        ecosystem: None,
        ecosystem_data: Default::default(),
    };

    Mock::given(method(Method::POST))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "access_token": "321",
                "token_type": "Bearer",
                "expires_in": crate::clock::now_utc().unix_timestamp() + 3600,
                "refresh_token": "321",
                "refresh_token_expires_in": crate::clock::now_utc().unix_timestamp() + 3600,
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
        .and({
            let credential_configuration_id = credential_configuration_id.clone();
            move |request: &wiremock::Request| {
                let request: CredentialRequest = request.body_json().unwrap();
                let CredentialRequestIdentifier::CredentialConfigurationId(config_id) =
                    &request.credential
                else {
                    panic!("invalid request: {request:?}");
                };
                assert_eq!(config_id, &credential_configuration_id);

                let Proofs::Jwt(proofs) = &request.proofs.as_ref().unwrap() else {
                    panic!("invalid request: {request:?}");
                };
                assert_eq!(proofs.len(), 1);

                true
            }
        })
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "credentials": [{ "credential": "credential1"}],
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
    formatter
        .expect_get_leeway()
        .return_const(Duration::seconds(1000));
    formatter.expect_parse_credential().times(1).returning({
        let clone = credential.clone();
        move |_, _, _| Ok(clone.clone())
    });

    let formatter = Arc::new(formatter);
    let formatter_clone = formatter.clone();
    formatter_provider
        .expect_get_credential_formatter()
        .with(eq(CredentialFormat::from("JWT")))
        .returning(move |_| Ok(formatter_clone.clone()));
    formatter_provider
        .expect_get_formatter_by_type()
        .returning(move |_| Some(("JWT".into(), formatter.clone())));

    let schema = credential.schema.as_ref().await.unwrap().to_owned();
    credential_schema_repository
        .expect_get_by_schema_id_and_organisation()
        .once()
        .returning(move |_, _| Ok(Some(schema.clone())));

    interaction_repository
        .expect_update_interaction()
        .once()
        .returning(move |_, _| Ok(()));

    key_provider
        .expect_get_signature_provider()
        .returning(move |_, _, _| {
            let mut mock_signature_provider = MockSignatureProvider::new();
            mock_signature_provider
                .expect_jose_alg()
                .returning(|| Ok("EdDSA".to_string()));

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

        storage.expect_generate().returning(|_, _, _| {
            Ok(StorageGeneratedKey {
                public_key: vec![],
                key_reference: Some(vec![]),
            })
        });

        Ok(Arc::new(storage))
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
        .returning(|| {
            let mut security = MockKeySecurityLevel::new();
            security
                .expect_get_key_storages()
                .return_const(vec!["INTERNAL".to_string()]);
            vec![(KeySecurityLevelType::Basic, Arc::new(security))]
        });

    let mut identifier_creator = MockIdentifierCreator::new();
    let issuer_identifier = dummy_identifier();
    identifier_creator
        .expect_get_or_create_remote_identifier()
        .times(1)
        .with(
            always(),
            always(),
            eq(IdentifierName::PrefixForId(
                IdentifierRole::Issuer.to_string(),
            )),
            eq(true),
            always(),
            always(),
        )
        .returning({
            let identifier = issuer_identifier.clone();
            move |_, _, _, _, _, _| {
                Ok((
                    identifier.clone(),
                    RemoteIdentifierRelation::Key(dummy_key()),
                ))
            }
        });

    let mut holder_wallet_unit_repository = MockInstanceRepository::new();
    holder_wallet_unit_repository
        .expect_get_by_role()
        .once()
        .return_once(|_, _| Ok(None));

    let openid_provider = setup_protocol(TestInputs {
        formatter_provider,
        key_provider,
        identifier_creator,
        key_algorithm_provider,
        key_security_level_provider,
        credential_schema_repository,
        holder_wallet_unit_repository,
        interaction_repository,
        config: dummy_config(),
        ..Default::default()
    });

    let configuration_ids = configuration_ids(&interaction);
    let issuer_response = openid_provider
        .holder_accept_credential(
            interaction,
            Some(HolderBindingInput {
                identifier: Identifier {
                    data: IdentifierData::Key(Related::from(key.clone())),
                    ..dummy_identifier()
                },
                key,
            }),
            None,
            configuration_ids,
        )
        .await
        .unwrap()
        .issued
        .pop()
        .unwrap();

    assert_eq!(
        issuer_response.main_credential.serialized,
        Some("credential1".into())
    );

    assert!(issuer_response.batch_items.is_empty());
    let main_credential = issuer_response.main_credential.credential;
    assert_eq!(
        main_credential.issuer_identifier.as_ref().unwrap().id(),
        issuer_identifier.id
    );
}

#[tokio::test]
async fn test_holder_reject_credential() {
    let mock_server = MockServer::start().await;
    let mut did_method_provider = MockDidMethodProvider::default();
    let mut key_algorithm_provider = MockKeyAlgorithmProvider::default();
    let mut interaction_repository = MockInteractionRepository::default();

    let encryption = SecretSlice::from(vec![0; 32]);

    let credential = {
        let mut credential = generic_credential_did();
        credential.state = CredentialStateEnum::Accepted;
        credential.key = Some(dummy_key().into());

        let interaction_data = HolderInteractionData {
            issuer_url: mock_server.uri(),
            credential_endpoint: format!("{}/credential", mock_server.uri()),
            token_endpoint: Some(format!("{}/token", mock_server.uri())),
            nonce_endpoint: Some(format!("{}/nonce", mock_server.uri())),
            notification_endpoint: Some(format!("{}/notification", mock_server.uri())),
            challenge_endpoint: None,
            grants: Some(Grants::PreAuthorizedCode(PreAuthorizedCodeGrant {
                pre_authorized_code: "code".to_string(),
                tx_code: None,
                authorization_server: None,
            })),
            batch_size: None,
            access_token: None,
            access_token_expires_at: None,
            refresh_token: Some(
                encrypt_data(&SecretSlice::from(vec![0; 32]), &encryption).unwrap(),
            ),
            refresh_token_expires_at: None,
            token_endpoint_auth_methods_supported: None,
            client_attestation_pop_signing_alg_values_supported: None,
            continue_issuance: None,
            issuer_display: None,
            protocol: "OPENID4VCI_FINAL1".to_string(),
            credential_request_encryption: None,
            credential_response_encryption: None,
            credential_configurations: vec![HolderCredentialConfiguration {
                credential_configuration_id: credential
                    .schema
                    .as_ref()
                    .await
                    .unwrap()
                    .schema_id()
                    .await
                    .unwrap(),
                format: "jwt_vc_json".to_string(),
                cryptographic_binding_methods_supported: None,
                credential_signing_alg_values_supported: None,
                proof_types_supported: None,
                credential_metadata: None,
                disclosure_policy: None,
                notification_id: Some("notification_id".to_string()),
                credential_id: None,
            }],
        };

        credential.interaction = Some(
            Interaction {
                id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
                    .unwrap()
                    .into(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                data: Some(serde_json::to_vec(&interaction_data).unwrap()),
                organisation: dummy_organisation(None).into(),
                nonce_id: None,
                interaction_type: InteractionType::Issuance,
                expires_at: None,
                ecosystem: None,
                ecosystem_data: Default::default(),
            }
            .into(),
        );

        credential
    };

    Mock::given(method(Method::POST))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "access_token": "321",
                "token_type": "Bearer",
                "expires_in": crate::clock::now_utc().unix_timestamp() + 3600,
                "refresh_token": "321",
                "refresh_token_expires_in": crate::clock::now_utc().unix_timestamp() + 3600,
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
                .returning(|| "ES256".to_string());

            Ok(Arc::new(algorithm))
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
        Ok((Arc::new(method), crate::config::core_config::DidType::Key))
    });

    interaction_repository
        .expect_update_interaction()
        .once()
        .returning(move |_, _| Ok(()));

    let mut holder_wallet_unit_repository = MockInstanceRepository::new();
    holder_wallet_unit_repository
        .expect_get_by_role()
        .once()
        .return_once(|_, _| Ok(None));

    let openid_provider = setup_protocol(TestInputs {
        did_method_provider,
        key_algorithm_provider,
        interaction_repository,
        holder_wallet_unit_repository,
        config: dummy_config(),
        ..Default::default()
    });

    openid_provider
        .holder_reject_credential(credential)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_handle_invitation_credential_by_ref_with_did_success() {
    inner_test_handle_invitation_credential_by_ref_success(
        generic_credential_did(),
        Some("did:example:123".to_string()),
    )
    .await;
}

#[tokio::test]
async fn test_handle_invitation_credential_by_ref_without_did_success() {
    inner_test_handle_invitation_credential_by_ref_success(generic_credential_did(), None).await;
}

async fn inner_test_handle_invitation_credential_by_ref_success(
    credential: Credential,
    issuer_did: Option<String>,
) {
    let mock_server = MockServer::start().await;
    let issuer_url = Url::from_str(&mock_server.uri()).unwrap();

    let credential_schema_id = credential.schema.id();
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
            )),
            eq("application/json"))
            .once()
            .returning({
                    let credential_issuer = credential_issuer.clone();
                    move |_,_| Ok(json!({
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

    // signed metadata not supported
    metadata_cache
        .expect_get()
        .with(always(), eq("application/jwt"))
        .returning(|_, _| {
            Err(crate::proto::http_client::Error::Timeout
                .error_while("test")
                .into())
        });
    metadata_cache
        .expect_get()
        .with(eq(format!(
            "{issuer_url}.well-known/openid-credential-issuer/ssi/openid4vci/final-1.0/{credential_schema_id}"
        )),
    eq("application/json"))
        .once()
        .returning(move |_,_| Ok(json!({
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
    let mut interaction_repository = MockInteractionRepository::default();
    interaction_repository
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
        interaction_repository,
        ..Default::default()
    });
    let result = protocol
        .holder_handle_invitation(url, dummy_organisation(None), None)
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

fn unsigned_metadata_offer_url() -> Url {
    let credential_offer = json!({
        "credential_issuer": "http://issuer.url/issuer",
        "credential_configuration_ids": ["doctype"],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": { "pre-authorized_code": "c322aa7f-9803-410d-b891-939b279fb965" }
        }
    });
    Url::parse_with_params(
        "openid-credential-offer://",
        &[("credential_offer", credential_offer.to_string())],
    )
    .unwrap()
}

#[tokio::test]
async fn test_handle_invitation_falls_back_to_unsigned_metadata_when_trust_optional() {
    let mut metadata_cache = MockOpenIDMetadataFetcher::new();
    metadata_cache
        .expect_get()
        .with(
            eq("http://issuer.url/.well-known/openid-credential-issuer/issuer"),
            eq("application/jwt"),
        )
        .once()
        .returning(|_, _| {
            Err(serde_json::from_slice::<Value>(b"not a jwt")
                .unwrap_err()
                .into())
        });
    metadata_cache
        .expect_get()
        .with(
            eq("http://issuer.url/.well-known/openid-credential-issuer/issuer"),
            eq("application/json"),
        )
        .once()
        .returning(|_, _| {
            Ok(json!({
                "credential_endpoint": "http://issuer.url/issuer/credential",
                "credential_issuer": "http://issuer.url/issuer",
                "nonce_endpoint": "http://issuer.url/issuer/nonce",
                "credential_configurations_supported": {
                    "doctype": {
                        "credential_definition": {
                            "type": ["VerifiableCredential"],
                            "credentialSubject": {
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
            .into_bytes())
        });
    metadata_cache
        .expect_get()
        .with(
            eq("http://issuer.url/.well-known/oauth-authorization-server/issuer"),
            eq("application/json"),
        )
        .once()
        .returning(|_, _| {
            Ok(json!({
                "issuer": "http://issuer.url/issuer",
                "grant_types_supported": ["urn:ietf:params:oauth:grant-type:pre-authorized_code"],
                "response_types_supported": ["token"],
                "token_endpoint": "http://issuer.url/issuer/token"
            })
            .to_string()
            .into_bytes())
        });

    let mut interaction_repository = MockInteractionRepository::default();
    interaction_repository
        .expect_create_interaction()
        .once()
        .returning(|i: Interaction| Ok(i.id));

    let protocol = setup_protocol(TestInputs {
        metadata_cache,
        interaction_repository,
        ..Default::default()
    });

    let result = protocol
        .holder_handle_invitation(
            unsigned_metadata_offer_url(),
            dummy_organisation(None),
            None,
        )
        .await
        .unwrap();
    assert!(matches!(result, InvitationResponseEnum::Credential { .. }));
}

#[tokio::test]
async fn test_handle_invitation_requires_signed_metadata_when_trust_mandatory() {
    // no "application/json" fallback expected, signed metadata is required
    let mut metadata_cache = MockOpenIDMetadataFetcher::new();
    metadata_cache
        .expect_get()
        .with(
            eq("http://issuer.url/.well-known/openid-credential-issuer/issuer"),
            eq("application/jwt"),
        )
        .once()
        .returning(|_, _| {
            Err(serde_json::from_slice::<Value>(b"not a jwt")
                .unwrap_err()
                .into())
        });

    let protocol = setup_protocol(TestInputs {
        metadata_cache,
        ..Default::default()
    });

    let organisation = Organisation {
        configuration: OrganisationConfiguration {
            enforce_ecosystem_as_holder: true,
            ..Default::default()
        },
        ..dummy_organisation(None)
    };

    protocol
        .holder_handle_invitation(unsigned_metadata_offer_url(), organisation, None)
        .await
        .unwrap_err();
}

#[tokio::test]
async fn test_handle_invitation_signed_metadata() {
    let mut client = MockHttpClient::new();

    let credential_offer = json!({
        "credential_issuer": "http://issuer.url",
        "credential_configuration_ids" : ["doctype"],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": { "pre-authorized_code": "c322aa7f-9803-410d-b891-939b279fb965" }
        }
    });

    client
        .expect_get()
        .with(eq("http://issuer.url/offer"))
        .once()
        .return_once(|url| {
            let mut client = MockHttpClient::new();
            client
                .expect_send()
                .once()
                .return_once(move |url, body, headers, method, timeout| {
                    Ok(Response {
                        body: credential_offer.to_string().as_bytes().to_vec(),
                        headers: Default::default(),
                        status: StatusCode(200),
                        request: Request {
                            body,
                            headers: headers.unwrap_or_default(),
                            method,
                            url: url.to_string(),
                            timeout,
                        },
                    })
                });

            RequestBuilder::new(
                Arc::new(client),
                crate::proto::http_client::Method::Get,
                url,
            )
        });

    let mut metadata_cache = MockOpenIDMetadataFetcher::new();

    let access_certificate = "MIIDDDCCArKgAwIBAgIUG8SguUrbgpJUvd6v+07Sp8utLfQwCgYIKoZIzj0EAwIwXDEeMBwGA1UEAwwVUElEIElzc3VlciBDQSAtIFVUIDAyMS0wKwYDVQQKDCRFVURJIFdhbGxldCBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xCzAJBgNVBAYTAlVUMB4XDTI1MDQxMDA2NDU1OFoXDTI3MDQxMDA2NDU1N1owVzEdMBsGA1UEAwwURVVESSBSZW1vdGUgVmVyaWZpZXIxCjAIBgNVBAUTATExHTAbBgNVBAoMFEVVREkgUmVtb3RlIFZlcmlmaWVyMQswCQYDVQQGEwJVVDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOciV42mIT8nQMAN8kW9CHNUTYwkieem5hl1QsLf62kEbbZh6wul5iL28g/A3ZqcTX9XoLnw/nvJ8/HRp3+95eKjggFVMIIBUTAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFGLHlEcovQ+iFiCnmsJJlETxAdPHMDkGA1UdEQQyMDCBEm5vLXJlcGx5QGV1ZGl3LmRldoIadmVyaWZpZXItYmFja2VuZC5ldWRpdy5kZXYwEgYDVR0lBAswCQYHKIGMXQUBBjBDBgNVHR8EPDA6MDigNqA0hjJodHRwczovL3ByZXByb2QucGtpLmV1ZGl3LmRldi9jcmwvcGlkX0NBX1VUXzAyLmNybDAdBgNVHQ4EFgQUgAh9KsoYXYK8jndUbFQEtfDsHjYwDgYDVR0PAQH/BAQDAgeAMF0GA1UdEgRWMFSGUmh0dHBzOi8vZ2l0aHViLmNvbS9ldS1kaWdpdGFsLWlkZW50aXR5LXdhbGxldC9hcmNoaXRlY3R1cmUtYW5kLXJlZmVyZW5jZS1mcmFtZXdvcmswCgYIKoZIzj0EAwIDSAAwRQIgDFCgyEjGnJS25n/FfdP7HX0elz7C2q4uUQ/7Zcrl0QYCIQC/rrJpQ5sF1O4aiHejIPPLuO3JjdrLJPZSA+FQH+eIrA==";
    let registration_certificate = "registration-certificate";
    let jwt = {
        let header = json!({
            "typ": "openidvci-issuer-metadata+jwt",
            "alg" : "ES256",
            "x5c": [access_certificate]
        });
        let payload = json!({
            "credential_endpoint": "http://issuer.url/credential",
            "credential_issuer": "http://issuer.url",
            "nonce_endpoint": "http://issuer.url/nonce",
            "credential_configurations_supported": {
                "doctype": {
                    "format": "mso_mdoc",
                    "doctype": "doctype",
                    "disclosure_policy": {
                        "id": "policy-id",
                        "policy": "none",
                        "url": "https://policy.url"
                    }
                }
            },
            "issuer_info": [{
                "format": "registration_cert",
                "data": registration_certificate
            }]
        });

        let header =
            Base64UrlSafeNoPadding::encode_to_string(header.to_string().as_bytes()).unwrap();
        let payload =
            Base64UrlSafeNoPadding::encode_to_string(payload.to_string().as_bytes()).unwrap();
        format!("{header}.{payload}.c2lnbmF0dXJl")
    };

    metadata_cache
        .expect_get()
        .with(
            eq("http://issuer.url/.well-known/openid-credential-issuer"),
            eq("application/jwt"),
        )
        .once()
        .return_once(move |_, _| Ok(jwt.as_bytes().to_vec()));

    metadata_cache
        .expect_get()
        .with(
            eq("http://issuer.url/.well-known/oauth-authorization-server"),
            eq("application/json"),
        )
        .once()
        .return_once(|_, _| {
            Ok(json!({
                "authorization_endpoint": "http://issuer.url/authorize",
                "grant_types_supported": [
                    "urn:ietf:params:oauth:grant-type:pre-authorized_code"
                ],
                "id_token_signing_alg_values_supported": [],
                "issuer": "http://issuer.url",
                "jwks_uri": "http://issuer.url/jwks",
                "token_endpoint": "http://issuer.url/token",
                "response_types_supported": [
                    "token"
                ],
                "subject_types_supported": [
                    "public"
                ]
            })
            .to_string()
            .as_bytes()
            .to_vec())
        });

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_jose_alg()
        .with(eq("ES256"))
        .once()
        .return_once(|_| {
            let mut key_algorithm = MockKeyAlgorithm::new();
            key_algorithm
                .expect_algorithm_type()
                .once()
                .return_const(KeyAlgorithmType::Ecdsa);
            Some((KeyAlgorithmType::Ecdsa, Arc::new(key_algorithm)))
        });

    let mut certificate_validator = MockCertificateValidator::new();
    certificate_validator
        .expect_parse_pem_chain()
        .once()
        .return_once(|_, _| {
            let mut signature_handle = MockSignaturePublicKeyHandle::new();
            signature_handle
                .expect_verify()
                .once()
                .return_once(|_, _| Ok(()));

            Ok(ParsedCertificate {
                attributes: CertificateX509AttributesDTO {
                    serial_number: "test".to_string(),
                    not_before: crate::clock::now_utc(),
                    not_after: crate::clock::now_utc(),
                    issuer: "Test Issuer".to_string(),
                    subject: "Test Subject".to_string(),
                    fingerprint: "test".to_string(),
                    extensions: vec![],
                },
                subject_common_name: Some("Test".to_string()),
                subject_key_identifier: None,
                public_key: KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(Arc::new(
                    signature_handle,
                ))),
            })
        });

    let mut interaction_repository = MockInteractionRepository::default();
    interaction_repository
        .expect_create_interaction()
        .withf(move |interaction| {
            let data: HolderInteractionData =
                serde_json::from_slice(interaction.data.as_ref().unwrap()).unwrap();

            assert_eq!(
                data.credential_configurations[0]
                    .disclosure_policy
                    .clone()
                    .unwrap(),
                DisclosurePolicy {
                    id: "policy-id".to_string(),
                    policy: PolicyType::None,
                    description: None,
                    url: Some("https://policy.url".to_string()),
                }
            );
            true
        })
        .once()
        .return_once(|_| Ok(Uuid::new_v4().into()));

    let protocol = setup_protocol(TestInputs {
        metadata_cache,
        key_algorithm_provider,
        certificate_validator,
        interaction_repository,
        client: Some(client),
        params: Some(test_params("openid-credential-offer")),
        ..Default::default()
    });

    let url = Url::parse(
        "openid-credential-offer://?credential_offer_uri=http%3A%2F%2Fissuer.url%2Foffer",
    )
    .unwrap();
    let result = protocol
        .holder_handle_invitation(url, dummy_organisation(None), None)
        .await
        .unwrap();

    assert2::assert!(
        let InvitationResponseEnum::Credential {..} = result
    );
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
    let credential = generic_credential_did();

    let credential_schema_id = credential.schema.id();
    let credential_issuer =
        format!("http://issuer/ssi/openid4vci/final-1.0/{credential_schema_id}");

    let mut metadata_cache = MockOpenIDMetadataFetcher::new();

    metadata_cache
        .expect_get()
        .with(eq(format!("http://issuer/.well-known/oauth-authorization-server/ssi/openid4vci/final-1.0/{credential_schema_id}")),
    eq("application/json"))
        .once()
        .returning({
            let credential_issuer = credential_issuer.clone();
            move |_,_| {
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

    // signed metadata not supported
    metadata_cache
        .expect_get()
        .with(always(), eq("application/jwt"))
        .returning(|_, _| {
            Err(crate::proto::http_client::Error::Timeout
                .error_while("test")
                .into())
        });
    metadata_cache
        .expect_get()
        .with(eq(format!(
            "http://issuer/.well-known/openid-credential-issuer/ssi/openid4vci/final-1.0/{credential_schema_id}"
        )),
        eq("application/json"))
        .once()
        .returning({
            let credential_issuer = credential_issuer.clone();
            move |_,_| {
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

    let capture_interaction_id = Arc::new(Mutex::new(None));
    let mut interaction_repository = MockInteractionRepository::new();
    interaction_repository
        .expect_create_interaction()
        .times(1)
        .returning({
            let capture_interaction_id = capture_interaction_id.clone();
            move |i: Interaction| {
                let mut guard = capture_interaction_id.lock().unwrap();
                *guard = Some(i.id);
                Ok(i.id)
            }
        });

    let protocol = setup_protocol(TestInputs {
        metadata_cache,
        interaction_repository,
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
        )
        .await
        .unwrap();

    assert_eq!(
        capture_interaction_id.lock().unwrap().unwrap(),
        result.interaction_id
    );
}

#[tokio::test]
async fn test_can_handle_issuance_success_with_custom_url_scheme() {
    let url_scheme = "my-custom-scheme";

    let protocol = setup_protocol(TestInputs {
        params: Some(test_params(url_scheme)),
        ..Default::default()
    });

    let test_url = format!(
        "{url_scheme}://?credential_offer_uri=http%3A%2F%2Fissuer.com%2Fssi%2Foidc-issuer%2Fv1%2Fc322aa7f-9803-410d-b891-939b279fb965%2Foffer%2Fc322aa7f-9803-410d-b891-939b279fb965",
    );
    assert!(protocol.holder_can_handle(&test_url.parse().unwrap()))
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
    assert!(!protocol.holder_can_handle(&test_url.parse().unwrap()))
}

#[tokio::test]
async fn test_generate_share_credentials_custom_scheme() {
    let mut credential = generic_credential_did();
    credential.interaction = None;

    let url_scheme = "my-custom-scheme";
    let protocol = setup_protocol(TestInputs {
        params: Some(test_params(url_scheme)),
        ..Default::default()
    });

    let result = protocol.issuer_share_credential(&credential).await.unwrap();
    assert!(result.url.starts_with(url_scheme));
}

#[tokio::test]
async fn test_holder_accept_credential_fails_without_wallet_unit_id_when_key_attestation_required()
{
    let credential = generic_credential_did();

    let mut proof_types = IndexMap::new();
    proof_types.insert(
        "jwt".to_string(),
        ProofTypeSupported {
            proof_signing_alg_values_supported: vec!["ES256".to_string()],
            key_attestations_required: Some(KeyAttestationsRequired {
                key_storage: vec![KeyStorageSecurityLevel::Basic],
                user_authentication: vec![],
            }),
        },
    );

    let interaction_data = HolderInteractionData {
        issuer_url: "http://issuer".to_string(),
        credential_endpoint: "http://issuer/credential".to_string(),
        token_endpoint: Some("http://issuer/token".to_string()),
        nonce_endpoint: Some("http://issuer/nonce".to_string()),
        notification_endpoint: None,
        challenge_endpoint: None,
        grants: Some(Grants::PreAuthorizedCode(PreAuthorizedCodeGrant {
            pre_authorized_code: "code".to_string(),
            tx_code: None,
            authorization_server: None,
        })),
        batch_size: None,
        access_token: None,
        access_token_expires_at: None,
        refresh_token: None,
        refresh_token_expires_at: None,
        token_endpoint_auth_methods_supported: None,
        client_attestation_pop_signing_alg_values_supported: None,
        continue_issuance: None,
        issuer_display: None,
        protocol: "OPENID4VCI_FINAL1".to_string(),
        credential_request_encryption: None,
        credential_response_encryption: None,
        credential_configurations: vec![HolderCredentialConfiguration {
            credential_configuration_id: credential
                .schema
                .as_ref()
                .await
                .unwrap()
                .schema_id()
                .await
                .unwrap(),
            format: "jwt_vc_json".to_string(),
            cryptographic_binding_methods_supported: None,
            credential_signing_alg_values_supported: None,
            proof_types_supported: Some(proof_types),
            credential_metadata: None,
            disclosure_policy: None,
            notification_id: None,
            credential_id: None,
        }],
    };

    let interaction = Interaction {
        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
            .unwrap()
            .into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        data: Some(serde_json::to_vec(&interaction_data).unwrap()),
        organisation: credential
            .schema
            .as_ref()
            .await
            .unwrap()
            .organisation
            .to_owned(),
        nonce_id: None,
        interaction_type: InteractionType::Issuance,
        expires_at: None,
        ecosystem: None,
        ecosystem_data: Default::default(),
    };

    let mut key_security_level_provider = MockKeySecurityLevelProvider::new();
    key_security_level_provider
        .expect_get_from_type()
        .returning(|_| {
            let mut security = MockKeySecurityLevel::new();
            security
                .expect_get_key_storages()
                .return_const(vec!["INTERNAL".to_string()]);
            security.expect_get_priority().return_const(0u64);
            security
                .expect_get_capabilities()
                .returning(|| KeySecurityLevelCapabilities {
                    openid_security_level: vec![KeyStorageSecurityLevel::Basic],
                });
            Ok(Arc::new(security))
        });

    let mut holder_wallet_unit_repository = MockInstanceRepository::new();
    holder_wallet_unit_repository
        .expect_get_by_role()
        .once()
        .return_once(|_, _| Ok(None));

    let openid_provider = setup_protocol(TestInputs {
        key_security_level_provider,
        holder_wallet_unit_repository,
        config: dummy_config(),
        ..Default::default()
    });

    let key = Key {
        storage_type: "INTERNAL".to_string(),
        ..dummy_key()
    };
    let configuration_ids = configuration_ids(&interaction);
    let result = openid_provider
        .holder_accept_credential(
            interaction,
            Some(HolderBindingInput {
                identifier: Identifier {
                    data: IdentifierData::Key(Related::from(key.clone())),
                    ..dummy_identifier()
                },
                key,
            }),
            None,
            configuration_ids,
        )
        .await;

    let err = result.unwrap_err();
    assert!(
        err.to_string()
            .contains("key storage attestation requires active holder wallet unit id"),
    );
}

#[tokio::test]
async fn test_holder_accept_credential_succeeds_with_wallet_unit_id_when_key_attestation_required()
{
    let mock_server = MockServer::start().await;
    let mut formatter_provider = MockCredentialFormatterProvider::default();
    let mut key_provider = MockKeyProvider::default();

    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();

    let key = Key {
        storage_type: "INTERNAL".to_string(),
        ..dummy_key()
    };
    let mut credential = generic_credential_did_with_holder_identifier();
    credential
        .holder_identifier
        .as_mut()
        .unwrap()
        .as_mut()
        .await
        .unwrap()
        .data = IdentifierData::Key(Related::from(key.clone()));

    let mut proof_types = IndexMap::new();
    proof_types.insert(
        "jwt".to_string(),
        ProofTypeSupported {
            proof_signing_alg_values_supported: vec!["ES256".to_string()],
            key_attestations_required: Some(KeyAttestationsRequired {
                key_storage: vec![KeyStorageSecurityLevel::Basic],
                user_authentication: vec![],
            }),
        },
    );

    let interaction_data = HolderInteractionData {
        issuer_url: mock_server.uri(),
        credential_endpoint: format!("{}/credential", mock_server.uri()),
        token_endpoint: Some(format!("{}/token", mock_server.uri())),
        nonce_endpoint: Some(format!("{}/nonce", mock_server.uri())),
        notification_endpoint: Some(format!("{}/notification", mock_server.uri())),
        challenge_endpoint: None,
        grants: Some(Grants::PreAuthorizedCode(PreAuthorizedCodeGrant {
            pre_authorized_code: "code".to_string(),
            tx_code: None,
            authorization_server: None,
        })),
        batch_size: None,
        access_token: None,
        access_token_expires_at: None,
        refresh_token: None,
        refresh_token_expires_at: None,
        token_endpoint_auth_methods_supported: None,
        client_attestation_pop_signing_alg_values_supported: None,
        continue_issuance: None,
        issuer_display: None,
        protocol: "OPENID4VCI_FINAL1".to_string(),
        credential_request_encryption: None,
        credential_response_encryption: None,
        credential_configurations: vec![HolderCredentialConfiguration {
            credential_configuration_id: credential
                .schema
                .as_ref()
                .await
                .unwrap()
                .schema_id()
                .await
                .unwrap(),
            format: "jwt_vc_json".to_string(),
            cryptographic_binding_methods_supported: Some(vec!["jwk".to_string()]),
            credential_signing_alg_values_supported: None,
            proof_types_supported: Some(proof_types),
            credential_metadata: None,
            disclosure_policy: None,
            notification_id: None,
            credential_id: None,
        }],
    };

    let interaction = Interaction {
        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
            .unwrap()
            .into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        data: Some(serde_json::to_vec(&interaction_data).unwrap()),
        organisation: credential
            .schema
            .as_ref()
            .await
            .unwrap()
            .organisation
            .to_owned(),
        nonce_id: None,
        interaction_type: InteractionType::Issuance,
        expires_at: None,
        ecosystem: None,
        ecosystem_data: Default::default(),
    };

    Mock::given(method(Method::POST))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "access_token": "321",
                "token_type": "Bearer",
                "expires_in": crate::clock::now_utc().unix_timestamp() + 3600,
                "refresh_token": "321",
                "refresh_token_expires_in": crate::clock::now_utc().unix_timestamp() + 3600,
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
    formatter
        .expect_get_leeway()
        .return_const(Duration::seconds(1000));
    formatter.expect_parse_credential().returning({
        let clone = credential.clone();
        move |_, _, _| Ok(clone.clone())
    });

    let formatter = Arc::new(formatter);
    let formatter_clone = formatter.clone();
    formatter_provider
        .expect_get_credential_formatter()
        .with(eq(CredentialFormat::from("JWT")))
        .returning(move |_| Ok(formatter_clone.clone()));
    formatter_provider
        .expect_get_formatter_by_type()
        .returning(move |_| Some(("JWT".into(), formatter.clone())));

    let schema = credential.schema.as_ref().await.unwrap().to_owned();
    credential_schema_repository
        .expect_get_by_schema_id_and_organisation()
        .once()
        .returning(move |_, _| Ok(Some(schema.clone())));

    interaction_repository
        .expect_update_interaction()
        .once()
        .returning(move |_, _| Ok(()));

    key_provider
        .expect_get_signature_provider()
        .returning(move |_, _, _| {
            let mut mock_signature_provider = MockSignatureProvider::new();
            mock_signature_provider
                .expect_jose_alg()
                .returning(|| Ok("EdDSA".to_string()));

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

    let mut key_security_level_provider = MockKeySecurityLevelProvider::new();
    key_security_level_provider
        .expect_get_from_type()
        .returning(|_| {
            let mut security = MockKeySecurityLevel::new();
            security
                .expect_get_key_storages()
                .return_const(vec!["INTERNAL".to_string()]);
            security.expect_get_priority().return_const(0u64);
            security
                .expect_get_capabilities()
                .returning(|| KeySecurityLevelCapabilities {
                    openid_security_level: vec![KeyStorageSecurityLevel::Basic],
                });
            Ok(Arc::new(security))
        });

    let mut holder_wallet_unit_repository = MockInstanceRepository::new();
    holder_wallet_unit_repository
        .expect_get_by_role()
        .with(eq(InstanceRole::Wallet), always())
        .once()
        .return_once(|_, _| {
            Ok(Some(Instance {
                id: Uuid::new_v4().into(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                provider_type: WalletProviderType::ProcivisOne,
                role: InstanceRole::Wallet,
                provider_name: "provider".to_string(),
                provider_url: "provider.url".to_string(),
                provider_instance_id: Uuid::new_v4().into(),
                status: InstanceStatus::Active,
                organisation: dummy_organisation(None).into(),
                authentication_key: None,
                wallet_unit_attestations: Default::default(),
                nonce: None,
                user_nonce: None,
            }))
        });

    let mut holder_wallet_unit_proto = MockHolderWalletUnitProto::new();
    holder_wallet_unit_proto
        .expect_issue_wallet_attestations()
        .once()
        .returning(|_, _| {
            Ok(IssuedWalletUnitAttestations {
                provider_response: IssueWalletUnitAttestationResponseDTO {
                    wia: vec![],
                    wua: vec!["wua_attestation_jwt".to_string()],
                },
                wia_pop_key: None,
            })
        });

    let identifier = dummy_identifier();
    let mut identifier_creator = MockIdentifierCreator::new();
    identifier_creator
        .expect_get_or_create_remote_identifier()
        .once()
        .with(
            always(),
            always(),
            eq(IdentifierName::PrefixForId(
                IdentifierRole::Issuer.to_string(),
            )),
            eq(true),
            always(),
            always(),
        )
        .return_once({
            let identifier = identifier.clone();
            move |_, _, _, _, _, _| Ok((identifier, RemoteIdentifierRelation::Key(dummy_key())))
        });

    let openid_provider = setup_protocol(TestInputs {
        formatter_provider,
        key_provider,
        key_algorithm_provider,
        identifier_creator,
        key_security_level_provider,
        holder_wallet_unit_proto,
        credential_schema_repository,
        holder_wallet_unit_repository,
        interaction_repository,
        config: dummy_config(),
        ..Default::default()
    });

    let configuration_ids = configuration_ids(&interaction);
    let issuer_response = openid_provider
        .holder_accept_credential(
            interaction,
            Some(HolderBindingInput {
                identifier: Identifier {
                    data: IdentifierData::Key(Related::from(key.clone())),
                    ..dummy_identifier()
                },
                key,
            }),
            None,
            configuration_ids,
        )
        .await
        .unwrap()
        .issued
        .pop()
        .unwrap();

    assert_eq!(
        issuer_response.main_credential.serialized,
        Some("credential".into())
    );
}

async fn interaction_with_metadata(
    credential: &Credential,
    credential_metadata: CredentialMetadata,
    mock_server_uri: &str,
) -> Interaction {
    let interaction_data = HolderInteractionData {
        issuer_url: mock_server_uri.to_owned(),
        credential_endpoint: format!("{mock_server_uri}/credential"),
        token_endpoint: Some(format!("{mock_server_uri}/token")),
        nonce_endpoint: Some(format!("{mock_server_uri}/nonce")),
        notification_endpoint: None,
        challenge_endpoint: None,
        grants: Some(Grants::PreAuthorizedCode(PreAuthorizedCodeGrant {
            pre_authorized_code: "code".to_string(),
            tx_code: None,
            authorization_server: None,
        })),
        batch_size: None,
        access_token: None,
        access_token_expires_at: None,
        refresh_token: None,
        token_endpoint_auth_methods_supported: None,
        client_attestation_pop_signing_alg_values_supported: None,
        refresh_token_expires_at: None,
        issuer_display: None,
        continue_issuance: None,
        protocol: "OPENID4VCI_FINAL1".to_string(),
        credential_request_encryption: None,
        credential_response_encryption: None,
        credential_configurations: vec![HolderCredentialConfiguration {
            credential_configuration_id: "CredentialSchemaId".to_owned(),
            format: "jwt_vc_json".to_string(),
            cryptographic_binding_methods_supported: Some(vec!["jwk".to_string()]),
            credential_signing_alg_values_supported: None,
            proof_types_supported: None,
            credential_metadata: Some(credential_metadata),
            disclosure_policy: None,
            notification_id: None,
            credential_id: None,
        }],
    };

    Interaction {
        id: Uuid::new_v4().into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        data: Some(serde_json::to_vec(&interaction_data).unwrap()),
        organisation: credential
            .schema
            .as_ref()
            .await
            .unwrap()
            .organisation
            .to_owned(),
        nonce_id: None,
        interaction_type: InteractionType::Issuance,
        expires_at: None,
        ecosystem: None,
        ecosystem_data: Default::default(),
    }
}

#[tokio::test]
async fn test_holder_accept_credential_stores_all_translations_from_metadata() {
    // GIVEN
    let mock_server = MockServer::start().await;
    let mut formatter_provider = MockCredentialFormatterProvider::default();
    let mut key_provider = MockKeyProvider::default();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();
    let mut credential_schema_importer = MockCredentialSchemaImporter::new();

    let credential = generic_credential_key();

    let credential_metadata = CredentialMetadata {
        display: Some(vec![
            CredentialDisplay {
                name: "My Credential".to_string(),
                locale: Some("en".to_string()),
                description: Some("English description".to_string()),
                ..Default::default()
            },
            CredentialDisplay {
                name: "Mein Ausweis".to_string(),
                locale: Some("de".to_string()),
                description: None,
                ..Default::default()
            },
        ]),
        claims: None,
    };

    let interaction =
        interaction_with_metadata(&credential, credential_metadata, &mock_server.uri()).await;

    Mock::given(method(Method::POST))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "tok",
            "token_type": "Bearer",
            "expires_in": crate::clock::now_utc().unix_timestamp() + 3600,
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/nonce"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"c_nonce": "nonce"})))
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/credential"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "credentials": [{"credential": "credential"}]
        })))
        .mount(&mock_server)
        .await;

    let mut formatter = MockCredentialFormatter::new();
    formatter
        .expect_get_leeway()
        .return_const(Duration::seconds(1000));
    formatter.expect_parse_credential().returning({
        let clone = credential.clone();
        move |_, _, _| Ok(clone.clone())
    });

    let formatter = Arc::new(formatter);
    let formatter_clone = formatter.clone();
    formatter_provider
        .expect_get_credential_formatter()
        .returning(move |_| Ok(formatter_clone.clone()));
    formatter_provider
        .expect_get_formatter_by_type()
        .returning(move |_| Some(("JWT".into(), formatter.clone())));

    credential_schema_repository
        .expect_get_by_schema_id_and_organisation()
        .once()
        .returning(|_, _| Ok(None));

    let captured_schema: Arc<Mutex<Option<CredentialSchema>>> = Arc::new(Mutex::new(None));
    let captured_schema_clone = captured_schema.clone();

    credential_schema_importer
        .expect_import_credential_schema()
        .once()
        .returning(move |schema| {
            *captured_schema_clone.lock().unwrap() = Some(schema.clone());
            Ok(schema)
        });

    interaction_repository
        .expect_update_interaction()
        .once()
        .returning(|_, _| Ok(()));

    key_provider
        .expect_get_signature_provider()
        .returning(move |_, _, _| {
            let mut mock_signature_provider = MockSignatureProvider::new();
            mock_signature_provider
                .expect_jose_alg()
                .returning(|| Ok("EdDSA".to_string()));
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

    let mut identifier_creator = MockIdentifierCreator::new();
    identifier_creator
        .expect_get_or_create_remote_identifier()
        .once()
        .with(
            always(),
            always(),
            eq(IdentifierName::PrefixForId(
                IdentifierRole::Issuer.to_string(),
            )),
            eq(true),
            always(),
            always(),
        )
        .return_once(|_, _, _, _, _, _| {
            Ok((
                dummy_identifier(),
                RemoteIdentifierRelation::Key(dummy_key()),
            ))
        });

    let mut holder_wallet_unit_repository = MockInstanceRepository::new();
    holder_wallet_unit_repository
        .expect_get_by_role()
        .once()
        .return_once(|_, _| Ok(None));

    let mut config = dummy_config();
    config.global_settings.default_language = "en".to_string();

    let openid_provider = setup_protocol(TestInputs {
        formatter_provider,
        key_provider,
        key_algorithm_provider,
        identifier_creator,
        credential_schema_repository,
        credential_schema_importer: Some(credential_schema_importer),
        holder_wallet_unit_repository,
        interaction_repository,
        config,
        ..Default::default()
    });

    // WHEN
    let key = dummy_key();
    let configuration_ids = configuration_ids(&interaction);
    openid_provider
        .holder_accept_credential(
            interaction,
            Some(HolderBindingInput {
                identifier: Identifier {
                    data: IdentifierData::Key(Related::from(key.clone())),
                    ..dummy_identifier()
                },
                key,
            }),
            None,
            configuration_ids,
        )
        .await
        .unwrap();

    // THEN
    let schema = captured_schema.lock().unwrap().take().unwrap();
    let translations = schema.translations.as_ref().await.unwrap();
    assert_eq!(
        translations.len(),
        3,
        "expected Name(en), Description(en), Name(de)"
    );

    let en_name = translations
        .iter()
        .find(|t| t.lang == "en" && t.field == LocalizedTextField::Name)
        .expect("en Name translation missing");
    assert_eq!(en_name.value, "My Credential");
    assert_eq!(
        en_name.entity_type,
        LocalizedTextEntityType::CredentialSchema
    );

    let en_desc = translations
        .iter()
        .find(|t| t.lang == "en" && t.field == LocalizedTextField::Description)
        .expect("en Description translation missing");
    assert_eq!(en_desc.value, "English description");

    let de_name = translations
        .iter()
        .find(|t| t.lang == "de" && t.field == LocalizedTextField::Name)
        .expect("de Name translation missing");
    assert_eq!(de_name.value, "Mein Ausweis");
}

#[tokio::test]
async fn test_holder_accept_credential_uses_default_language_for_display_without_locale() {
    // GIVEN
    let mock_server = MockServer::start().await;
    let mut formatter_provider = MockCredentialFormatterProvider::default();
    let mut key_provider = MockKeyProvider::default();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();
    let mut credential_schema_importer = MockCredentialSchemaImporter::new();

    let credential = generic_credential_key();

    let credential_metadata = CredentialMetadata {
        display: Some(vec![CredentialDisplay {
            name: "Mein Ausweis".to_string(),
            locale: None, // no locale — should fall back to default_language
            description: None,
            ..Default::default()
        }]),
        claims: None,
    };

    let interaction =
        interaction_with_metadata(&credential, credential_metadata, &mock_server.uri()).await;

    Mock::given(method(Method::POST))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "tok",
            "token_type": "Bearer",
            "expires_in": crate::clock::now_utc().unix_timestamp() + 3600,
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/nonce"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"c_nonce": "nonce"})))
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/credential"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "credentials": [{"credential": "credential"}]
        })))
        .mount(&mock_server)
        .await;

    let mut formatter = MockCredentialFormatter::new();
    formatter
        .expect_get_leeway()
        .return_const(Duration::seconds(1000));
    formatter.expect_parse_credential().returning({
        let clone = credential.clone();
        move |_, _, _| Ok(clone.clone())
    });

    let formatter = Arc::new(formatter);
    let formatter_clone = formatter.clone();
    formatter_provider
        .expect_get_credential_formatter()
        .returning(move |_| Ok(formatter_clone.clone()));
    formatter_provider
        .expect_get_formatter_by_type()
        .returning(move |_| Some(("JWT".into(), formatter.clone())));

    credential_schema_repository
        .expect_get_by_schema_id_and_organisation()
        .once()
        .returning(|_, _| Ok(None));

    let captured_schema: Arc<Mutex<Option<CredentialSchema>>> = Arc::new(Mutex::new(None));
    let captured_schema_clone = captured_schema.clone();

    credential_schema_importer
        .expect_import_credential_schema()
        .once()
        .returning(move |schema| {
            *captured_schema_clone.lock().unwrap() = Some(schema.clone());
            Ok(schema)
        });

    interaction_repository
        .expect_update_interaction()
        .once()
        .returning(|_, _| Ok(()));

    key_provider
        .expect_get_signature_provider()
        .returning(move |_, _, _| {
            let mut mock_signature_provider = MockSignatureProvider::new();
            mock_signature_provider
                .expect_jose_alg()
                .returning(|| Ok("EdDSA".to_string()));
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

    let mut identifier_creator = MockIdentifierCreator::new();
    identifier_creator
        .expect_get_or_create_remote_identifier()
        .once()
        .with(
            always(),
            always(),
            eq(IdentifierName::PrefixForId(
                IdentifierRole::Issuer.to_string(),
            )),
            eq(true),
            always(),
            always(),
        )
        .return_once(|_, _, _, _, _, _| {
            Ok((
                dummy_identifier(),
                RemoteIdentifierRelation::Key(dummy_key()),
            ))
        });

    let mut holder_wallet_unit_repository = MockInstanceRepository::new();
    holder_wallet_unit_repository
        .expect_get_by_role()
        .once()
        .return_once(|_, _| Ok(None));

    let mut config = dummy_config();
    config.global_settings.default_language = "fr".to_string(); // custom default language

    let openid_provider = setup_protocol(TestInputs {
        formatter_provider,
        key_provider,
        key_algorithm_provider,
        identifier_creator,
        credential_schema_repository,
        credential_schema_importer: Some(credential_schema_importer),
        holder_wallet_unit_repository,
        interaction_repository,
        config,
        ..Default::default()
    });

    // WHEN
    let key = dummy_key();
    let configuration_ids = configuration_ids(&interaction);
    openid_provider
        .holder_accept_credential(
            interaction,
            Some(HolderBindingInput {
                identifier: Identifier {
                    data: IdentifierData::Key(Related::from(key.clone())),
                    ..dummy_identifier()
                },
                key,
            }),
            None,
            configuration_ids,
        )
        .await
        .unwrap();

    // THEN
    let schema = captured_schema.lock().unwrap().take().unwrap();
    let translations = schema.translations.as_ref().await.unwrap();
    assert_eq!(translations.len(), 1);

    let translation = &translations[0];
    assert_eq!(
        translation.lang, "fr",
        "locale-less display should use default_language"
    );
    assert_eq!(translation.field, LocalizedTextField::Name);
    assert_eq!(translation.value, "Mein Ausweis");
}

#[tokio::test]
async fn test_holder_accept_credential_stores_claim_schema_translations_from_metadata() {
    // GIVEN
    let mock_server = MockServer::start().await;
    let mut formatter_provider = MockCredentialFormatterProvider::default();
    let mut key_provider = MockKeyProvider::default();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();
    let mut credential_schema_importer = MockCredentialSchemaImporter::new();

    // generic_credential_key() has a claim schema with key "NUMBER"
    let credential = generic_credential_key();

    let credential_metadata = CredentialMetadata {
        display: Some(vec![CredentialDisplay {
            name: "My Credential".to_string(),
            locale: Some("en".to_string()),
            ..Default::default()
        }]),
        claims: Some(vec![ClaimMetadata {
            path: vec!["NUMBER".to_string()],
            display: Some(vec![
                ClaimDisplay {
                    name: Some("Number".to_string()),
                    locale: Some("en".to_string()),
                },
                ClaimDisplay {
                    name: Some("Nummer".to_string()),
                    locale: Some("de".to_string()),
                },
            ]),
            mandatory: None,
            additional_values: Default::default(),
        }]),
    };

    let interaction =
        interaction_with_metadata(&credential, credential_metadata, &mock_server.uri()).await;

    Mock::given(method(Method::POST))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "tok",
            "token_type": "Bearer",
            "expires_in": crate::clock::now_utc().unix_timestamp() + 3600,
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/nonce"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"c_nonce": "nonce"})))
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/credential"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "credentials": [{"credential": "credential"}]
        })))
        .mount(&mock_server)
        .await;

    let mut formatter = MockCredentialFormatter::new();
    formatter
        .expect_get_leeway()
        .return_const(Duration::seconds(1000));
    formatter.expect_parse_credential().returning({
        let clone = credential.clone();
        move |_, _, _| Ok(clone.clone())
    });

    let formatter = Arc::new(formatter);
    let formatter_clone = formatter.clone();
    formatter_provider
        .expect_get_credential_formatter()
        .returning(move |_| Ok(formatter_clone.clone()));
    formatter_provider
        .expect_get_formatter_by_type()
        .returning(move |_| Some(("JWT".into(), formatter.clone())));

    credential_schema_repository
        .expect_get_by_schema_id_and_organisation()
        .once()
        .returning(|_, _| Ok(None));

    let captured_schema: Arc<Mutex<Option<CredentialSchema>>> = Arc::new(Mutex::new(None));
    let captured_schema_clone = captured_schema.clone();

    credential_schema_importer
        .expect_import_credential_schema()
        .once()
        .returning(move |schema| {
            *captured_schema_clone.lock().unwrap() = Some(schema.clone());
            Ok(schema)
        });

    interaction_repository
        .expect_update_interaction()
        .once()
        .returning(|_, _| Ok(()));

    key_provider
        .expect_get_signature_provider()
        .returning(move |_, _, _| {
            let mut mock_signature_provider = MockSignatureProvider::new();
            mock_signature_provider
                .expect_jose_alg()
                .returning(|| Ok("EdDSA".to_string()));
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

    let mut identifier_creator = MockIdentifierCreator::new();
    identifier_creator
        .expect_get_or_create_remote_identifier()
        .once()
        .with(
            always(),
            always(),
            eq(IdentifierName::PrefixForId(
                IdentifierRole::Issuer.to_string(),
            )),
            eq(true),
            always(),
            always(),
        )
        .return_once(|_, _, _, _, _, _| {
            Ok((
                dummy_identifier(),
                RemoteIdentifierRelation::Key(dummy_key()),
            ))
        });

    let mut holder_wallet_unit_repository = MockInstanceRepository::new();
    holder_wallet_unit_repository
        .expect_get_by_role()
        .once()
        .return_once(|_, _| Ok(None));

    let mut config = dummy_config();
    config.global_settings.default_language = "en".to_string();

    let openid_provider = setup_protocol(TestInputs {
        formatter_provider,
        key_provider,
        key_algorithm_provider,
        identifier_creator,
        credential_schema_repository,
        credential_schema_importer: Some(credential_schema_importer),
        holder_wallet_unit_repository,
        interaction_repository,
        config,
        ..Default::default()
    });

    // WHEN
    let key = dummy_key();
    let configuration_ids = configuration_ids(&interaction);
    openid_provider
        .holder_accept_credential(
            interaction,
            Some(HolderBindingInput {
                identifier: Identifier {
                    data: IdentifierData::Key(Related::from(key.clone())),
                    ..dummy_identifier()
                },
                key,
            }),
            None,
            configuration_ids,
        )
        .await
        .unwrap();

    // THEN
    let schema = captured_schema.lock().unwrap().take().unwrap();
    let claim_schemas = schema.claim_schemas.as_ref().await.unwrap();
    let number_claim = claim_schemas
        .iter()
        .find(|cs| cs.key == "NUMBER")
        .expect("NUMBER claim schema missing");

    let claim_translations = number_claim.translations.as_ref().await.unwrap();
    assert_eq!(
        claim_translations.len(),
        2,
        "expected Name(en) and Name(de) for NUMBER claim"
    );

    let en = claim_translations
        .iter()
        .find(|t| t.lang == "en")
        .expect("en translation missing");
    assert_eq!(en.field, LocalizedTextField::Name);
    assert_eq!(en.value, "Number");
    assert_eq!(en.entity_type, LocalizedTextEntityType::ClaimSchema);

    let de = claim_translations
        .iter()
        .find(|t| t.lang == "de")
        .expect("de translation missing");
    assert_eq!(de.field, LocalizedTextField::Name);
    assert_eq!(de.value, "Nummer");
    assert_eq!(de.entity_type, LocalizedTextEntityType::ClaimSchema);
}

#[tokio::test]
async fn test_holder_accept_credential_stores_disclosure_policy() {
    // GIVEN
    let mock_server = MockServer::start().await;
    let mut formatter_provider = MockCredentialFormatterProvider::default();
    let mut key_provider = MockKeyProvider::default();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut interaction_repository = MockInteractionRepository::default();
    let mut credential_schema_importer = MockCredentialSchemaImporter::new();

    let credential = generic_credential_key();

    let disclosure_policy = DisclosurePolicy {
        id: "policy-id".to_string(),
        policy: PolicyType::None,
        description: None,
        url: Some("https://policy.url".to_string()),
    };

    let mock_server_uri = mock_server.uri();
    let interaction_data = HolderInteractionData {
        issuer_url: mock_server_uri.to_owned(),
        credential_endpoint: format!("{mock_server_uri}/credential"),
        token_endpoint: Some(format!("{mock_server_uri}/token")),
        nonce_endpoint: Some(format!("{mock_server_uri}/nonce")),
        notification_endpoint: None,
        challenge_endpoint: None,
        grants: Some(Grants::PreAuthorizedCode(PreAuthorizedCodeGrant {
            pre_authorized_code: "code".to_string(),
            tx_code: None,
            authorization_server: None,
        })),
        batch_size: None,
        access_token: None,
        access_token_expires_at: None,
        refresh_token: None,
        token_endpoint_auth_methods_supported: None,
        client_attestation_pop_signing_alg_values_supported: None,
        refresh_token_expires_at: None,
        issuer_display: None,
        continue_issuance: None,
        protocol: "OPENID4VCI_FINAL1".to_string(),
        credential_request_encryption: None,
        credential_response_encryption: None,
        credential_configurations: vec![HolderCredentialConfiguration {
            credential_configuration_id: "CredentialSchemaId".to_owned(),
            format: "jwt_vc_json".to_string(),
            cryptographic_binding_methods_supported: Some(vec!["jwk".to_string()]),
            credential_signing_alg_values_supported: None,
            proof_types_supported: None,
            credential_metadata: None,
            disclosure_policy: Some(disclosure_policy.to_owned()),
            notification_id: None,
            credential_id: None,
        }],
    };

    let interaction = Interaction {
        id: Uuid::new_v4().into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        data: Some(serde_json::to_vec(&interaction_data).unwrap()),
        organisation: credential
            .schema
            .as_ref()
            .await
            .unwrap()
            .organisation
            .to_owned(),
        nonce_id: None,
        interaction_type: InteractionType::Issuance,
        expires_at: None,
        ecosystem: None,
        ecosystem_data: Default::default(),
    };

    Mock::given(method(Method::POST))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "tok",
            "token_type": "Bearer",
            "expires_in": crate::clock::now_utc().unix_timestamp() + 3600,
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/nonce"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"c_nonce": "nonce"})))
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/credential"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "credentials": [{"credential": "credential"}]
        })))
        .mount(&mock_server)
        .await;

    let mut formatter = MockCredentialFormatter::new();
    formatter
        .expect_get_leeway()
        .return_const(Duration::seconds(1000));
    formatter.expect_parse_credential().returning({
        let clone = credential.clone();
        move |_, _, _| Ok(clone.clone())
    });

    let formatter = Arc::new(formatter);
    let formatter_clone = formatter.clone();
    formatter_provider
        .expect_get_credential_formatter()
        .returning(move |_| Ok(formatter_clone.clone()));
    formatter_provider
        .expect_get_formatter_by_type()
        .returning(move |_| Some(("JWT".into(), formatter.clone())));

    credential_schema_repository
        .expect_get_by_schema_id_and_organisation()
        .once()
        .returning(|_, _| Ok(None));

    credential_schema_importer
        .expect_import_credential_schema()
        .once()
        .returning(Ok);

    interaction_repository
        .expect_update_interaction()
        .once()
        .returning(|_, _| Ok(()));

    key_provider
        .expect_get_signature_provider()
        .returning(move |_, _, _| {
            let mut mock_signature_provider = MockSignatureProvider::new();
            mock_signature_provider
                .expect_jose_alg()
                .returning(|| Ok("EdDSA".to_string()));
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

    let mut identifier_creator = MockIdentifierCreator::new();
    identifier_creator
        .expect_get_or_create_remote_identifier()
        .once()
        .with(
            always(),
            always(),
            eq(IdentifierName::PrefixForId(
                IdentifierRole::Issuer.to_string(),
            )),
            eq(true),
            always(),
            always(),
        )
        .return_once(|_, _, _, _, _, _| {
            Ok((
                dummy_identifier(),
                RemoteIdentifierRelation::Key(dummy_key()),
            ))
        });

    let mut holder_wallet_unit_repository = MockInstanceRepository::new();
    holder_wallet_unit_repository
        .expect_get_by_role()
        .once()
        .return_once(|_, _| Ok(None));

    let mut config = dummy_config();
    config.global_settings.default_language = "en".to_string();

    let openid_provider = setup_protocol(TestInputs {
        formatter_provider,
        key_provider,
        key_algorithm_provider,
        identifier_creator,
        credential_schema_repository,
        credential_schema_importer: Some(credential_schema_importer),
        holder_wallet_unit_repository,
        interaction_repository,
        config,
        ..Default::default()
    });

    // WHEN
    let key = dummy_key();
    let configuration_ids = configuration_ids(&interaction);
    let result = openid_provider
        .holder_accept_credential(
            interaction,
            Some(HolderBindingInput {
                identifier: Identifier {
                    data: IdentifierData::Key(Related::from(key.clone())),
                    ..dummy_identifier()
                },
                key,
            }),
            None,
            configuration_ids,
        )
        .await
        .unwrap()
        .issued
        .pop()
        .unwrap();

    // THEN
    let embedded_disclosure_policy: DisclosurePolicy = serde_json::from_str(
        result
            .main_credential
            .credential
            .embedded_disclosure_policy
            .as_ref()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(embedded_disclosure_policy, disclosure_policy);
}

fn test_params(issuance_url_scheme: &str) -> serde_json::Value {
    json!({
        "preAuthorizedCodeExpiresInSeconds": 10,
        "tokenExpiresInSeconds": 10,
        "refreshExpiresInSeconds": 1000,
        "credentialOfferByValue": true,
        "encryption": "0000000000000000000000000000000000000000000000000000000000000000",
        "redirectUri": {
            "enabled": true,
            "allowedSchemes": ["https"]
        },
        "urlScheme": issuance_url_scheme,
        "oauthAttestationLeewaySeconds": 60,
        "keyAttestationLeewaySeconds": 60
    })
}

async fn encryption_interaction_data(
    mock_server: &MockServer,
    credential: &Credential,
    credential_request_encryption: Option<CredentialRequestEncryption>,
    credential_response_encryption: Option<CredentialResponseEncryption>,
) -> HolderInteractionData {
    HolderInteractionData {
        issuer_url: mock_server.uri(),
        credential_endpoint: format!("{}/credential", mock_server.uri()),
        token_endpoint: Some(format!("{}/token", mock_server.uri())),
        nonce_endpoint: Some(format!("{}/nonce", mock_server.uri())),
        notification_endpoint: None,
        challenge_endpoint: None,
        grants: Some(Grants::PreAuthorizedCode(PreAuthorizedCodeGrant {
            pre_authorized_code: "code".to_string(),
            tx_code: None,
            authorization_server: None,
        })),
        batch_size: None,
        access_token: None,
        access_token_expires_at: None,
        refresh_token: None,
        token_endpoint_auth_methods_supported: None,
        client_attestation_pop_signing_alg_values_supported: None,
        refresh_token_expires_at: None,
        continue_issuance: None,
        issuer_display: None,
        protocol: "OPENID4VCI_FINAL1".to_string(),
        credential_request_encryption,
        credential_response_encryption,
        credential_configurations: vec![HolderCredentialConfiguration {
            credential_configuration_id: credential
                .schema
                .as_ref()
                .await
                .unwrap()
                .schema_id()
                .await
                .unwrap(),
            format: "jwt_vc_json".to_string(),
            cryptographic_binding_methods_supported: Some(vec!["jwk".to_string()]),
            credential_signing_alg_values_supported: None,
            proof_types_supported: None,
            credential_metadata: None,
            disclosure_policy: None,
            notification_id: None,
            credential_id: None,
        }],
    }
}

async fn interaction_for(
    credential: &Credential,
    interaction_data: &HolderInteractionData,
) -> Interaction {
    Interaction {
        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
            .unwrap()
            .into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        data: Some(serde_json::to_vec(interaction_data).unwrap()),
        organisation: credential
            .schema
            .as_ref()
            .await
            .unwrap()
            .organisation
            .to_owned(),
        nonce_id: None,
        interaction_type: InteractionType::Issuance,
        expires_at: None,
        ecosystem: None,
        ecosystem_data: Default::default(),
    }
}

async fn provider_with_encryption(credential: &Credential) -> OpenID4VCIFinal1_0 {
    let mut formatter = MockCredentialFormatter::new();
    formatter
        .expect_get_leeway()
        .return_const(Duration::seconds(1000));
    formatter.expect_parse_credential().returning({
        let clone = credential.clone();
        move |_, _, _| Ok(clone.clone())
    });
    let formatter = Arc::new(formatter);
    let formatter_clone = formatter.clone();
    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .with(eq(CredentialFormat::from("JWT")))
        .returning(move |_| Ok(formatter_clone.clone()));
    formatter_provider
        .expect_get_formatter_by_type()
        .returning(move |_| Some(("JWT".into(), formatter.clone())));

    let schema = credential.schema.as_ref().await.unwrap().to_owned();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    credential_schema_repository
        .expect_get_by_schema_id_and_organisation()
        .once()
        .returning(move |_, _| Ok(Some(schema.clone())));

    let mut interaction_repository = MockInteractionRepository::default();
    interaction_repository
        .expect_update_interaction()
        .once()
        .returning(move |_, _| Ok(()));

    let mut key_provider = MockKeyProvider::default();
    key_provider
        .expect_get_signature_provider()
        .returning(move |_, _, _| {
            let mut mock_signature_provider = MockSignatureProvider::new();
            mock_signature_provider
                .expect_jose_alg()
                .returning(|| Ok("EdDSA".to_string()));
            mock_signature_provider
                .expect_get_key_id()
                .returning(|| Some("key-id".to_string()));
            mock_signature_provider
                .expect_sign()
                .returning(|_| Ok(vec![0; 32]));
            Ok(Box::new(mock_signature_provider))
        });

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    // Delegate JWK parsing (request encryption) to the real ECDSA implementation.
    key_algorithm_provider.expect_parse_jwk().returning(|k| {
        Ok(ParsedKey {
            key: Ecdsa.parse_jwk(k).unwrap(),
            algorithm_type: KeyAlgorithmType::Ecdsa,
        })
    });
    // Ephemeral key generation for both encryption paths uses the real ECDSA.
    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .returning(|_| Ok(Arc::new(Ecdsa)));
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

    let mut identifier_creator = MockIdentifierCreator::new();
    identifier_creator
        .expect_get_or_create_remote_identifier()
        .once()
        .with(
            always(),
            always(),
            eq(IdentifierName::PrefixForId(
                IdentifierRole::Issuer.to_string(),
            )),
            eq(true),
            always(),
            always(),
        )
        .return_once(move |_, _, _, _, _, _| {
            Ok((
                dummy_identifier(),
                RemoteIdentifierRelation::Key(dummy_key()),
            ))
        });

    let mut holder_wallet_unit_repository = MockInstanceRepository::new();
    holder_wallet_unit_repository
        .expect_get_by_role()
        .once()
        .return_once(|_, _| Ok(None));

    setup_protocol(TestInputs {
        formatter_provider,
        key_provider,
        key_algorithm_provider,
        identifier_creator,
        credential_schema_repository,
        holder_wallet_unit_repository,
        interaction_repository,
        config: dummy_config(),
        ..Default::default()
    })
}

fn holder_binding_input(key: Key) -> HolderBindingInput {
    HolderBindingInput {
        identifier: Identifier {
            data: IdentifierData::Key(Related::from(key.clone())),
            ..dummy_identifier()
        },
        key,
    }
}

fn encrypt_credential_response(request_body: &[u8], response_body: &Value) -> String {
    let request: CredentialRequest = serde_json::from_slice(request_body).unwrap();
    let response_encryption = request
        .credential_response_encryption
        .expect("request is missing credential_response_encryption");

    // Fresh issuer-side ephemeral key for ECDH-ES.
    let issuer_ephemeral = Ecdsa.generate_key().unwrap();
    let key_agreement = issuer_ephemeral.key.key_agreement().unwrap();
    let shared_secret = futures::executor::block_on(
        key_agreement
            .private()
            .unwrap()
            .shared_secret(&response_encryption.jwk),
    )
    .unwrap();
    let ephemeral_public_jwk = key_agreement.public().as_jwk().unwrap();

    build_jwe(
        &serde_json::to_vec(response_body).unwrap(),
        Header {
            key_id: None,
            zip: response_encryption.zip,
            partyuinfo_data: None,
            partyvinfo_data: None,
        },
        shared_secret,
        ephemeral_public_jwk,
        response_encryption.enc,
    )
    .unwrap()
}

#[tokio::test]
async fn test_holder_accept_credential_request_encryption() {
    let mock_server = MockServer::start().await;

    let key = dummy_key();
    let mut credential = generic_credential_did_with_holder_identifier();
    credential
        .holder_identifier
        .as_mut()
        .unwrap()
        .as_mut()
        .await
        .unwrap()
        .data = IdentifierData::Key(Related::from(key.clone()));

    // Issuer key the holder must encrypt the request to.
    let issuer_key = Ecdsa.generate_key().unwrap();
    let issuer_key_agreement = issuer_key.key.key_agreement().unwrap();

    let interaction_data = encryption_interaction_data(
        &mock_server,
        &credential,
        Some(CredentialRequestEncryption {
            jwks: Jwks {
                keys: vec![issuer_key_agreement.public().as_jwk().unwrap()],
            },
            enc_values_supported: vec![EncryptionAlgorithm::A256GCM],
            zip_values_supported: vec![],
            encryption_required: true,
        }),
        None,
    )
    .await;
    let interaction = interaction_for(&credential, &interaction_data).await;

    Mock::given(method(Method::POST))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "321",
            "token_type": "Bearer",
            "expires_in": crate::clock::now_utc().unix_timestamp() + 3600,
        })))
        .expect(1)
        .mount(&mock_server)
        .await;
    Mock::given(method(Method::POST))
        .and(path("/nonce"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "c_nonce": "123" })))
        .expect(1)
        .mount(&mock_server)
        .await;
    // The encrypted request is posted as `application/jwt`; respond in plaintext
    // (no response encryption was requested).
    Mock::given(method(Method::POST))
        .and(path("/credential"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "credentials": [{ "credential": "credential" }],
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let openid_provider = provider_with_encryption(&credential).await;
    let configuration_ids = configuration_ids(&interaction);
    let issuer_response = openid_provider
        .holder_accept_credential(
            interaction,
            Some(holder_binding_input(key)),
            None,
            configuration_ids,
        )
        .await
        .unwrap()
        .issued
        .pop()
        .unwrap();
    assert_eq!(
        issuer_response.main_credential.serialized,
        Some("credential".into())
    );

    // Verify the credential request was actually encrypted to the issuer key.
    let requests = mock_server.received_requests().await.unwrap();
    let credential_request = requests
        .iter()
        .find(|r| r.url.path().ends_with("/credential"))
        .expect("no credential request recorded");
    assert_eq!(
        credential_request
            .headers
            .get("Content-Type")
            .unwrap()
            .to_str()
            .unwrap(),
        "application/jwt"
    );

    let jwe = String::from_utf8(credential_request.body.clone()).unwrap();
    let decrypted = decrypt_jwe_payload(&jwe, issuer_key_agreement.private().unwrap().as_ref())
        .await
        .unwrap();
    let decrypted_request: CredentialRequest = serde_json::from_slice(&decrypted).unwrap();
    let_assert!(
        CredentialRequestIdentifier::CredentialConfigurationId(config_id) =
            &decrypted_request.credential
    );
    assert_eq!(
        config_id,
        &interaction_data.credential_configurations[0].credential_configuration_id
    );
    let_assert!(Some(Proofs::Jwt(proofs)) = &decrypted_request.proofs);
    assert_eq!(proofs.len(), 1);
}

#[tokio::test]
async fn test_holder_accept_credential_response_encryption() {
    let mock_server = MockServer::start().await;

    let key = dummy_key();
    let mut credential = generic_credential_did_with_holder_identifier();
    credential
        .holder_identifier
        .as_mut()
        .unwrap()
        .as_mut()
        .await
        .unwrap()
        .data = IdentifierData::Key(Related::from(key.clone()));

    let interaction_data = encryption_interaction_data(
        &mock_server,
        &credential,
        None,
        Some(CredentialResponseEncryption {
            alg_values_supported: vec![EncryptionKeyManagementAlgorithm::EcdhEs],
            enc_values_supported: vec![EncryptionAlgorithm::A256GCM],
            zip_values_supported: vec![],
            encryption_required: true,
        }),
    )
    .await;
    let interaction = interaction_for(&credential, &interaction_data).await;

    Mock::given(method(Method::POST))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "321",
            "token_type": "Bearer",
            "expires_in": crate::clock::now_utc().unix_timestamp() + 3600,
        })))
        .expect(1)
        .mount(&mock_server)
        .await;
    Mock::given(method(Method::POST))
        .and(path("/nonce"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "c_nonce": "123" })))
        .expect(1)
        .mount(&mock_server)
        .await;
    // Encrypt the response to the holder's ephemeral key found in the request.
    Mock::given(method(Method::POST))
        .and(path("/credential"))
        .respond_with(|req: &wiremock::Request| {
            let jwe = encrypt_credential_response(
                &req.body,
                &json!({ "credentials": [{ "credential": "credential" }] }),
            );
            ResponseTemplate::new(200).set_body_raw(jwe.into_bytes(), "application/jwt")
        })
        .expect(1)
        .mount(&mock_server)
        .await;

    let openid_provider = provider_with_encryption(&credential).await;
    let configuration_ids = configuration_ids(&interaction);
    let issuer_response = openid_provider
        .holder_accept_credential(
            interaction,
            Some(holder_binding_input(key)),
            None,
            configuration_ids,
        )
        .await
        .unwrap()
        .issued
        .pop()
        .unwrap();

    // The credential could only be returned if the encrypted response decrypted.
    assert_eq!(
        issuer_response.main_credential.serialized,
        Some("credential".into())
    );
}

#[tokio::test]
async fn test_holder_accept_credential_request_and_response_encryption_with_compression() {
    let mock_server = MockServer::start().await;

    let key = dummy_key();
    let mut credential = generic_credential_did_with_holder_identifier();
    credential
        .holder_identifier
        .as_mut()
        .unwrap()
        .as_mut()
        .await
        .unwrap()
        .data = IdentifierData::Key(Related::from(key.clone()));

    let issuer_key = Ecdsa.generate_key().unwrap();
    let issuer_key_agreement = issuer_key.key.key_agreement().unwrap();

    let interaction_data = encryption_interaction_data(
        &mock_server,
        &credential,
        Some(CredentialRequestEncryption {
            jwks: Jwks {
                keys: vec![issuer_key_agreement.public().as_jwk().unwrap()],
            },
            enc_values_supported: vec![EncryptionAlgorithm::A256GCM],
            zip_values_supported: vec![CompressionAlgorithm::DEF],
            encryption_required: true,
        }),
        Some(CredentialResponseEncryption {
            alg_values_supported: vec![EncryptionKeyManagementAlgorithm::EcdhEs],
            enc_values_supported: vec![EncryptionAlgorithm::A256GCM],
            zip_values_supported: vec![CompressionAlgorithm::DEF],
            encryption_required: true,
        }),
    )
    .await;
    let interaction = interaction_for(&credential, &interaction_data).await;

    Mock::given(method(Method::POST))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "321",
            "token_type": "Bearer",
            "expires_in": crate::clock::now_utc().unix_timestamp() + 3600,
        })))
        .expect(1)
        .mount(&mock_server)
        .await;
    Mock::given(method(Method::POST))
        .and(path("/nonce"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "c_nonce": "123" })))
        .expect(1)
        .mount(&mock_server)
        .await;
    // Decrypt the compressed, encrypted request, then respond with a compressed,
    // encrypted response.
    let issuer_private = issuer_key
        .key
        .key_agreement()
        .unwrap()
        .private()
        .unwrap()
        .clone();
    Mock::given(method(Method::POST))
        .and(path("/credential"))
        .respond_with(move |req: &wiremock::Request| {
            let jwe = String::from_utf8(req.body.clone()).unwrap();
            let decrypted =
                futures::executor::block_on(decrypt_jwe_payload(&jwe, issuer_private.as_ref()))
                    .unwrap();
            // Round-trip the request through decryption to prove it was encrypted
            // and compressed correctly.
            let request: CredentialRequest = serde_json::from_slice(&decrypted).unwrap();
            assert!(matches!(request.proofs, Some(Proofs::Jwt(_))));
            let response_jwe = encrypt_credential_response(
                &decrypted,
                &json!({ "credentials": [{ "credential": "credential" }] }),
            );
            ResponseTemplate::new(200).set_body_raw(response_jwe.into_bytes(), "application/jwt")
        })
        .expect(1)
        .mount(&mock_server)
        .await;

    let openid_provider = provider_with_encryption(&credential).await;
    let configuration_ids = configuration_ids(&interaction);
    let issuer_response = openid_provider
        .holder_accept_credential(
            interaction,
            Some(holder_binding_input(key)),
            None,
            configuration_ids,
        )
        .await
        .unwrap()
        .issued
        .pop()
        .unwrap();

    assert_eq!(
        issuer_response.main_credential.serialized,
        Some("credential".into())
    );
}

#[test]
fn test_parse_eudi_issuer_metadata() {
    // Taken from https://issuer.eudiw.dev/.well-known/openid-credential-issuer on 03.07.2026
    let metadata = include_str!("fixtures/eudi_issuer_metadata.json");
    assert!(serde_json::from_str::<CredentialIssuerMetadata>(metadata).is_ok());
}

fn configuration_ids(interaction: &Interaction) -> Vec<String> {
    let data: HolderInteractionData =
        serde_json::from_slice(interaction.data.as_ref().unwrap()).unwrap();
    data.credential_configurations
        .into_iter()
        .map(|c| c.credential_configuration_id)
        .collect()
}

#[tokio::test]
async fn test_prepare_wallet_attestations_attests_each_key_once() {
    let mut key_security_level_provider = MockKeySecurityLevelProvider::new();
    key_security_level_provider
        .expect_get_from_type()
        .returning(|_| {
            let mut security = MockKeySecurityLevel::new();
            security
                .expect_get_key_storages()
                .return_const(vec!["INTERNAL".to_string()]);
            security.expect_get_priority().return_const(0u64);
            security
                .expect_get_capabilities()
                .returning(|| KeySecurityLevelCapabilities {
                    openid_security_level: vec![KeyStorageSecurityLevel::Basic],
                });
            Ok(Arc::new(security))
        });
    let mut holder_wallet_unit_repository = MockInstanceRepository::new();
    holder_wallet_unit_repository
        .expect_get_by_role()
        .with(eq(InstanceRole::Wallet), always())
        .once()
        .return_once(|_, _| {
            Ok(Some(Instance {
                id: Uuid::new_v4().into(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                provider_type: WalletProviderType::ProcivisOne,
                role: InstanceRole::Wallet,
                provider_name: "provider".to_string(),
                provider_url: "provider.url".to_string(),
                provider_instance_id: Uuid::new_v4().into(),
                status: InstanceStatus::Active,
                organisation: dummy_organisation(None).into(),
                authentication_key: None,
                wallet_unit_attestations: Default::default(),
                nonce: None,
                user_nonce: None,
            }))
        });
    let mut holder_wallet_unit_proto = MockHolderWalletUnitProto::new();
    holder_wallet_unit_proto
        .expect_issue_wallet_attestations()
        .once()
        .withf(|_, request| {
            // one key, shared by the configurations requiring key attestation
            matches!(
                request,
                IssueWalletAttestationRequest::Wua(WUARequestParams { attested_keys })
                    if attested_keys.len() == 1
                        && attested_keys[0].1 == KeyStorageSecurityLevel::Basic
            )
        })
        .returning(|_, _| {
            Ok(IssuedWalletUnitAttestations {
                provider_response: IssueWalletUnitAttestationResponseDTO {
                    wia: vec![],
                    wua: vec!["wua".to_string()],
                },
                wia_pop_key: None,
            })
        });
    let protocol = setup_protocol(TestInputs {
        key_security_level_provider,
        holder_wallet_unit_repository,
        holder_wallet_unit_proto,
        ..Default::default()
    });

    let configuration = |id: &str, key_attestation_required: bool| HolderCredentialConfiguration {
        credential_configuration_id: id.to_string(),
        format: "jwt_vc_json".to_string(),
        cryptographic_binding_methods_supported: None,
        credential_signing_alg_values_supported: None,
        proof_types_supported: Some(IndexMap::from([(
            "jwt".to_string(),
            ProofTypeSupported {
                proof_signing_alg_values_supported: vec!["ES256".to_string()],
                key_attestations_required: key_attestation_required.then(|| {
                    KeyAttestationsRequired {
                        key_storage: vec![KeyStorageSecurityLevel::Basic],
                        user_authentication: vec![],
                    }
                }),
            },
        )])),
        credential_metadata: None,
        disclosure_policy: None,
        notification_id: None,
        credential_id: None,
    };
    let key = Key {
        storage_type: "INTERNAL".to_string(),
        ..dummy_key()
    };
    let requested = |id: &str, key_attestation_required: bool| RequestedCredential {
        configuration: configuration(id, key_attestation_required),
        holder_bindings: vec![HolderBinding {
            identifier: dummy_identifier(),
            key: key.clone(),
            wua_proof: None,
        }],
    };
    let mut requested_credentials = vec![
        requested("a", true),
        requested("b", false),
        requested("c", true),
    ];
    let interaction_data = HolderInteractionData {
        issuer_url: "http://issuer".to_string(),
        credential_endpoint: "http://issuer/credential".to_string(),
        token_endpoint: None,
        notification_endpoint: None,
        nonce_endpoint: None,
        challenge_endpoint: None,
        grants: None,
        continue_issuance: None,
        batch_size: None,
        access_token: None,
        access_token_expires_at: None,
        refresh_token: None,
        refresh_token_expires_at: None,
        token_endpoint_auth_methods_supported: None,
        client_attestation_pop_signing_alg_values_supported: None,
        issuer_display: None,
        credential_request_encryption: None,
        credential_response_encryption: None,
        protocol: "OPENID4VCI_FINAL1".to_string(),
        credential_configurations: requested_credentials
            .iter()
            .map(|requested| requested.configuration.clone())
            .collect(),
    };

    let wia_tokens = protocol
        .prepare_wallet_attestations(
            &interaction_data,
            &mut requested_credentials,
            Uuid::new_v4().into(),
            &[AttestationType::WUA],
        )
        .await
        .unwrap();

    assert!(wia_tokens.is_none());
    assert_eq!(
        requested_credentials
            .iter()
            .flat_map(|requested| &requested.holder_bindings)
            .map(|binding| binding.wua_proof.clone())
            .collect::<Vec<_>>(),
        vec![Some("wua".to_string()), None, Some("wua".to_string())]
    );
}

fn text(field: LocalizedTextField, lang: &str, value: &str) -> LocalizedText {
    let now = now_utc();
    LocalizedText {
        entity_id: uuid::Uuid::new_v4().into(),
        field,
        created_date: now,
        last_modified: now,
        lang: lang.to_owned(),
        value: value.to_owned(),
        entity_type: LocalizedTextEntityType::Identifier,
    }
}

#[test]
fn falls_back_to_default_language_when_no_name_translations() {
    let result = build_issuer_display("Plain name", &[], Some("data:image/png;base64,AAAA"), "en");

    assert_eq!(
        result,
        vec![IssuerDisplay {
            name: "Plain name".to_string(),
            locale: Some("en".to_string()),
            logo: Some(Image {
                uri: "data:image/png;base64,AAAA".to_string(),
                alt_text: None,
            }),
        }]
    );
}

#[test]
fn one_entry_per_name_language_with_logo_and_matching_alt_text() {
    let translations = vec![
        text(LocalizedTextField::Name, "en", "English name"),
        text(LocalizedTextField::Name, "de", "Deutscher Name"),
        text(LocalizedTextField::LogoAltText, "de", "Logo Beschreibung"),
    ];

    let mut result = build_issuer_display("Plain", &translations, Some("https://logo"), "en");
    result.sort_by(|a, b| a.locale.cmp(&b.locale));

    assert_eq!(
        result,
        vec![
            IssuerDisplay {
                name: "Deutscher Name".to_string(),
                locale: Some("de".to_string()),
                logo: Some(Image {
                    uri: "https://logo".to_string(),
                    alt_text: Some("Logo Beschreibung".to_string()),
                }),
            },
            IssuerDisplay {
                name: "English name".to_string(),
                locale: Some("en".to_string()),
                logo: Some(Image {
                    uri: "https://logo".to_string(),
                    alt_text: None,
                }),
            },
        ]
    );
}

#[test]
fn no_logo_when_identifier_has_none() {
    let translations = vec![text(LocalizedTextField::Name, "en", "Name")];

    let result = build_issuer_display("Plain", &translations, None, "en");

    assert_eq!(result.len(), 1);
    assert!(result[0].logo.is_none());
}
