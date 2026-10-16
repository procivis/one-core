use std::str::FromStr;
use std::sync::{Arc, Mutex};

use assert2::let_assert;
use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use indexmap::IndexMap;
use mockall::predicate::{always, eq};
use one_crypto::Hasher;
use one_crypto::encryption::encrypt_data;
use one_crypto::hasher::sha256::SHA256;
use one_crypto::jwe::{Header, build_jwe, decrypt_jwe_payload};
use secrecy::{SecretSlice, SecretString};
use serde_json::{Value, json};
use shared_types::{CredentialFormat, EntityId, KeyId};
use similar_asserts::assert_eq;
use standardized_types::etsi_119_472::disclosure_policy::{DisclosurePolicy, PolicyType};
use standardized_types::iana::{EncryptionAlgorithm, EncryptionKeyManagementAlgorithm};
use standardized_types::jwe::CompressionAlgorithm;
use standardized_types::jwk::{Jwks, PublicJwk, PublicJwkEc};
use standardized_types::oauth2::authorization_server_metadata::AuthorizationServerMetadata;
use standardized_types::oauth2::dpop::{DPOP_JWT_TYPE, DPoPClaims};
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
use super::dpop::DpopContext;
use super::model::{
    HolderBinding, HolderCredentialConfiguration, HolderInteractionData,
    OpenID4VCIIssuerInteractionDataDTO, RequestedCredential,
};
use super::service::{build_issuer_display, calculate_mandatory_claims, create_credential_offer};
use crate::clock::now_utc;
use crate::config::core_config::{
    CoreConfig, DatatypeConfig, DatatypeType, Fields, FormatType, KeyAlgorithmType,
    KeySecurityLevelType,
};
use crate::error::ErrorCodeMixinExt;
use crate::mapper::credential::stored_credential_claims;
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{
    Credential, CredentialCommon, CredentialFilterValue, CredentialRole, CredentialStateEnum,
    CredentialType, GetCredentialList,
};
use crate::model::credential_schema::{
    CredentialSchema, GetCredentialSchemaList, KeyStorageSecurity, UpdateCredentialSchemaRequest,
    WalletAttestation,
};
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::credential_schema_format_claim_schema::CredentialSchemaFormatClaimSchema;
use crate::model::did::{Did, DidType, KeyRole, RelatedKey};
use crate::model::history::{HistoryAction, HistoryEntityType, HistorySource};
use crate::model::identifier::{Identifier, IdentifierData, IdentifierState};
use crate::model::instance::{Instance, InstanceRole, InstanceStatus, WalletProviderType};
use crate::model::interaction::{Interaction, InteractionType};
use crate::model::key::Key;
use crate::model::localized_text::{LocalizedText, LocalizedTextEntityType, LocalizedTextField};
use crate::model::organisation::{Organisation, OrganisationConfiguration};
use crate::model::relation::Related;
use crate::model::wallet_attestation::AttestationType;
use crate::proto::certificate_validator::{MockCertificateValidator, ParsedCertificate};
use crate::proto::credential_schema::importer::MockCredentialSchemaImporter;
use crate::proto::http_client::reqwest_client::ReqwestClient;
use crate::proto::http_client::{
    Method as HttpMethod, MockHttpClient, Request, RequestBuilder, Response, StatusCode,
};
use crate::proto::identifier_creator::{
    CreateLocalIdentifierRequestType, IdentifierName, IdentifierRole, MockIdentifierCreator,
    RemoteIdentifierRelation,
};
use crate::proto::jwt::Jwt;
use crate::proto::jwt::model::DecomposedJwt;
use crate::proto::session_provider::NoSessionProvider;
use crate::proto::transaction_manager::NoTransactionManager;
use crate::proto::wallet_instance::{
    AttestationCheckResult, IssueWalletAttestationRequest, IssuedWalletUnitAttestations,
    MockHolderWalletUnitProto, WUARequestParams, WalletUnitStatusCheckResponse,
};
use crate::provider::blob_storage::provider::MockBlobStorageProvider;
use crate::provider::caching_loader::openid_metadata::MockOpenIDMetadataFetcher;
use crate::provider::credential_formatter::MockCredentialFormatter;
use crate::provider::credential_formatter::model::{IdentifierDetails, MockSignatureProvider};
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::did_method::{DidCreated, MockDidMethod};
use crate::provider::issuance_protocol::dto::ContinueIssuanceDTO;
use crate::provider::issuance_protocol::mapper::interaction_from_handle_invitation;
use crate::provider::issuance_protocol::model::{InvitationResponseEnum, IssuanceRefreshResponse};
use crate::provider::issuance_protocol::{
    HolderBindingInput, IssuanceProtocol, IssuanceProtocolError,
};
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
use crate::repository::did_repository::MockDidRepository;
use crate::repository::error::DataLayerError;
use crate::repository::history_repository::MockHistoryRepository;
use crate::repository::identifier_repository::MockIdentifierRepository;
use crate::repository::instance_repository::MockInstanceRepository;
use crate::repository::interaction_repository::MockInteractionRepository;
use crate::repository::key_repository::MockKeyRepository;
use crate::repository::wallet_attestation_repository::MockWalletAttestationRepository;
use crate::service::certificate::dto::CertificateX509AttributesDTO;
use crate::service::managed_instance::dto::IssueWalletUnitAttestationResponseDTO;
use crate::service::test_utilities::{
    CredentialBuilder, dummy_claim_schema, dummy_did, dummy_identifier, dummy_key,
    dummy_organisation, generic_formatter_capabilities, get_dummy_date,
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
    pub did_repository: MockDidRepository,
    pub wallet_attestation_repository: MockWalletAttestationRepository,
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
        Arc::new(inputs.did_repository),
        Arc::new(inputs.wallet_attestation_repository),
        Arc::new(NoTransactionManager),
    )
    .unwrap()
}

fn credential_schema_list(schema: Option<CredentialSchema>) -> GetCredentialSchemaList {
    let values = schema.into_iter().collect::<Vec<_>>();
    GetCredentialSchemaList {
        total_pages: Some(u64::from(!values.is_empty())),
        total_items: Some(values.len() as u64),
        values,
    }
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
    credential = CredentialBuilder {
        holder_identifier: Some(
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
        ),
        ..credential.into()
    }
    .build();
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
    credential = CredentialBuilder {
        holder_identifier: Some(holder_identifier.into()),
        ..credential.into()
    }
    .build();
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
    CredentialBuilder {
        consumed_at: None,
        role: CredentialRole::Issuer,
        r#type: CredentialType::Single,
        claims: vec![Claim {
            id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
                .unwrap()
                .into(),
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
        key: None,
        credential_blob_id: None,
        wallet_key_attestation_blob_id: None,
        wallet_instance_attestation_blob_id: None,
        webhook_url: None,
        parent: None,
        embedded_disclosure_policy: None,
        subscriber_information: None,
        common: CredentialCommon {
            expires_at: None,
            ecosystem: None,
            id: credential_id,
            created_date: now,
            issuance_date: None,
            last_modified: now,
            deleted_at: None,
            protocol: "OPENID4VCI_FINAL1".to_string(),
            redirect_uri: None,
            state: CredentialStateEnum::Created,
            schema: CredentialSchema {
                expiration: None,
                ecosystem: None,
                batch_size: None,
                allow_revocation: false,
                id: credential_schema_id,
                deleted_at: None,
                imported_source_url: "CORE_URL".to_string(),
                created_date: now,
                wallet_attestation: WalletAttestation {
                    require_instance_attestation: false,
                    key_storage_security_level: Some(KeyStorageSecurity::Basic),
                    preferred_key_storage_attestation_lifetime: None,
                    preferred_instance_attestation_lifetime: None,
                },
                last_modified: now,
                name: "schema".to_string(),
                formats: vec![format.clone()].into(),
                claim_schemas: vec![claim_schema].into(),
                layout_properties: None,
                organisation: dummy_organisation(None).into(),
                allow_suspension: true,
                transaction_code: None,
                translations: Default::default(),
                embedded_disclosure_policy: None,
            }
            .into(),
            interaction: Some(
                Interaction {
                    dpop_key: None,
                    id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
                        .unwrap()
                        .into(),
                    created_date: now,
                    data: Some(vec![1, 2, 3]),
                    last_modified: now,
                    organisation: dummy_organisation(None).into(),
                    interaction_type: InteractionType::Issuance,
                    expires_at: None,
                    ecosystem: None,
                    ecosystem_data: Default::default(),
                }
                .into(),
            ),
            profile: None,
        },
        format: Some(format.into()),
    }
    .build()
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
    let issuer_identifier_id = credential.issuer().unwrap().data.identifier.id();

    let credential_schema = credential.common().schema.as_ref().await.unwrap();
    let offer = create_credential_offer(
        &protocol_base_url,
        &credential.common().protocol,
        &interaction_id.to_string(),
        &credential_schema,
        &credential_schema.formats.as_ref().await.unwrap(),
        issuer_identifier_id,
    )
    .unwrap();

    assert_eq!(
        json!(&offer),
        json!({
            "credential_issuer": format!("BASE_URL/ssi/openid4vci/final-1.0/{}/{issuer_identifier_id}/c322aa7f-9803-410d-b891-939b279fb965", credential.common().protocol),
            "credential_configuration_ids" : [
                credential.common().schema.as_ref().await.unwrap().schema_id().await.unwrap(),
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
        data.configurations_for_credential(Uuid::new_v4().into())
            .next()
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
    credential.common_mut().interaction = None;
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
    credential.common_mut().interaction = None;

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
        .issuer_credential_mut()
        .unwrap()
        .data
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
        token_endpoint_auth_methods_supported: vec![],
        client_attestation_pop_signing_alg_values_supported: None,
        refresh_token_expires_at: None,
        continue_issuance: None,
        issuer_display: None,
        protocol: "OPENID4VCI_FINAL1".to_string(),
        credential_request_encryption: None,
        credential_response_encryption: None,
        dpop_signing_alg_values_supported: None,
        dpop_nonce: None,
        credential_configurations: vec![HolderCredentialConfiguration {
            credential_configuration_id: credential
                .common()
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
            credential_metadata: Some(CredentialMetadata {
                display: Some(vec![CredentialDisplay {
                    name: "Number credential".to_string(),
                    locale: Some("en".to_string()),
                    description: Some("Contains a number".to_string()),
                    ..Default::default()
                }]),
                claims: Some(vec![ClaimMetadata {
                    path: vec!["NUMBER".to_string()].into(),
                    display: Some(vec![ClaimDisplay {
                        name: Some("Number".to_string()),
                        locale: Some("en".to_string()),
                    }]),
                    mandatory: Some(true),
                    additional_values: Default::default(),
                }]),
            }),
            disclosure_policy: None,
            notification_id: None,
            credential_id: None,
            credential_schema_format_id: None,
        }],
    };

    let interaction = Interaction {
        dpop_key: None,
        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
            .unwrap()
            .into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        data: Some(serde_json::to_vec(&interaction_data).unwrap()),
        organisation: credential
            .common()
            .schema
            .as_ref()
            .await
            .unwrap()
            .organisation
            .to_owned(),
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
        move |_, _, _| {
            Ok(crate::service::test_utilities::parsed_credential(
                clone.clone(),
            ))
        }
    });
    formatter
        .expect_get_capabilities()
        .return_const(generic_formatter_capabilities());

    let formatter = Arc::new(formatter);
    let formatter_clone = formatter.clone();
    formatter_provider
        .expect_get_credential_formatter()
        .with(eq(CredentialFormat::from("JWT")))
        .returning(move |_| Ok(formatter_clone.clone()));
    formatter_provider
        .expect_get_formatter_by_type()
        .returning(move |_| Some(("JWT".into(), formatter.clone())));

    let mut schema = credential
        .common()
        .schema
        .as_ref()
        .await
        .unwrap()
        .to_owned();
    // Keep the stored claims independent from the formatter's parsed schema.
    let claim_schemas = schema.claim_schemas.as_ref().await.unwrap().to_owned();
    schema.claim_schemas = claim_schemas.into();
    credential_schema_repository
        .expect_get_credential_schema_list()
        .once()
        .returning(move |_| Ok(credential_schema_list(Some(schema.clone()))));
    credential_schema_repository
        .expect_update_credential_schema()
        .once()
        .withf(|_, request| {
            request.translations.as_ref().is_some_and(|translations| {
                translations.len() == 3
                    && translations.iter().any(|translation| {
                        translation.field == LocalizedTextField::Description
                            && translation.lang == "en"
                            && translation.value == "Contains a number"
                    })
                    && translations.iter().any(|translation| {
                        translation.entity_type == LocalizedTextEntityType::ClaimSchema
                            && translation.field == LocalizedTextField::Name
                            && translation.lang == "en"
                            && translation.value == "Number"
                    })
            })
        })
        .returning(|_, _| Ok(()));

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
    assert_eq!(single_credential.common().id, credential.common().id);
    assert_eq!(
        single_credential
            .holder()
            .unwrap()
            .data
            .issuer
            .identifier
            .id(),
        identifier.id
    );
    let accepted_schema = single_credential.common().schema.as_ref().await.unwrap();
    let schema_translations = accepted_schema.translations.as_ref().await.unwrap();
    assert_eq!(schema_translations.len(), 2);
    let claim_schemas = accepted_schema.claim_schemas.as_ref().await.unwrap();
    let claim_translations = claim_schemas[0].translations.as_ref().await.unwrap();
    assert_eq!(claim_translations.len(), 1);
    assert_eq!(claim_translations[0].value, "Number");
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
        token_endpoint_auth_methods_supported: vec![],
        client_attestation_pop_signing_alg_values_supported: None,
        refresh_token: None,
        refresh_token_expires_at: None,
        continue_issuance: None,
        issuer_display: None,
        protocol: "OPENID4VCI_FINAL1".to_string(),
        credential_request_encryption: None,
        credential_response_encryption: None,
        dpop_signing_alg_values_supported: None,
        dpop_nonce: None,
        credential_configurations: vec![HolderCredentialConfiguration {
            credential_configuration_id: credential
                .common()
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
            credential_schema_format_id: None,
        }],
    };

    let interaction = Interaction {
        dpop_key: None,
        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
            .unwrap()
            .into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        data: Some(serde_json::to_vec(&interaction_data).unwrap()),
        organisation: credential
            .common()
            .schema
            .as_ref()
            .await
            .unwrap()
            .organisation
            .to_owned(),
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
        move |_, _, _| {
            Ok(crate::service::test_utilities::parsed_credential(
                clone.clone(),
            ))
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

    let schema = credential
        .common()
        .schema
        .as_ref()
        .await
        .unwrap()
        .to_owned();
    credential_schema_repository
        .expect_get_credential_schema_list()
        .once()
        .returning(move |_| Ok(credential_schema_list(Some(schema.clone()))));

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
    assert_eq!(single_credential.common().id, credential.common().id);
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
        token_endpoint_auth_methods_supported: vec![],
        client_attestation_pop_signing_alg_values_supported: None,
        refresh_token_expires_at: None,
        continue_issuance: None,
        issuer_display: None,
        protocol: "OPENID4VCI_FINAL1".to_string(),
        credential_request_encryption: None,
        credential_response_encryption: None,
        dpop_signing_alg_values_supported: None,
        dpop_nonce: None,
        credential_configurations: vec![HolderCredentialConfiguration {
            credential_configuration_id: credential
                .common()
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
            credential_schema_format_id: None,
        }],
    };

    let interaction = Interaction {
        dpop_key: None,
        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
            .unwrap()
            .into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        data: Some(serde_json::to_vec(&interaction_data).unwrap()),
        organisation: credential
            .common()
            .schema
            .as_ref()
            .await
            .unwrap()
            .organisation
            .to_owned(),
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
        move |_, _, _| {
            Ok(crate::service::test_utilities::parsed_credential(
                clone.clone(),
            ))
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

    let schema = credential
        .common()
        .schema
        .as_ref()
        .await
        .unwrap()
        .to_owned();
    credential_schema_repository
        .expect_get_credential_schema_list()
        .once()
        .returning(move |_| Ok(credential_schema_list(Some(schema.clone()))));

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
    assert_eq!(create_credential.common().id, credential.common().id);
    assert!(matches!(create_credential, Credential::HolderSingle { .. }));
    assert_eq!(
        create_credential
            .holder()
            .unwrap()
            .data
            .issuer
            .identifier
            .id(),
        issuer_identifier.id
    );
}

/// Offer of a batch of two credentials, to be bound to auto-generated keys
async fn batch_autogenerated_binding_interaction(
    mock_server: &MockServer,
    credential: &Credential,
) -> Interaction {
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
        token_endpoint_auth_methods_supported: vec![],
        client_attestation_pop_signing_alg_values_supported: None,
        refresh_token_expires_at: None,
        continue_issuance: None,
        issuer_display: None,
        protocol: "OPENID4VCI_FINAL1".to_string(),
        credential_request_encryption: None,
        credential_response_encryption: None,
        dpop_signing_alg_values_supported: None,
        dpop_nonce: None,
        credential_configurations: vec![HolderCredentialConfiguration {
            credential_configuration_id: credential
                .common()
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
            credential_schema_format_id: None,
        }],
    };

    Interaction {
        dpop_key: None,
        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
            .unwrap()
            .into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        data: Some(serde_json::to_vec(&interaction_data).unwrap()),
        organisation: credential
            .common()
            .schema
            .as_ref()
            .await
            .unwrap()
            .organisation
            .to_owned(),
        interaction_type: InteractionType::Issuance,
        expires_at: None,
        ecosystem: None,
        ecosystem_data: Default::default(),
    }
}

/// Mocks for accepting [`batch_autogenerated_binding_interaction`], the issuer returns
/// `issued_credentials` of the two requested credentials
async fn batch_autogenerated_binding_inputs(
    credential: &Credential,
    issued_credentials: usize,
) -> TestInputs {
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
                    id: Uuid::new_v4().into(),
                    data: IdentifierData::Key(Related::from(key)),
                    ..dummy_identifier()
                })
            }
        });

    let issuer_identifier = credential
        .issuer()
        .unwrap()
        .data
        .identifier
        .as_ref()
        .await
        .unwrap()
        .to_owned();
    identifier_creator
        .expect_get_or_create_remote_identifier()
        .times(issued_credentials)
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
    formatter
        .expect_parse_credential()
        .times(issued_credentials)
        .returning({
            let clone = credential.clone();
            let claims = stored_credential_claims(credential).await.unwrap();
            let holder_keys = holder_keys.clone();
            move |_, _, _| {
                let mut guard = holder_keys.lock().unwrap();
                let key = guard.pop().unwrap();

                let id = Uuid::new_v4().into();
                let claims = claims
                    .iter()
                    .cloned()
                    .map(|mut claim| {
                        claim.id = Uuid::new_v4().into();
                        claim
                    })
                    .collect::<Vec<_>>();
                Ok(crate::service::test_utilities::parsed_credential({
                    let mut updated_credential = clone.clone();
                    updated_credential.common_mut().id = id;
                    updated_credential = CredentialBuilder {
                        claims: claims.into(),
                        holder_identifier: Some(
                            Identifier {
                                data: IdentifierData::Key(Related::from(key)),
                                ..dummy_identifier()
                            }
                            .into(),
                        ),
                        ..updated_credential.into()
                    }
                    .build();
                    updated_credential
                }))
            }
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

    // the configuration is accepted once any of its credentials is issued
    let accepted_configurations = usize::from(issued_credentials > 0);
    let schema = credential
        .common()
        .schema
        .as_ref()
        .await
        .unwrap()
        .to_owned();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    credential_schema_repository
        .expect_get_credential_schema_list()
        .times(accepted_configurations)
        .returning(move |_| Ok(credential_schema_list(Some(schema.clone()))));

    let mut interaction_repository = MockInteractionRepository::default();
    interaction_repository
        .expect_update_interaction()
        .times(accepted_configurations)
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

    let mut identifier_repository = MockIdentifierRepository::new();
    identifier_repository
        .expect_has_credential_references()
        .returning(|_| Ok(false));

    TestInputs {
        formatter_provider,
        key_provider,
        key_repository,
        identifier_creator,
        identifier_repository,
        key_algorithm_provider,
        key_security_level_provider,
        credential_schema_repository,
        holder_wallet_unit_repository,
        interaction_repository,
        config: dummy_config(),
        ..Default::default()
    }
}

#[tokio::test]
async fn test_holder_accept_credential_batch_autogenerated_binding() {
    let mock_server = MockServer::start().await;
    let credential = generic_credential_did();
    let interaction = batch_autogenerated_binding_interaction(&mock_server, &credential).await;

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

    let issuer_identifier = credential
        .issuer()
        .unwrap()
        .data
        .identifier
        .as_ref()
        .await
        .unwrap()
        .to_owned();
    let inputs = batch_autogenerated_binding_inputs(&credential, 2).await;
    let openid_provider = setup_protocol(inputs);

    let configuration_ids = configuration_ids(&interaction);
    let issuer_response = openid_provider
        .holder_accept_credential(interaction, None, None, configuration_ids)
        .await
        .unwrap()
        .issued
        .pop()
        .unwrap();
    let main_credential = &issuer_response.main_credential;
    assert!(matches!(
        main_credential.credential,
        Credential::HolderBatchParent { .. }
    ));
    assert_eq!(main_credential.serialized, None);
    let mut claim_ids = std::collections::HashSet::new();
    for item in &issuer_response.batch_items {
        let claims = item
            .credential
            .holder()
            .unwrap()
            .data
            .claims
            .as_ref()
            .await
            .unwrap();
        assert_eq!(claims.len(), 1);
        assert!(claim_ids.insert(claims[0].id));
        assert_eq!(claims[0].value.as_deref(), Some("123"));
        assert_eq!(
            claims[0].schema.id(),
            stored_credential_claims(&credential).await.unwrap()[0]
                .schema
                .id()
        );
    }

    let credentials = &issuer_response.batch_items;
    assert_eq!(credentials.len(), 2);
    assert_eq!(credentials[0].serialized, Some("credential1".into()));
    assert_eq!(credentials[1].serialized, Some("credential2".into()));
    assert!(matches!(
        credentials[0].credential,
        Credential::HolderBatchItem { .. }
    ));
    assert!(matches!(
        credentials[1].credential,
        Credential::HolderBatchItem { .. }
    ));
    assert_eq!(
        credentials[0]
            .credential
            .holder()
            .unwrap()
            .data
            .issuer
            .identifier
            .id(),
        issuer_identifier.id
    );
    assert_eq!(
        credentials[1]
            .credential
            .holder()
            .unwrap()
            .data
            .issuer
            .identifier
            .id(),
        issuer_identifier.id
    );
}

async fn mount_partial_batch_issuance(mock_server: &MockServer) {
    Mock::given(method(Method::POST))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "access_token": "321",
                "token_type": "Bearer",
                "expires_in": crate::clock::now_utc().unix_timestamp() + 3600,
            }
        )))
        .expect(1)
        .mount(mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/nonce"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "c_nonce": "123"
            }
        )))
        .expect(1)
        .mount(mock_server)
        .await;

    // the issuer issues only one of the two requested credentials
    Mock::given(method(Method::POST))
        .and(path("/credential"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "credentials": [
                    { "credential": "credential1"}
                ],
                "notification_id": "notification_id"
            }
        )))
        .expect(1)
        .mount(mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/notification"))
        .and(body_json(json!({
            "notification_id": "notification_id",
            "event": "credential_accepted"
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(mock_server)
        .await;
}

#[tokio::test]
async fn test_holder_accept_credential_batch_deletes_unused_autogenerated_binding() {
    let mock_server = MockServer::start().await;
    let credential = generic_credential_did();
    let interaction = batch_autogenerated_binding_interaction(&mock_server, &credential).await;

    mount_partial_batch_issuance(&mock_server).await;

    let mut inputs = batch_autogenerated_binding_inputs(&credential, 1).await;
    let deleted_identifier_id = Arc::new(Mutex::new(None));
    inputs
        .identifier_repository
        .expect_hard_delete()
        .once()
        .returning({
            let deleted_identifier_id = deleted_identifier_id.clone();
            move |id| {
                *deleted_identifier_id.lock().unwrap() = Some(*id);
                Ok(())
            }
        });
    let deleted_key_id = Arc::new(Mutex::new(None));
    inputs
        .key_repository
        .expect_hard_delete()
        .once()
        .returning({
            let deleted_key_id = deleted_key_id.clone();
            move |id| {
                *deleted_key_id.lock().unwrap() = Some(*id);
                Ok(())
            }
        });
    let openid_provider = setup_protocol(inputs);

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
        Some("credential1".into())
    );
    assert!(issuer_response.batch_items.is_empty());

    // the binding of the issued credential stays, the other one is deleted
    let issued_credential = &issuer_response.main_credential.credential;
    assert!(matches!(issued_credential, Credential::HolderSingle { .. }));
    let binding = issued_credential
        .holder()
        .unwrap()
        .data
        .binding
        .as_ref()
        .unwrap();
    let deleted_identifier_id = deleted_identifier_id.lock().unwrap().take().unwrap();
    assert_ne!(deleted_identifier_id, binding.identifier.id());
    let deleted_key_id = deleted_key_id.lock().unwrap().take().unwrap();
    assert_ne!(deleted_key_id, binding.key.id());
}

#[tokio::test]
async fn test_unused_binding_cleanup_preserves_referenced_binding() {
    let binding = || {
        let key = Key {
            id: Uuid::new_v4().into(),
            ..dummy_key()
        };
        HolderBinding {
            identifier: Identifier {
                id: Uuid::new_v4().into(),
                autogenerated: true,
                data: IdentifierData::Key(key.clone().into()),
                ..dummy_identifier()
            },
            key,
            wua_proof: None,
        }
    };
    let retained = binding();
    let unused = binding();
    let used = binding();
    let mut inputs = TestInputs::default();
    inputs
        .identifier_repository
        .expect_has_credential_references()
        .with(eq(retained.identifier.id))
        .once()
        .returning(|_| Ok(true));
    inputs
        .identifier_repository
        .expect_has_credential_references()
        .with(eq(unused.identifier.id))
        .once()
        .returning(|_| Ok(false));
    inputs
        .identifier_repository
        .expect_hard_delete()
        .with(eq(unused.identifier.id))
        .once()
        .returning(|_| Ok(()));
    inputs
        .key_repository
        .expect_hard_delete()
        .with(eq(unused.key.id))
        .once()
        .returning(|_| Ok(()));

    setup_protocol(inputs)
        .delete_unused_autogenerated_bindings(
            &[retained, unused, used.clone()],
            std::collections::HashSet::from([used.identifier.id]),
        )
        .await;
}

#[tokio::test]
async fn test_holder_accept_credential_succeeds_when_deleting_unused_binding_fails() {
    let mock_server = MockServer::start().await;
    let credential = generic_credential_did();
    let interaction = batch_autogenerated_binding_interaction(&mock_server, &credential).await;

    mount_partial_batch_issuance(&mock_server).await;

    let mut inputs = batch_autogenerated_binding_inputs(&credential, 1).await;
    inputs
        .identifier_repository
        .expect_hard_delete()
        .once()
        .returning(|_| Err(DataLayerError::Db(anyhow::anyhow!("hard delete failed"))));
    let openid_provider = setup_protocol(inputs);

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
        Some("credential1".into())
    );
}

#[tokio::test]
async fn test_holder_accept_credential_deletes_autogenerated_bindings_when_token_request_fails() {
    let mock_server = MockServer::start().await;
    let credential = generic_credential_did();
    let interaction = batch_autogenerated_binding_interaction(&mock_server, &credential).await;

    Mock::given(method(Method::POST))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!(
            {
                "error": "invalid_grant"
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut inputs = batch_autogenerated_binding_inputs(&credential, 0).await;
    inputs
        .identifier_repository
        .expect_hard_delete()
        .times(2)
        .returning(|_| Ok(()));
    inputs
        .key_repository
        .expect_hard_delete()
        .times(2)
        .returning(|_| Ok(()));
    let openid_provider = setup_protocol(inputs);

    let configuration_ids = configuration_ids(&interaction);
    let result = openid_provider
        .holder_accept_credential(interaction, None, None, configuration_ids)
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_holder_refresh_credential_preserves_error_when_deleting_unused_binding_fails() {
    let mock_server = MockServer::start().await;
    let credential = generic_credential_did();
    let mut parent = CredentialBuilder {
        role: CredentialRole::Holder,
        r#type: CredentialType::BatchParent,
        ..credential.clone().into()
    }
    .build();
    parent.common_mut().state = CredentialStateEnum::Accepted;
    let item = CredentialBuilder {
        common: CredentialCommon {
            id: Uuid::new_v4().into(),
            state: CredentialStateEnum::Accepted,
            ..credential.common().clone()
        },
        role: CredentialRole::Holder,
        r#type: CredentialType::BatchItem,
        parent: Some(parent.clone().into()),
        key: None,
        ..credential.clone().into()
    }
    .build();
    let mut interaction = batch_autogenerated_binding_interaction(&mock_server, &credential).await;
    let mut data: HolderInteractionData =
        serde_json::from_slice(interaction.data.as_ref().unwrap()).unwrap();
    data.credential_configurations[0].credential_id = Some(parent.common().id);
    data.credential_configurations[0].credential_schema_format_id =
        Some(item.holder().unwrap().data.format.id());

    Mock::given(method(Method::POST))
        .and(path("/nonce"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"c_nonce": "123"})))
        .expect(1)
        .mount(&mock_server)
        .await;
    // The issuer's response fails before any refreshed credential is stored.
    Mock::given(method(Method::POST))
        .and(path("/credential"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut inputs = batch_autogenerated_binding_inputs(&credential, 0).await;
    inputs
        .credential_repository
        .expect_get_credentials_by_interaction_id()
        .once()
        .return_once(move |_| Ok(vec![parent]));
    inputs
        .credential_repository
        .expect_get_credential_list()
        .times(2)
        .returning(move |_| {
            Ok(GetCredentialList {
                values: vec![item.clone()],
                total_items: None,
                total_pages: None,
            })
        });
    inputs
        .identifier_repository
        .expect_hard_delete()
        .once()
        .returning(|_| Err(DataLayerError::Db(anyhow::anyhow!("hard delete failed"))));
    let protocol = setup_protocol(inputs);
    data.access_token = Some(
        one_crypto::encryption::encrypt_string(&"access-token".into(), &protocol.params.encryption)
            .unwrap(),
    );
    interaction.data = Some(serde_json::to_vec(&data).unwrap());

    let result = protocol.holder_refresh_credential(&interaction, None).await;

    assert!(
        matches!(&result, Err(IssuanceProtocolError::Failed(message)) if message == "Missing credentials"),
        "Unexpected refresh result: {result:?}"
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
        .issuer_credential_mut()
        .unwrap()
        .data
        .holder_identifier
        .as_mut()
        .unwrap()
        .as_mut()
        .await
        .unwrap()
        .data = IdentifierData::Key(Related::from(key.clone()));

    let credential_configuration_id = credential
        .common()
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
        token_endpoint_auth_methods_supported: vec![],
        client_attestation_pop_signing_alg_values_supported: None,
        refresh_token_expires_at: None,
        issuer_display: None,
        continue_issuance: None,
        protocol: "OPENID4VCI_FINAL1".to_string(),
        credential_request_encryption: None,
        credential_response_encryption: None,
        dpop_signing_alg_values_supported: None,
        dpop_nonce: None,
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
            credential_schema_format_id: None,
        }],
    };

    let interaction = Interaction {
        dpop_key: None,
        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
            .unwrap()
            .into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        data: Some(serde_json::to_vec(&interaction_data).unwrap()),
        organisation: credential
            .common()
            .schema
            .as_ref()
            .await
            .unwrap()
            .organisation
            .to_owned(),
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
        move |_, _, _| {
            Ok(crate::service::test_utilities::parsed_credential(
                clone.clone(),
            ))
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

    let schema = credential
        .common()
        .schema
        .as_ref()
        .await
        .unwrap()
        .to_owned();
    credential_schema_repository
        .expect_get_credential_schema_list()
        .once()
        .returning(move |_| Ok(credential_schema_list(Some(schema.clone()))));

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
        main_credential
            .holder()
            .unwrap()
            .data
            .issuer
            .identifier
            .id(),
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
        credential.common_mut().state = CredentialStateEnum::Accepted;
        credential = CredentialBuilder {
            key: Some(dummy_key().into()),
            ..credential.into()
        }
        .build();

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
            token_endpoint_auth_methods_supported: vec![],
            client_attestation_pop_signing_alg_values_supported: None,
            continue_issuance: None,
            issuer_display: None,
            protocol: "OPENID4VCI_FINAL1".to_string(),
            credential_request_encryption: None,
            credential_response_encryption: None,
            dpop_signing_alg_values_supported: None,
            dpop_nonce: None,
            credential_configurations: vec![HolderCredentialConfiguration {
                credential_configuration_id: credential
                    .common()
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
                credential_schema_format_id: None,
            }],
        };

        credential.common_mut().interaction = Some(
            Interaction {
                dpop_key: None,
                id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
                    .unwrap()
                    .into(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                data: Some(serde_json::to_vec(&interaction_data).unwrap()),
                organisation: dummy_organisation(None).into(),
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

    let credential_schema_id = credential.common().schema.id();
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
            credential_schema_id,
            credential.common().id
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

    let url = Url::parse(&format!("openid-credential-offer://?credential_offer_uri=http%3A%2F%2F{}%2Fssi%2Fopenid4vci%2Ffinal-1.0%2F{}%2Foffer%2F{}", issuer_url.authority(), credential_schema_id, credential.common().id)).unwrap();

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
    inner_continue_issuance_test(true, false, None).await;
}

#[tokio::test]
async fn test_continue_issuance_with_credential_configuration_ids_success() {
    inner_continue_issuance_test(false, true, None).await;
}

#[tokio::test]
async fn test_continue_issuance_with_scope_and_credential_configuration_ids_success() {
    inner_continue_issuance_test(true, true, None).await;
}

#[tokio::test]
async fn test_continue_issuance_reuses_authorization_dpop_key() {
    inner_continue_issuance_test(true, false, Some(Uuid::new_v4().into())).await;
}

async fn inner_continue_issuance_test(
    with_scope: bool,
    with_credential_configuration_ids: bool,
    dpop_key: Option<KeyId>,
) {
    let credential = generic_credential_did();

    let credential_schema_id = credential.common().schema.id();
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
                // the authorization code can only be redeemed with the key it is bound to
                assert_eq!(i.dpop_key.as_ref().map(Related::id), dpop_key);
                let mut guard = capture_interaction_id.lock().unwrap();
                *guard = Some(i.id);
                Ok(i.id)
            }
        });

    // no new DPoP key is generated
    let mut key_repository = MockKeyRepository::new();
    key_repository.expect_create_key().never();

    let protocol = setup_protocol(TestInputs {
        metadata_cache,
        interaction_repository,
        key_repository,
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
            dpop_key,
        )
        .await
        .unwrap();

    assert_eq!(
        capture_interaction_id.lock().unwrap().unwrap(),
        result.interaction_id
    );
}

fn dpop_authorization_server_metadata(
    dpop_signing_alg_values_supported: Option<Vec<&str>>,
) -> AuthorizationServerMetadata {
    serde_json::from_value(json!({
        "issuer": "https://authorization.server",
        "authorization_endpoint": "https://authorization.server/authorize",
        "dpop_signing_alg_values_supported": dpop_signing_alg_values_supported,
    }))
    .unwrap()
}

#[tokio::test]
async fn test_holder_prepare_authorization_dpop_key() {
    // given
    let mut key_provider = MockKeyProvider::new();
    key_provider
        .expect_get_key_storage()
        .once()
        .with(eq("INTERNAL"))
        .returning(|_| {
            let mut storage = MockKeyStorage::new();
            storage.expect_generate().once().returning(|_, _, _| {
                Ok(StorageGeneratedKey {
                    public_key: vec![1, 2, 3],
                    key_reference: Some(vec![]),
                })
            });
            Ok(Arc::new(storage))
        });

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_jose_alg()
        .with(eq("ES256"))
        .returning(|_| Some((KeyAlgorithmType::Ecdsa, Arc::new(MockKeyAlgorithm::new()))));
    key_algorithm_provider
        .expect_reconstruct_key()
        .once()
        .withf(|algorithm, public_key, _, _| {
            *algorithm == KeyAlgorithmType::Ecdsa && public_key == [1, 2, 3]
        })
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

    let mut key_repository = MockKeyRepository::new();
    key_repository
        .expect_create_key()
        .once()
        .returning(|key| Ok(key.id));

    let mut params = test_params("openid-credential-offer");
    params["holderDpopKeyStorage"] = json!("INTERNAL");
    let protocol = setup_protocol(TestInputs {
        key_provider,
        key_algorithm_provider,
        key_repository,
        params: Some(params),
        ..Default::default()
    });

    // when
    let result = protocol
        .holder_prepare_authorization_dpop_key(
            &dummy_organisation(None),
            &dpop_authorization_server_metadata(Some(vec!["ES256"])),
        )
        .await
        .unwrap()
        .unwrap();

    // then
    assert_eq!(result.key.storage_type, "INTERNAL");
    assert_eq!(result.key.key_type, "ECDSA");
    assert!(result.key.autogenerated);
    // RFC 7638 JWK SHA-256 thumbprint of the key
    assert_eq!(result.jkt, "u7vrjwUEqr4_WVk1nfCx7nhirx2CrSvP9yUbAN4FNiQ");
}

#[tokio::test]
async fn test_holder_prepare_authorization_dpop_key_without_dpop_support() {
    // given
    let mut key_repository = MockKeyRepository::new();
    key_repository.expect_create_key().never();

    let mut params = test_params("openid-credential-offer");
    params["holderDpopKeyStorage"] = json!("INTERNAL");
    let protocol = setup_protocol(TestInputs {
        key_repository,
        params: Some(params),
        ..Default::default()
    });

    // when
    let result = protocol
        .holder_prepare_authorization_dpop_key(
            &dummy_organisation(None),
            &dpop_authorization_server_metadata(None),
        )
        .await
        .unwrap();

    // then
    assert!(result.is_none());
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
    credential.common_mut().interaction = None;

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
                preferred_key_storage_status_period: None,
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
        token_endpoint_auth_methods_supported: vec![],
        client_attestation_pop_signing_alg_values_supported: None,
        continue_issuance: None,
        issuer_display: None,
        protocol: "OPENID4VCI_FINAL1".to_string(),
        credential_request_encryption: None,
        credential_response_encryption: None,
        dpop_signing_alg_values_supported: None,
        dpop_nonce: None,
        credential_configurations: vec![HolderCredentialConfiguration {
            credential_configuration_id: credential
                .common()
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
            credential_schema_format_id: None,
        }],
    };

    let interaction = Interaction {
        dpop_key: None,
        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
            .unwrap()
            .into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        data: Some(serde_json::to_vec(&interaction_data).unwrap()),
        organisation: credential
            .common()
            .schema
            .as_ref()
            .await
            .unwrap()
            .organisation
            .to_owned(),
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
        .issuer_credential_mut()
        .unwrap()
        .data
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
                preferred_key_storage_status_period: None,
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
        token_endpoint_auth_methods_supported: vec![],
        client_attestation_pop_signing_alg_values_supported: None,
        continue_issuance: None,
        issuer_display: None,
        protocol: "OPENID4VCI_FINAL1".to_string(),
        credential_request_encryption: None,
        credential_response_encryption: None,
        dpop_signing_alg_values_supported: None,
        dpop_nonce: None,
        credential_configurations: vec![HolderCredentialConfiguration {
            credential_configuration_id: credential
                .common()
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
            credential_schema_format_id: None,
        }],
    };

    let interaction = Interaction {
        dpop_key: None,
        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
            .unwrap()
            .into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        data: Some(serde_json::to_vec(&interaction_data).unwrap()),
        organisation: credential
            .common()
            .schema
            .as_ref()
            .await
            .unwrap()
            .organisation
            .to_owned(),
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
        move |_, _, _| {
            Ok(crate::service::test_utilities::parsed_credential(
                clone.clone(),
            ))
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

    let schema = credential
        .common()
        .schema
        .as_ref()
        .await
        .unwrap()
        .to_owned();
    credential_schema_repository
        .expect_get_credential_schema_list()
        .once()
        .returning(move |_| Ok(credential_schema_list(Some(schema.clone()))));

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
                wallet_attestations: Default::default(),
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
    holder_wallet_unit_proto
        .expect_check_attestation_status()
        .once()
        .with(
            eq("wua_attestation_jwt"),
            eq(AttestationType::KeyAttestation),
        )
        .returning(|_, _| {
            Ok(AttestationCheckResult {
                status: WalletUnitStatusCheckResponse::Active,
                expiration_date: None,
            })
        });

    let mut wallet_attestation_repository = MockWalletAttestationRepository::new();
    wallet_attestation_repository
        .expect_create()
        .once()
        .returning(|attestation| Ok(attestation.id));

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
        wallet_attestation_repository,
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
        token_endpoint_auth_methods_supported: vec![],
        client_attestation_pop_signing_alg_values_supported: None,
        refresh_token_expires_at: None,
        issuer_display: None,
        continue_issuance: None,
        protocol: "OPENID4VCI_FINAL1".to_string(),
        credential_request_encryption: None,
        credential_response_encryption: None,
        dpop_signing_alg_values_supported: None,
        dpop_nonce: None,
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
            credential_schema_format_id: None,
        }],
    };

    Interaction {
        dpop_key: None,
        id: Uuid::new_v4().into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        data: Some(serde_json::to_vec(&interaction_data).unwrap()),
        organisation: credential
            .common()
            .schema
            .as_ref()
            .await
            .unwrap()
            .organisation
            .to_owned(),
        interaction_type: InteractionType::Issuance,
        expires_at: None,
        ecosystem: None,
        ecosystem_data: Default::default(),
    }
}

fn capture_credential_schema_update(
    repository: &mut MockCredentialSchemaRepository,
) -> Arc<Mutex<Option<UpdateCredentialSchemaRequest>>> {
    let captured_update = Arc::new(Mutex::new(None));
    let captured_update_clone = captured_update.clone();
    repository
        .expect_update_credential_schema()
        .once()
        .returning(move |_, update| {
            *captured_update_clone.lock().unwrap() = Some(update);
            Ok(())
        });
    captured_update
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
        move |_, _, _| {
            Ok(crate::service::test_utilities::parsed_credential(
                clone.clone(),
            ))
        }
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
        .expect_get_credential_schema_list()
        .once()
        .returning(|_| Ok(credential_schema_list(None)));
    credential_schema_repository
        .expect_update_credential_schema()
        .never();

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
        move |_, _, _| {
            Ok(crate::service::test_utilities::parsed_credential(
                clone.clone(),
            ))
        }
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
        .expect_get_credential_schema_list()
        .once()
        .returning(|_| Ok(credential_schema_list(None)));
    credential_schema_repository
        .expect_update_credential_schema()
        .never();

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
            path: vec!["NUMBER".to_string()].into(),
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
        move |_, _, _| {
            Ok(crate::service::test_utilities::parsed_credential(
                clone.clone(),
            ))
        }
    });
    formatter
        .expect_get_capabilities()
        .return_const(generic_formatter_capabilities());

    let formatter = Arc::new(formatter);
    let formatter_clone = formatter.clone();
    formatter_provider
        .expect_get_credential_formatter()
        .returning(move |_| Ok(formatter_clone.clone()));
    formatter_provider
        .expect_get_formatter_by_type()
        .returning(move |_| Some(("JWT".into(), formatter.clone())));

    credential_schema_repository
        .expect_get_credential_schema_list()
        .once()
        .returning(|_| Ok(credential_schema_list(None)));
    credential_schema_repository
        .expect_update_credential_schema()
        .never();

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

#[rstest::rstest]
#[case::all_changed(true, true, true, "en")]
#[case::schema_name_changed(true, false, false, "en")]
#[case::schema_description_changed(false, true, false, "en")]
#[case::claim_name_changed(false, false, true, "en")]
#[case::unchanged(false, false, false, "en")]
#[case::new_language(false, false, false, "de")]
#[tokio::test]
async fn test_holder_accept_credential_updates_only_changed_translations_from_metadata(
    #[case] schema_name_changed: bool,
    #[case] schema_description_changed: bool,
    #[case] claim_name_changed: bool,
    #[case] stored_language: &str,
) {
    // GIVEN
    let mock_server = MockServer::start().await;
    let credential = generic_credential_key();
    let mut stored_schema = credential
        .common()
        .schema
        .as_ref()
        .await
        .unwrap()
        .to_owned();
    let stored_schema_id = stored_schema.id;
    let now = get_dummy_date();
    stored_schema.translations = vec![
        LocalizedText {
            entity_id: stored_schema.id.into(),
            field: LocalizedTextField::Name,
            created_date: now,
            last_modified: now,
            lang: stored_language.to_string(),
            value: if schema_name_changed {
                "Old credential name"
            } else {
                "Updated credential name"
            }
            .to_string(),
            entity_type: LocalizedTextEntityType::CredentialSchema,
        },
        LocalizedText {
            entity_id: stored_schema.id.into(),
            field: LocalizedTextField::Description,
            created_date: now,
            last_modified: now,
            lang: stored_language.to_string(),
            value: if schema_description_changed {
                "Old credential description"
            } else {
                "Updated credential description"
            }
            .to_string(),
            entity_type: LocalizedTextEntityType::CredentialSchema,
        },
    ]
    .into();
    let mut stored_claim_schemas = stored_schema
        .claim_schemas
        .as_ref()
        .await
        .unwrap()
        .to_owned();
    let number_claim = stored_claim_schemas
        .iter_mut()
        .find(|claim_schema| claim_schema.key == "NUMBER")
        .unwrap();
    let number_claim_id = number_claim.id;
    number_claim.translations = vec![LocalizedText {
        entity_id: number_claim.id.into(),
        field: LocalizedTextField::Name,
        created_date: now,
        last_modified: now,
        lang: stored_language.to_string(),
        value: if claim_name_changed {
            "Old number name"
        } else {
            "Updated number name"
        }
        .to_string(),
        entity_type: LocalizedTextEntityType::ClaimSchema,
    }]
    .into();
    stored_schema.claim_schemas = stored_claim_schemas.into();

    let credential_metadata = CredentialMetadata {
        display: Some(vec![CredentialDisplay {
            name: "Updated credential name".to_string(),
            locale: Some("en".to_string()),
            description: Some("Updated credential description".to_string()),
            ..Default::default()
        }]),
        claims: Some(vec![ClaimMetadata {
            path: vec!["NUMBER".to_string()].into(),
            display: Some(vec![ClaimDisplay {
                name: Some("Updated number name".to_string()),
                locale: Some("en".to_string()),
            }]),
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

    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    credential_schema_repository
        .expect_get_credential_schema_list()
        .once()
        .return_once(move |_| Ok(credential_schema_list(Some(stored_schema))));
    let expected_changes = [
        schema_name_changed || stored_language != "en",
        schema_description_changed || stored_language != "en",
        claim_name_changed || stored_language != "en",
    ];
    let expected_change_count = expected_changes.iter().filter(|changed| **changed).count();
    let captured_update = if expected_change_count > 0 {
        Some(capture_credential_schema_update(
            &mut credential_schema_repository,
        ))
    } else {
        credential_schema_repository
            .expect_update_credential_schema()
            .never();
        None
    };
    let openid_provider =
        provider_for_credential_acceptance(&credential, credential_schema_repository).await;

    // WHEN
    let key = dummy_key();
    let configuration_ids = configuration_ids(&interaction);
    let mut response = openid_provider
        .holder_accept_credential(
            interaction,
            Some(holder_binding_input(key)),
            None,
            configuration_ids,
        )
        .await
        .unwrap();

    // THEN
    let accepted_credential = response.issued.pop().unwrap().main_credential.credential;
    assert_eq!(accepted_credential.common().schema.id(), stored_schema_id);
    let accepted_schema = accepted_credential.common().schema.as_ref().await.unwrap();
    let schema_translations = accepted_schema.translations.as_ref().await.unwrap();
    assert_eq!(schema_translations.len(), 2);
    assert_eq!(schema_translations[0].value, "Updated credential name");
    assert_eq!(
        schema_translations[1].value,
        "Updated credential description"
    );
    let claim_schemas = accepted_schema.claim_schemas.as_ref().await.unwrap();
    let claim_translations = claim_schemas[0].translations.as_ref().await.unwrap();
    assert_eq!(claim_translations.len(), 1);
    assert_eq!(claim_translations[0].value, "Updated number name");

    let Some(captured_update) = captured_update else {
        return;
    };
    let update = captured_update.lock().unwrap().take().unwrap();
    assert!(update.claim_schemas.is_none());
    assert!(update.formats.is_none());
    let translations = update.translations.expect("translations not persisted");
    assert_eq!(translations.len(), expected_change_count);
    assert_eq!(
        translations.iter().any(|translation| {
            translation.entity_id == EntityId::from(stored_schema_id)
                && translation.entity_type == LocalizedTextEntityType::CredentialSchema
                && translation.field == LocalizedTextField::Name
                && translation.lang == "en"
                && translation.value == "Updated credential name"
        }),
        expected_changes[0]
    );
    assert_eq!(
        translations.iter().any(|translation| {
            translation.entity_id == EntityId::from(stored_schema_id)
                && translation.entity_type == LocalizedTextEntityType::CredentialSchema
                && translation.field == LocalizedTextField::Description
                && translation.lang == "en"
                && translation.value == "Updated credential description"
        }),
        expected_changes[1]
    );
    assert_eq!(
        translations.iter().any(|translation| {
            translation.entity_id == EntityId::from(number_claim_id)
                && translation.entity_type == LocalizedTextEntityType::ClaimSchema
                && translation.field == LocalizedTextField::Name
                && translation.lang == "en"
                && translation.value == "Updated number name"
        }),
        expected_changes[2]
    );
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
        token_endpoint_auth_methods_supported: vec![],
        client_attestation_pop_signing_alg_values_supported: None,
        refresh_token_expires_at: None,
        issuer_display: None,
        continue_issuance: None,
        protocol: "OPENID4VCI_FINAL1".to_string(),
        credential_request_encryption: None,
        credential_response_encryption: None,
        dpop_signing_alg_values_supported: None,
        dpop_nonce: None,
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
            credential_schema_format_id: None,
        }],
    };

    let interaction = Interaction {
        dpop_key: None,
        id: Uuid::new_v4().into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        data: Some(serde_json::to_vec(&interaction_data).unwrap()),
        organisation: credential
            .common()
            .schema
            .as_ref()
            .await
            .unwrap()
            .organisation
            .to_owned(),
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
        move |_, _, _| {
            Ok(crate::service::test_utilities::parsed_credential(
                clone.clone(),
            ))
        }
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
        .expect_get_credential_schema_list()
        .once()
        .returning(|_| Ok(credential_schema_list(None)));

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
            .holder()
            .unwrap()
            .data
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
        dpop_signing_alg_values_supported: None,
        dpop_nonce: None,
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
        token_endpoint_auth_methods_supported: vec![],
        client_attestation_pop_signing_alg_values_supported: None,
        refresh_token_expires_at: None,
        continue_issuance: None,
        issuer_display: None,
        protocol: "OPENID4VCI_FINAL1".to_string(),
        credential_request_encryption,
        credential_response_encryption,
        credential_configurations: vec![HolderCredentialConfiguration {
            credential_configuration_id: credential
                .common()
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
            credential_schema_format_id: None,
        }],
    }
}

async fn interaction_for(
    credential: &Credential,
    interaction_data: &HolderInteractionData,
) -> Interaction {
    Interaction {
        dpop_key: None,
        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
            .unwrap()
            .into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        data: Some(serde_json::to_vec(interaction_data).unwrap()),
        organisation: credential
            .common()
            .schema
            .as_ref()
            .await
            .unwrap()
            .organisation
            .to_owned(),
        interaction_type: InteractionType::Issuance,
        expires_at: None,
        ecosystem: None,
        ecosystem_data: Default::default(),
    }
}

async fn provider_with_encryption(credential: &Credential) -> OpenID4VCIFinal1_0 {
    let schema = credential
        .common()
        .schema
        .as_ref()
        .await
        .unwrap()
        .to_owned();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    credential_schema_repository
        .expect_get_credential_schema_list()
        .once()
        .returning(move |_| Ok(credential_schema_list(Some(schema.clone()))));

    provider_for_credential_acceptance(credential, credential_schema_repository).await
}

async fn provider_for_credential_acceptance(
    credential: &Credential,
    credential_schema_repository: MockCredentialSchemaRepository,
) -> OpenID4VCIFinal1_0 {
    let mut formatter = MockCredentialFormatter::new();
    formatter
        .expect_get_leeway()
        .return_const(Duration::seconds(1000));
    formatter.expect_parse_credential().returning({
        let clone = credential.clone();
        move |_, _, _| {
            Ok(crate::service::test_utilities::parsed_credential(
                clone.clone(),
            ))
        }
    });
    formatter
        .expect_get_capabilities()
        .return_const(generic_formatter_capabilities());
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
        .issuer_credential_mut()
        .unwrap()
        .data
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
        .issuer_credential_mut()
        .unwrap()
        .data
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
        .issuer_credential_mut()
        .unwrap()
        .data
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
                wallet_attestations: Default::default(),
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
    holder_wallet_unit_proto
        .expect_check_attestation_status()
        .times(3)
        .with(eq("wua"), eq(AttestationType::KeyAttestation))
        .returning(|_, _| {
            Ok(AttestationCheckResult {
                status: WalletUnitStatusCheckResponse::Active,
                expiration_date: None,
            })
        });

    let mut wallet_attestation_repository = MockWalletAttestationRepository::new();
    wallet_attestation_repository
        .expect_create()
        .times(3)
        .returning(|attestation| Ok(attestation.id));

    let protocol = setup_protocol(TestInputs {
        key_security_level_provider,
        holder_wallet_unit_repository,
        holder_wallet_unit_proto,
        wallet_attestation_repository,
        ..Default::default()
    });

    let configuration = |id: &str, key_storage: Option<Vec<_>>| HolderCredentialConfiguration {
        credential_configuration_id: id.to_string(),
        format: "jwt_vc_json".to_string(),
        cryptographic_binding_methods_supported: None,
        credential_signing_alg_values_supported: None,
        proof_types_supported: Some(IndexMap::from([(
            "jwt".to_string(),
            ProofTypeSupported {
                proof_signing_alg_values_supported: vec!["ES256".to_string()],
                key_attestations_required: key_storage.map(|key_storage| KeyAttestationsRequired {
                    key_storage,
                    user_authentication: vec![],
                    preferred_key_storage_status_period: None,
                }),
            },
        )])),
        credential_metadata: None,
        disclosure_policy: None,
        notification_id: None,
        credential_id: None,
        credential_schema_format_id: None,
    };
    let key = Key {
        storage_type: "INTERNAL".to_string(),
        ..dummy_key()
    };
    let requested = |id: &str, key_storage: Option<Vec<_>>| RequestedCredential {
        configuration: configuration(id, key_storage),
        holder_bindings: vec![HolderBinding {
            identifier: dummy_identifier(),
            key: key.clone(),
            wua_proof: None,
        }],
    };
    let mut requested_credentials = vec![
        requested("a", Some(vec![KeyStorageSecurityLevel::Basic])),
        requested("b", None),
        requested("c", Some(vec![KeyStorageSecurityLevel::Basic])),
        requested("d", Some(vec![])),
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
        token_endpoint_auth_methods_supported: vec![],
        client_attestation_pop_signing_alg_values_supported: None,
        issuer_display: None,
        credential_request_encryption: None,
        credential_response_encryption: None,
        dpop_signing_alg_values_supported: None,
        dpop_nonce: None,
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
            &[AttestationType::KeyAttestation],
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
        vec![
            Some("wua".to_string()),
            None,
            Some("wua".to_string()),
            Some("wua".to_string()),
        ]
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
fn required_child_of_optional_parent_is_not_always_present() {
    let optional_parent = claim_schema("optionalParent", "CUSTOM_OBJECT", false);
    let optional_parent_child = claim_schema("optionalParent/requiredChild", "STRING", true);
    let required_parent = claim_schema("requiredParent", "CUSTOM_OBJECT", true);
    let required_parent_child = claim_schema("requiredParent/requiredChild", "STRING", true);
    let claim_schemas = vec![
        optional_parent,
        optional_parent_child,
        required_parent,
        required_parent_child,
    ];
    let mandatory_by_claim_id =
        calculate_mandatory_claims(&claim_schemas, &datatype_config()).unwrap();

    assert!(!mandatory_by_claim_id[&claim_schemas[0].id]);
    assert!(!mandatory_by_claim_id[&claim_schemas[1].id]);
    assert!(mandatory_by_claim_id[&claim_schemas[2].id]);
    assert!(mandatory_by_claim_id[&claim_schemas[3].id]);
}

#[test]
fn required_parent_without_always_present_children_is_not_always_present() {
    let required_parent = claim_schema("requiredParent", "CUSTOM_OBJECT", true);
    let optional_child = claim_schema("requiredParent/optionalChild", "CUSTOM_OBJECT", false);
    let optional_grandchild = claim_schema(
        "requiredParent/optionalChild/optionalGrandchild",
        "STRING",
        false,
    );
    let claim_schemas = vec![required_parent, optional_child, optional_grandchild];
    let mandatory_by_claim_id =
        calculate_mandatory_claims(&claim_schemas, &datatype_config()).unwrap();

    assert!(!mandatory_by_claim_id[&claim_schemas[0].id]);
}

fn claim_schema(key: &str, data_type: &str, required: bool) -> ClaimSchema {
    ClaimSchema {
        key: key.to_string(),
        data_type: data_type.to_string(),
        required,
        ..dummy_claim_schema()
    }
}

fn datatype_config() -> DatatypeConfig {
    let fields = |r#type| Fields {
        r#type,
        display: "display".into(),
        order: None,
        priority: None,
        enabled: true,
        capabilities: None,
        params: None,
    };
    let mut config = DatatypeConfig::default();
    config.insert("STRING".to_string(), fields(DatatypeType::String));
    config.insert("CUSTOM_OBJECT".to_string(), fields(DatatypeType::Object));
    config
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
    // Match the language/field order returned by persistence.
    let translations = vec![
        text(LocalizedTextField::LogoAltText, "de", "Logo Beschreibung"),
        text(LocalizedTextField::Name, "de", "Deutscher Name"),
        text(LocalizedTextField::Name, "en", "English name"),
    ];

    let result = build_issuer_display("Plain", &translations, Some("https://logo"), "en");

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

fn holder_interaction_data(configurations: Value) -> HolderInteractionData {
    serde_json::from_value(json!({
        "issuer_url": "https://issuer.example.com",
        "credential_endpoint": "https://issuer.example.com/credential",
        "protocol": "OPENID4VCI_FINAL1",
        "credential_configurations": configurations,
    }))
    .unwrap()
}

fn accepted_batch_parent() -> Credential {
    {
        let mut updated_credential = generic_credential_did();
        updated_credential.common_mut().id = Uuid::new_v4().into();
        updated_credential.common_mut().state = CredentialStateEnum::Accepted;
        updated_credential = CredentialBuilder {
            role: CredentialRole::Holder,
            r#type: CredentialType::BatchParent,
            format: None,
            ..updated_credential.into()
        }
        .build();
        updated_credential
    }
}

#[tokio::test]
async fn refresh_history_records_each_parent_once_per_operation() {
    let organisation = dummy_organisation(None);
    let first_parent = accepted_batch_parent();
    let second_parent = accepted_batch_parent();
    let item = |parent: &Credential| {
        let mut updated_credential = generic_credential_did();
        updated_credential.common_mut().id = Uuid::new_v4().into();
        updated_credential = CredentialBuilder {
            r#type: CredentialType::BatchItem,
            parent: Some(parent.clone().into()),
            ..updated_credential.into()
        }
        .build();
        updated_credential
    };
    let refreshed = vec![
        IssuanceRefreshResponse {
            credential_configuration_id: "first".to_string(),
            credentials: vec![item(&first_parent), item(&first_parent)],
        },
        IssuanceRefreshResponse {
            credential_configuration_id: "second".to_string(),
            credentials: vec![item(&first_parent)],
        },
        IssuanceRefreshResponse {
            credential_configuration_id: "third".to_string(),
            credentials: vec![item(&second_parent)],
        },
    ];
    let histories = Arc::new(Mutex::new(vec![]));
    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .times(4)
        .returning({
            let histories = histories.clone();
            let organisation_id = organisation.id;
            move |history| {
                assert_eq!(history.action, HistoryAction::Refreshed);
                assert_eq!(history.entity_type, HistoryEntityType::Credential);
                assert_eq!(history.source, HistorySource::Core);
                assert_eq!(history.organisation_id, Some(organisation_id));
                let id = history.id;
                histories.lock().unwrap().push(history);
                Ok(id)
            }
        });
    let protocol = setup_protocol(TestInputs {
        history_repository,
        ..Default::default()
    });

    for _ in 0..2 {
        protocol
            .record_batch_refresh_history(&refreshed, organisation.id)
            .await
            .unwrap();
    }
    protocol
        .record_batch_refresh_history(&[], organisation.id)
        .await
        .unwrap();

    let histories = histories.lock().unwrap();
    assert_eq!(
        histories
            .iter()
            .map(|history| history.entity_id)
            .collect::<Vec<_>>(),
        [
            first_parent.common().id,
            second_parent.common().id,
            first_parent.common().id,
            second_parent.common().id
        ]
        .map(|id| Some(id.into()))
    );
    assert_eq!(
        histories
            .iter()
            .map(|history| history.id)
            .collect::<std::collections::HashSet<_>>()
            .len(),
        4
    );
}

#[tokio::test]
async fn refresh_selects_all_refreshable_configurations() {
    let parent = accepted_batch_parent();
    let jwt_item = {
        let mut updated_credential = generic_credential_did_with_holder_identifier();
        updated_credential.common_mut().expires_at = Some(now_utc() + Duration::days(1));
        updated_credential = CredentialBuilder {
            role: CredentialRole::Holder,
            r#type: CredentialType::BatchItem,
            parent: Some(parent.clone().into()),
            key: Some(dummy_key().into()),
            ..updated_credential.into()
        }
        .build();
        updated_credential
    };
    let mdoc_item = CredentialBuilder {
        role: CredentialRole::Holder,
        r#type: CredentialType::BatchItem,
        parent: Some(parent.clone().into()),
        key: None,
        ..generic_credential_did().into()
    }
    .build();
    let fixed_without_expiry = CredentialBuilder {
        role: CredentialRole::Holder,
        r#type: CredentialType::BatchItem,
        parent: Some(parent.clone().into()),
        ..generic_credential_did_with_holder_identifier().into()
    }
    .build();
    let rejected = {
        let mut updated_credential = accepted_batch_parent();
        updated_credential.common_mut().state = CredentialStateEnum::Rejected;
        updated_credential
    };
    let deleted = {
        let mut updated_credential = accepted_batch_parent();
        updated_credential.common_mut().deleted_at = Some(get_dummy_date());
        updated_credential
    };
    let single = CredentialBuilder {
        role: CredentialRole::Holder,
        key: None,
        ..generic_credential_did().into()
    }
    .build();
    let data = holder_interaction_data(json!([
        {"credential_configuration_id": "jwt", "format": "jwt_vc_json", "credential_id": parent.common().id, "credential_schema_format_id": jwt_item.holder().unwrap().data.format.id()},
        {"credential_configuration_id": "mdoc", "format": "mso_mdoc", "credential_id": parent.common().id, "credential_schema_format_id": mdoc_item.holder().unwrap().data.format.id()},
        {"credential_configuration_id": "fixed_without_expiry", "format": "jwt_vc_json", "credential_id": parent.common().id, "credential_schema_format_id": fixed_without_expiry.holder().unwrap().data.format.id()},
        {"credential_configuration_id": "failed", "format": "jwt_vc_json"},
        {"credential_configuration_id": "skipped", "format": "jwt_vc_json"},
        {"credential_configuration_id": "rejected", "format": "jwt_vc_json", "credential_id": rejected.common().id},
        {"credential_configuration_id": "deleted", "format": "jwt_vc_json", "credential_id": deleted.common().id},
        {"credential_configuration_id": "single", "format": "jwt_vc_json", "credential_id": single.common().id}
    ]));
    let interaction = interaction_for(&parent, &data).await;
    let mut repository = MockCredentialRepository::new();
    repository
        .expect_get_credentials_by_interaction_id()
        .once()
        .return_once(move |_| Ok(vec![parent, rejected, deleted, single]));
    repository
        .expect_get_credential_list()
        .times(6)
        .returning(move |query| {
            let item = [&jwt_item, &mdoc_item, &fixed_without_expiry]
                .into_iter()
                .find(|item| {
                    query.filtering.as_ref().unwrap().contains(&|filter| {
                        matches!(filter, CredentialFilterValue::FormatIds(ids) if ids == &[item.holder().unwrap().data.format.id()])
                    })
                })
                .expect("Refresh must select the item of the configuration's exact format");
            Ok(GetCredentialList {
                values: vec![item.clone()],
                total_items: None,
                total_pages: None,
            })
        });
    let protocol = setup_protocol(TestInputs {
        credential_repository: repository,
        ..Default::default()
    });

    let configurations = protocol
        .select_refresh_configurations(&interaction, &data, None)
        .await
        .unwrap();

    // A fixed binding without expiry must not prevent the other formats from refreshing.
    assert_eq!(
        configurations
            .iter()
            .map(|c| c.configuration.credential_configuration_id.as_str())
            .collect::<Vec<_>>(),
        ["jwt", "mdoc"]
    );
}

#[rstest::rstest]
#[case::fixed_without_expiry(false, None)]
#[case::fixed_with_expiry(false, Some(Duration::days(1)))]
#[case::fixed_expired(false, Some(Duration::days(-1)))]
#[case::autogenerated_without_expiry(true, None)]
#[case::autogenerated_with_expiry(true, Some(Duration::days(1)))]
#[tokio::test]
async fn refresh_respects_holder_binding_and_item_expiry(
    #[case] autogenerated: bool,
    #[case] expiry: Option<Duration>,
    #[values(true, false)] has_format_id: bool,
) {
    let parent = accepted_batch_parent();
    let mut item = {
        let mut updated_credential = generic_credential_did_with_holder_identifier();
        updated_credential.common_mut().expires_at = expiry.map(|duration| now_utc() + duration);
        updated_credential = CredentialBuilder {
            role: CredentialRole::Holder,
            r#type: CredentialType::BatchItem,
            parent: Some(parent.clone().into()),
            key: Some(dummy_key().into()),
            ..updated_credential.into()
        }
        .build();
        updated_credential
    };
    let holder = item.holder_mut().unwrap();
    let binding = holder.data.binding.as_mut().unwrap();
    binding.identifier.as_mut().await.unwrap().autogenerated = autogenerated;
    let identifier_id = binding.identifier.id();
    let key_id = binding.key.id();
    let format_id = holder.data.format.id();
    let data = holder_interaction_data(json!([{
        "credential_configuration_id": "jwt", "format": "jwt_vc_json",
        "credential_id": has_format_id.then_some(parent.common().id),
        "credential_schema_format_id": has_format_id.then_some(format_id),
    }]));
    let interaction = interaction_for(&parent, &data).await;
    let mut repository = MockCredentialRepository::new();
    repository
        .expect_get_credentials_by_interaction_id()
        .once()
        .return_once(move |_| Ok(vec![parent]));
    repository
        .expect_get_credential_list()
        .times(2)
        .returning(move |_| {
            Ok(GetCredentialList {
                values: vec![item.clone()],
                total_items: None,
                total_pages: None,
            })
        });
    let protocol = setup_protocol(TestInputs {
        credential_repository: repository,
        ..Default::default()
    });

    let result = protocol
        .select_refresh_configurations(&interaction, &data, None)
        .await;

    if !autogenerated && expiry.is_none() {
        assert!(matches!(
            result,
            Err(IssuanceProtocolError::RefreshNotSupported)
        ));
    } else {
        let configurations = result.unwrap();
        let_assert!([selected] = configurations.as_slice());
        assert_eq!(
            selected.configuration.credential_schema_format_id,
            Some(format_id)
        );
        if autogenerated {
            assert!(selected.holder_binding.is_none());
        } else {
            let binding = selected.holder_binding.as_ref().unwrap();
            assert_eq!(binding.identifier.id, identifier_id);
            assert_eq!(binding.key.id, key_id);
        }
    }
}

#[rstest::rstest]
#[case::accepted(CredentialStateEnum::Accepted)]
#[case::rejected(CredentialStateEnum::Rejected)]
#[tokio::test]
async fn mso_refresh_selects_the_configuration_matching_the_items_format_id(
    #[case] state: CredentialStateEnum,
) {
    let parent = accepted_batch_parent();
    let mut item = {
        let mut updated_credential = generic_credential_did_with_holder_identifier();
        updated_credential.common_mut().id = Uuid::new_v4().into();
        updated_credential.common_mut().state = state;
        updated_credential = CredentialBuilder {
            role: CredentialRole::Holder,
            r#type: CredentialType::BatchItem,
            parent: Some(parent.clone().into()),
            key: Some(dummy_key().into()),
            ..updated_credential.into()
        }
        .build();
        updated_credential
    };
    item.holder_mut()
        .unwrap()
        .data
        .format
        .as_mut()
        .await
        .unwrap()
        .format = "MDOC".into();
    let format_id = item.holder().unwrap().data.format.id();
    let data = holder_interaction_data(json!([
        {"credential_configuration_id": "other", "format": "mso_mdoc", "credential_id": parent.common().id, "credential_schema_format_id": Uuid::new_v4()},
        {"credential_configuration_id": "selected", "format": "mso_mdoc", "credential_id": parent.common().id, "credential_schema_format_id": format_id}
    ]));
    let interaction = interaction_for(&parent, &data).await;
    let protocol = setup_protocol(TestInputs::default());

    let result = protocol
        .select_refresh_configurations(&interaction, &data, Some(&item))
        .await;
    if state == CredentialStateEnum::Rejected {
        assert!(matches!(
            result,
            Err(super::IssuanceProtocolError::RefreshNotPossible)
        ));
        return;
    }
    let configurations = result.unwrap();

    let_assert!([selected] = configurations.as_slice());
    assert_eq!(
        selected.configuration.credential_configuration_id,
        "selected"
    );
    assert_eq!(
        selected.configuration.credential_schema_format_id,
        Some(format_id)
    );
    assert_eq!(
        selected.holder_binding.as_ref().unwrap().identifier.id,
        item.holder()
            .unwrap()
            .data
            .binding
            .as_ref()
            .unwrap()
            .identifier
            .id()
    );
}

#[rstest::rstest]
#[case::stored_format_id(true)]
#[case::legacy_batch_item(false)]
#[tokio::test]
async fn refresh_resolves_the_issued_format_independently_of_schema_order(
    #[case] has_format_id: bool,
) {
    use crate::model::credential::GetCredentialList;

    let mut item = generic_credential_did();
    item = CredentialBuilder {
        role: CredentialRole::Holder,
        r#type: CredentialType::BatchItem,
        ..item.into()
    }
    .build();
    let issued_format = item
        .holder()
        .unwrap()
        .data
        .format
        .as_ref()
        .await
        .unwrap()
        .to_owned();
    let mut unrelated_format = issued_format.clone();
    unrelated_format.id = Uuid::new_v4().into();
    unrelated_format.format = "MDOC".into();
    let mut schema = item.common().schema.as_ref().await.unwrap().to_owned();
    // The first schema format is deliberately not the issued format.
    schema.formats = vec![unrelated_format, issued_format.clone()].into();
    let parent = {
        let mut updated_credential = accepted_batch_parent();
        updated_credential.common_mut().schema = schema.into();
        updated_credential
    };
    item = CredentialBuilder {
        parent: Some(parent.clone().into()),
        ..item.into()
    }
    .build();
    let configuration: HolderCredentialConfiguration = serde_json::from_value(json!({
        "credential_configuration_id": "jwt", "format": "jwt_vc_json",
        "credential_id": parent.common().id,
        "credential_schema_format_id": has_format_id.then_some(issued_format.id),
    }))
    .unwrap();
    let mut repository = MockCredentialRepository::new();
    if !has_format_id {
        repository
            .expect_get_credential_list()
            .once()
            .return_once(move |_| {
                Ok(GetCredentialList {
                    values: vec![item],
                    total_items: Some(1),
                    total_pages: Some(1),
                })
            });
    }
    let protocol = setup_protocol(TestInputs {
        credential_repository: repository,
        config: dummy_config(),
        ..Default::default()
    });

    let format = protocol
        .get_batch_schema_format(&parent, &configuration, FormatType::Jwt)
        .await
        .unwrap();

    assert_eq!(format.id, issued_format.id);
}

#[rstest::rstest]
#[case::both_notifications_succeed(204)]
#[case::first_notification_fails(400)]
#[tokio::test]
async fn rejection_notifies_every_associated_configuration(#[case] first_status: u16) {
    let server = MockServer::start().await;
    let mut parent = accepted_batch_parent();
    let mut data = holder_interaction_data(json!([
        {"credential_configuration_id": "first", "format": "jwt_vc_json", "credential_id": parent.common().id, "notification_id": "first"},
        {"credential_configuration_id": "second", "format": "mso_mdoc", "credential_id": parent.common().id, "notification_id": "second"},
        {"credential_configuration_id": "failed", "format": "jwt_vc_json", "notification_id": "failed"},
        {"credential_configuration_id": "other", "format": "jwt_vc_json", "credential_id": Uuid::new_v4(), "notification_id": "other"}
    ]));
    data.notification_endpoint = Some(format!("{}/notification", server.uri()));
    data.access_token = Some(
        encrypt_data(
            &SecretSlice::from(b"token".to_vec()),
            &SecretSlice::from(vec![0; 32]),
        )
        .unwrap(),
    );
    parent.common_mut().interaction = Some(interaction_for(&parent, &data).await.into());
    for (id, status) in [("first", first_status), ("second", 204)] {
        Mock::given(method(Method::POST))
            .and(path("/notification"))
            .and(body_json(
                json!({"notification_id": id, "event": "credential_deleted"}),
            ))
            .respond_with(ResponseTemplate::new(status))
            .expect(1)
            .mount(&server)
            .await;
    }
    let protocol = setup_protocol(TestInputs::default());

    let result = protocol.holder_reject_credential(parent).await;

    // Attempt both associated notifications, including when the first one fails.
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
    assert_eq!(result.is_ok(), first_status == 204);
    if let Err(error) = result {
        assert!(error.to_string().contains("first"));
    }
}

/// A DPoP context signing with a stub key, as [`OpenID4VCIFinal1_0::dpop_context`] builds it from
/// the binding key of an interaction.
fn dpop_context(nonce: Option<&str>) -> DpopContext {
    let mut signature_provider = MockSignatureProvider::new();
    signature_provider
        .expect_jose_alg()
        .returning(|| Ok("ES256".to_string()));
    signature_provider
        .expect_sign()
        .returning(|_| Ok(vec![0; 64]));

    DpopContext::new(
        Uuid::new_v4().into(),
        Box::new(signature_provider),
        PublicJwk::Ec(PublicJwkEc {
            alg: None,
            r#use: None,
            kid: None,
            crv: "P-256".to_string(),
            x: "igrFmi0whuihKnj9R3Om1SoMph72wUGeFaBbzG2vzns".to_owned(),
            y: Some("efsX5b10x8yjyrj4ny3pGfLcY7Xby1KzgqOdqnsrJIM".to_owned()),
        }),
        nonce.map(ToOwned::to_owned),
    )
}

fn sent_dpop_proofs(requests: &[wiremock::Request]) -> Vec<DecomposedJwt<DPoPClaims>> {
    requests
        .iter()
        .map(|request| {
            let proof = request
                .headers
                .get("DPoP")
                .expect("request carries a DPoP proof")
                .to_str()
                .unwrap();
            Jwt::<DPoPClaims>::decompose_token(proof).unwrap()
        })
        .collect()
}

#[tokio::test]
async fn test_dpop_request_is_repeated_with_the_nonce_demanded_by_the_issuer() {
    let mock_server = MockServer::start().await;

    Mock::given(method(Method::POST))
        .and(path("/credential"))
        .respond_with(
            ResponseTemplate::new(401)
                .insert_header("DPoP-Nonce", "fresh-nonce")
                .insert_header("WWW-Authenticate", r#"DPoP error="use_dpop_nonce""#),
        )
        .up_to_n_times(1)
        .expect(1)
        .mount(&mock_server)
        .await;
    Mock::given(method(Method::POST))
        .and(path("/credential"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .expect(1)
        .mount(&mock_server)
        .await;

    let protocol = setup_protocol(TestInputs::default());
    let context = dpop_context(None);
    let access_token = SecretString::from("access-token");
    let url = format!("{}/credential?query=ignored", mock_server.uri());

    let response = protocol
        .send_authorized_request(
            Some(&context),
            HttpMethod::Post,
            &url,
            Some(&access_token),
            |request| request.json(json!({"credential": "configuration"})),
        )
        .await
        .unwrap();

    assert!(response.status.is_success());
    // the nonce of the retry is kept for the requests that follow
    assert_eq!(Some("fresh-nonce".to_string()), context.nonce());

    let requests = mock_server.received_requests().await.unwrap();
    assert_eq!(2, requests.len());
    for request in &requests {
        assert_eq!(
            "DPoP access-token",
            request.headers.get("Authorization").unwrap()
        );
    }

    let proofs = sent_dpop_proofs(&requests);
    for proof in &proofs {
        assert_eq!(Some(DPOP_JWT_TYPE), proof.header.r#type.as_deref());
        assert_eq!("ES256", proof.header.algorithm);
        assert!(proof.header.jwk.is_some());
        assert!(proof.payload.jwt_id.is_some());
        assert!(proof.payload.issued_at.is_some());
        assert_eq!("POST", proof.payload.custom.htm);
        // the `htu` claim carries no query
        assert_eq!(
            format!("{}/credential", mock_server.uri()),
            proof.payload.custom.htu.to_string()
        );
        assert_eq!(
            Some(SHA256.hash_base64_url(b"access-token").unwrap()),
            proof.payload.custom.ath
        );
    }
    assert_eq!(None, proofs[0].payload.custom.nonce);
    assert_eq!(
        Some("fresh-nonce".to_string()),
        proofs[1].payload.custom.nonce
    );
    assert_ne!(proofs[0].payload.jwt_id, proofs[1].payload.jwt_id);
}

#[tokio::test]
async fn test_dpop_request_is_not_repeated_without_a_new_nonce() {
    let mock_server = MockServer::start().await;

    // the issuer asks for a nonce but provides none, so repeating the request is pointless
    Mock::given(method(Method::POST))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({"error": "use_dpop_nonce"})))
        .expect(1)
        .mount(&mock_server)
        .await;

    let protocol = setup_protocol(TestInputs::default());
    let context = dpop_context(Some("known-nonce"));

    let response = protocol
        .send_authorized_request(
            Some(&context),
            HttpMethod::Post,
            &format!("{}/token", mock_server.uri()),
            None,
            |request| request.json(json!({})),
        )
        .await
        .unwrap();

    assert_eq!(400, response.status.0);
    assert_eq!(Some("known-nonce".to_string()), context.nonce());

    let requests = mock_server.received_requests().await.unwrap();
    assert_eq!(1, requests.len());
    let proof = sent_dpop_proofs(&requests).pop().unwrap();
    assert_eq!(Some("known-nonce".to_string()), proof.payload.custom.nonce);
    // without an access token the proof does not bind one
    assert_eq!(None, proof.payload.custom.ath);
    assert!(requests[0].headers.get("Authorization").is_none());
}

#[tokio::test]
async fn test_request_without_dpop_uses_the_bearer_scheme() {
    let mock_server = MockServer::start().await;
    Mock::given(method(Method::POST))
        .and(path("/credential"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(1)
        .mount(&mock_server)
        .await;

    let protocol = setup_protocol(TestInputs::default());
    protocol
        .send_authorized_request(
            None,
            HttpMethod::Post,
            &format!("{}/credential", mock_server.uri()),
            Some(&SecretString::from("access-token")),
            |request| request.json(json!({})),
        )
        .await
        .unwrap();

    let requests = mock_server.received_requests().await.unwrap();
    assert_eq!(
        "Bearer access-token",
        requests[0].headers.get("Authorization").unwrap()
    );
    assert!(requests[0].headers.get("DPoP").is_none());
}

/// An offer the holder has not accepted yet, carrying the DPoP signing algorithms the
/// authorization server advertised.
fn dpop_offer(dpop_signing_algs: Option<&[&str]>) -> (Interaction, HolderInteractionData) {
    let interaction_data: HolderInteractionData = serde_json::from_value(json!({
        "issuer_url": "https://issuer.example.com/",
        "credential_endpoint": "https://issuer.example.com/credential",
        "protocol": "OPENID4VCI_FINAL1",
        "credential_configurations": [],
        "dpop_signing_alg_values_supported": dpop_signing_algs,
    }))
    .unwrap();

    let interaction = interaction_from_handle_invitation(
        Some(serde_json::to_vec(&interaction_data).unwrap()),
        get_dummy_date(),
        dummy_organisation(None),
    );
    (interaction, interaction_data)
}

fn dpop_params() -> serde_json::Value {
    let mut params = test_params("openid-credential-offer");
    params["holderDpopKeyStorage"] = json!("INTERNAL");
    params
}

#[tokio::test]
async fn test_dpop_binding_key_is_created_on_accept_and_attached_to_the_interaction() {
    let (interaction, interaction_data) = dpop_offer(Some(&["ES256"]));

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_jose_alg()
        .returning(|alg| (alg == "ES256").then(|| (KeyAlgorithmType::Ecdsa, Arc::new(Ecdsa) as _)));

    let mut key_provider = MockKeyProvider::new();
    key_provider
        .expect_get_key_storage()
        .once()
        .returning(|storage_type| {
            assert_eq!("INTERNAL", storage_type);
            let mut key_storage = MockKeyStorage::new();
            key_storage
                .expect_generate()
                .once()
                .returning(|_, algorithm, _| {
                    assert_eq!(KeyAlgorithmType::Ecdsa, algorithm);
                    Ok(StorageGeneratedKey {
                        public_key: vec![1; 32],
                        key_reference: Some(vec![2; 32]),
                    })
                });
            Ok(Arc::new(key_storage))
        });

    let mut key_repository = MockKeyRepository::new();
    key_repository
        .expect_create_key()
        .once()
        .returning(|key| Ok(key.id));

    let attached_key_id = Arc::new(std::sync::Mutex::new(None));
    let interaction_id = interaction.id;
    let attached = attached_key_id.clone();
    let mut interaction_repository = MockInteractionRepository::new();
    interaction_repository
        .expect_update_interaction()
        .once()
        .returning(move |id, request| {
            assert_eq!(interaction_id, id);
            *attached.lock().unwrap() = request.dpop_key.flatten();
            Ok(())
        });

    let protocol = setup_protocol(TestInputs {
        key_algorithm_provider,
        key_provider,
        key_repository,
        interaction_repository,
        params: Some(dpop_params()),
        ..Default::default()
    });

    let key = protocol
        .create_dpop_binding_key(&interaction, &interaction_data)
        .await
        .unwrap()
        .expect("issuance is DPoP bound");

    assert_eq!(Some(key.id), *attached_key_id.lock().unwrap());
    assert_eq!("INTERNAL", key.storage_type);
    assert_eq!(KeyAlgorithmType::Ecdsa.to_string(), key.key_type);
    assert!(key.autogenerated);
}

#[tokio::test]
async fn test_no_dpop_binding_key_without_advertised_signing_algorithms() {
    let (interaction, interaction_data) = dpop_offer(None);

    // the mocks expect no call: generating or storing a key would fail the test
    let protocol = setup_protocol(TestInputs {
        params: Some(dpop_params()),
        ..Default::default()
    });

    assert!(
        protocol
            .create_dpop_binding_key(&interaction, &interaction_data)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn test_no_dpop_binding_key_without_configured_key_storage() {
    let (interaction, interaction_data) = dpop_offer(Some(&["ES256"]));

    let protocol = setup_protocol(TestInputs::default());

    assert!(
        protocol
            .create_dpop_binding_key(&interaction, &interaction_data)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn test_no_dpop_binding_key_for_unsupported_signing_algorithms() {
    let (interaction, interaction_data) = dpop_offer(Some(&["ES256"]));

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_jose_alg()
        .returning(|_| None);

    let protocol = setup_protocol(TestInputs {
        key_algorithm_provider,
        params: Some(dpop_params()),
        ..Default::default()
    });

    assert!(
        protocol
            .create_dpop_binding_key(&interaction, &interaction_data)
            .await
            .unwrap()
            .is_none()
    );
}
