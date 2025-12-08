use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use assert2::let_assert;
use indexmap::IndexMap;
use mockall::predicate::{self, eq};
use one_crypto::encryption::encrypt_data;
use secrecy::SecretSlice;
use serde_json::{Value, json};
use similar_asserts::assert_eq;
use time::{Duration, OffsetDateTime};
use url::Url;
use uuid::Uuid;
use wiremock::http::Method;
use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::config::core_config::{CoreConfig, Fields, FormatType, KeyAlgorithmType};
use crate::model::certificate::{Certificate, CertificateState};
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{Credential, CredentialRole, CredentialStateEnum};
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaClaim, KeyStorageSecurity, LayoutType,
};
use crate::model::did::{Did, DidType, KeyRole, RelatedKey};
use crate::model::identifier::{Identifier, IdentifierState, IdentifierType};
use crate::model::interaction::{Interaction, InteractionType};
use crate::model::key::{Key, PublicKeyJwk, PublicKeyJwkEllipticData};
use crate::proto::certificate_validator::MockCertificateValidator;
use crate::proto::http_client::reqwest_client::ReqwestClient;
use crate::proto::identifier_creator::{MockIdentifierCreator, RemoteIdentifierRelation};
use crate::provider::blob_storage_provider::MockBlobStorageProvider;
use crate::provider::caching_loader::openid_metadata::MockOpenIDMetadataFetcher;
use crate::provider::caching_loader::{CacheError, ResolverError};
use crate::provider::credential_formatter::MockCredentialFormatter;
use crate::provider::credential_formatter::model::{
    CredentialSubject, DetailCredential, IdentifierDetails, MockSignatureProvider,
};
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::did_method::{DidCreated, MockDidMethod};
use crate::provider::issuance_protocol::dto::ContinueIssuanceDTO;
use crate::provider::issuance_protocol::model::{
    InvitationResponseEnum, OpenID4VCRedirectUriParams,
};
use crate::provider::issuance_protocol::openid4vci_draft13::handle_invitation_operations::{
    BuildCredentialSchemaResponse, MockHandleInvitationOperations,
};
use crate::provider::issuance_protocol::openid4vci_draft13::mapper::{
    extract_offered_claims, get_parent_claim_paths,
};
use crate::provider::issuance_protocol::openid4vci_draft13::model::{
    HolderInteractionData, OpenID4VCICredentialValueDetails, OpenID4VCIDraft13Params,
    OpenID4VCIGrants, OpenID4VCIPreAuthorizedCodeGrant, WalletStorageTypeEnum,
};
use crate::provider::issuance_protocol::openid4vci_draft13::service::create_credential_offer;
use crate::provider::issuance_protocol::openid4vci_draft13::{IssuanceProtocolError, OpenID4VCI13};
use crate::provider::issuance_protocol::{HolderBindingInput, IssuanceProtocol};
use crate::provider::key_algorithm::ecdsa::Ecdsa;
use crate::provider::key_algorithm::key::{
    KeyHandle, MockSignaturePrivateKeyHandle, MockSignaturePublicKeyHandle, SignatureKeyHandle,
};
use crate::provider::key_algorithm::model::GeneratedKey;
use crate::provider::key_algorithm::provider::{MockKeyAlgorithmProvider, ParsedKey};
use crate::provider::key_algorithm::{KeyAlgorithm, MockKeyAlgorithm};
use crate::provider::key_security_level::provider::MockKeySecurityLevelProvider;
use crate::provider::key_storage::provider::MockKeyProvider;
use crate::provider::revocation::provider::MockRevocationMethodProvider;
use crate::repository::credential_repository::MockCredentialRepository;
use crate::repository::key_repository::MockKeyRepository;
use crate::repository::validity_credential_repository::MockValidityCredentialRepository;
use crate::service::oid4vci_draft13::service::credentials_format;
use crate::service::storage_proxy::MockStorageProxy;
use crate::service::test_utilities::{
    dummy_did, dummy_identifier, dummy_key, dummy_organisation, get_dummy_date,
};

#[derive(Default)]
struct TestInputs {
    pub credential_repository: MockCredentialRepository,
    pub metadata_cache: MockOpenIDMetadataFetcher,
    pub validity_credential_repository: MockValidityCredentialRepository,
    pub formatter_provider: MockCredentialFormatterProvider,
    pub revocation_provider: MockRevocationMethodProvider,
    pub key_algorithm_provider: MockKeyAlgorithmProvider,
    pub key_provider: MockKeyProvider,
    pub did_method_provider: MockDidMethodProvider,
    pub certificate_validator: MockCertificateValidator,
    pub identifier_creator: MockIdentifierCreator,
    pub blob_storage_provider: MockBlobStorageProvider,
    pub config: CoreConfig,
    pub params: Option<OpenID4VCIDraft13Params>,
    pub handle_invitation_operations: MockHandleInvitationOperations,
}

fn setup_protocol(inputs: TestInputs) -> OpenID4VCI13 {
    OpenID4VCI13::new(
        Arc::new(ReqwestClient::default()),
        Arc::new(inputs.metadata_cache),
        Arc::new(inputs.credential_repository),
        Arc::new(MockKeyRepository::new()),
        Arc::new(inputs.validity_credential_repository),
        Arc::new(inputs.formatter_provider),
        Arc::new(inputs.revocation_provider),
        Arc::new(inputs.did_method_provider),
        Arc::new(inputs.key_algorithm_provider),
        Arc::new(MockKeySecurityLevelProvider::new()),
        Arc::new(inputs.key_provider),
        Arc::new(inputs.certificate_validator),
        Arc::new(inputs.identifier_creator),
        Arc::new(inputs.blob_storage_provider),
        Some("http://base_url".to_string()),
        Arc::new(inputs.config),
        inputs.params.unwrap_or(OpenID4VCIDraft13Params {
            pre_authorized_code_expires_in: 10,
            token_expires_in: 10,
            credential_offer_by_value: false,
            refresh_expires_in: 1000,
            encryption: SecretSlice::from(vec![0; 32]),
            url_scheme: "openid-credential-offer".to_string(),
            redirect_uri: OpenID4VCRedirectUriParams {
                enabled: true,
                allowed_schemes: vec!["https".to_string()],
            },
            enable_credential_preview: true,
        }),
        Arc::new(inputs.handle_invitation_operations),
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

fn generic_credential_certificate() -> Credential {
    let now = OffsetDateTime::now_utc();
    let id = Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
        .unwrap()
        .into();
    let issuer_identifier = Identifier {
        id,
        created_date: now,
        last_modified: now,
        name: "certificate identifier 1".to_string(),
        r#type: IdentifierType::Certificate,
        is_remote: true,
        state: IdentifierState::Active,
        deleted_at: None,
        organisation: None,
        did: None,
        key: None,
        certificates: Some(vec![Certificate {
            id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb966")
                .unwrap()
                .into(),
            identifier_id: id,
            organisation_id: None,
            created_date: now,
            last_modified: now,
            expiry_date: now + Duration::hours(12),
            name: "certificate 1".to_string(),
            chain: "<dummy test cert chain>".to_string(),
            fingerprint: "123456".to_string(),
            state: CertificateState::Active,
            key: None,
        }]),
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
        protocol: "OPENID4VCI_DRAFT13".to_string(),
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
            format: "JWT".to_string(),
            revocation_method: "NONE".to_string(),
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
            id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965").unwrap(),
            created_date: now,
            data: Some(vec![1, 2, 3]),
            last_modified: now,
            organisation: None,
            nonce_id: None,
            interaction_type: InteractionType::Issuance,
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
        "JWT".to_string(),
        Fields {
            r#type: FormatType::Jwt,
            display: "display".into(),
            order: None,
            enabled: None,
            capabilities: None,
            params: None,
        },
    );

    config
}

#[tokio::test]
async fn test_generate_offer_did() {
    let protocol_base_url = "BASE_URL/ssi/openid4vci/draft-13".to_string();
    let interaction_id = Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965").unwrap();
    let credential = generic_credential_did();

    let keys = credential.claims.clone().unwrap_or_default();

    let credential_subject =
        credentials_format(Some(WalletStorageTypeEnum::Software), &keys, true).unwrap();

    let offer = create_credential_offer(
        &protocol_base_url,
        &interaction_id.to_string(),
        &credential,
        &credential.schema.as_ref().unwrap().id,
        &credential.schema.as_ref().unwrap().schema_id,
        credential_subject,
    )
    .unwrap();

    assert_eq!(
        json!(&offer),
        json!({
            "credential_issuer": "BASE_URL/ssi/openid4vci/draft-13/c322aa7f-9803-410d-b891-939b279fb965",
            "issuer_did": "did:example:123",
            "credential_configuration_ids" : [
                credential.schema.as_ref().unwrap().schema_id,
            ],
            "grants": {
                "urn:ietf:params:oauth:grant-type:pre-authorized_code": { "pre-authorized_code": "c322aa7f-9803-410d-b891-939b279fb965" }
            },
            "credential_subject": {
                "keys": {
                    "NUMBER": {
                        "value": "123",
                        "value_type": "NUMBER"
                    }
                },
                "wallet_storage_type": "SOFTWARE"
            }
        })
    )
}

#[tokio::test]
async fn test_generate_offer_certificate() {
    let protocol_base_url = "BASE_URL/ssi/openid4vci/draft-13".to_string();
    let interaction_id = Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965").unwrap();
    let credential = generic_credential_certificate();

    let keys = credential.claims.clone().unwrap_or_default();

    let credential_subject =
        credentials_format(Some(WalletStorageTypeEnum::Software), &keys, true).unwrap();

    let offer = create_credential_offer(
        &protocol_base_url,
        &interaction_id.to_string(),
        &credential,
        &credential.schema.as_ref().unwrap().id,
        &credential.schema.as_ref().unwrap().schema_id,
        credential_subject,
    )
    .unwrap();

    assert_eq!(
        json!(&offer),
        json!({
            "credential_issuer": "BASE_URL/ssi/openid4vci/draft-13/c322aa7f-9803-410d-b891-939b279fb965",
            "issuer_certificate": "<dummy test cert chain>",
            "credential_configuration_ids" : [
                credential.schema.as_ref().unwrap().schema_id,
            ],
            "grants": {
                "urn:ietf:params:oauth:grant-type:pre-authorized_code": { "pre-authorized_code": "c322aa7f-9803-410d-b891-939b279fb965" }
            },
            "credential_subject": {
                "keys": {
                    "NUMBER": {
                        "value": "123",
                        "value_type": "NUMBER"
                    }
                },
                "wallet_storage_type": "SOFTWARE"
            }
        })
    )
}

#[tokio::test]
async fn test_generate_offer_claims_without_values() {
    let protocol_base_url = "BASE_URL/ssi/openid4vci/draft-13".to_string();
    let interaction_id = Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965").unwrap();
    let credential = generic_credential_certificate();

    let keys = credential.claims.clone().unwrap_or_default();

    let credential_subject =
        credentials_format(Some(WalletStorageTypeEnum::Software), &keys, false).unwrap();

    let offer = create_credential_offer(
        &protocol_base_url,
        &interaction_id.to_string(),
        &credential,
        &credential.schema.as_ref().unwrap().id,
        &credential.schema.as_ref().unwrap().schema_id,
        credential_subject,
    )
    .unwrap();

    assert_eq!(
        json!(&offer),
        json!({
            "credential_issuer": "BASE_URL/ssi/openid4vci/draft-13/c322aa7f-9803-410d-b891-939b279fb965",
            "issuer_certificate": "<dummy test cert chain>",
            "credential_configuration_ids" : [
                credential.schema.as_ref().unwrap().schema_id,
            ],
            "grants": {
                "urn:ietf:params:oauth:grant-type:pre-authorized_code": { "pre-authorized_code": "c322aa7f-9803-410d-b891-939b279fb965" }
            },
            "credential_subject": {
                "keys": {
                    "NUMBER": {
                        "value_type": "NUMBER"
                    }
                },
                "wallet_storage_type": "SOFTWARE"
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
        "openid-credential-offer://?credential_offer_uri=http%3A%2F%2Fbase_url%2Fssi%2Fopenid4vci%2Fdraft-13%2Fc322aa7f-9803-410d-b891-939b279fb965%2Foffer%2Fc322aa7f-9803-410d-b891-939b279fb965"
    );
}

#[tokio::test]
async fn test_generate_share_credentials_offer_by_value() {
    let credential = generic_credential_did();

    let protocol = setup_protocol(TestInputs {
        params: Some(OpenID4VCIDraft13Params {
            pre_authorized_code_expires_in: 10,
            token_expires_in: 10,
            credential_offer_by_value: true,
            refresh_expires_in: 1000,
            encryption: SecretSlice::from(vec![0; 32]),
            url_scheme: "openid-credential-offer".to_string(),
            redirect_uri: OpenID4VCRedirectUriParams {
                enabled: true,
                allowed_schemes: vec!["https".to_string()],
            },
            enable_credential_preview: true,
        }),
        ..Default::default()
    });

    let result = protocol.issuer_share_credential(&credential).await.unwrap();
    // Everything except for interaction id is here.
    // Generating token with predictable interaction id is tested somewhere else.
    assert!(
        result.url.starts_with(r#"openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22http%3A%2F%2Fbase_url%2Fssi%2Fopenid4vci%2Fdraft-13%2Fc322aa7f-9803-410d-b891-939b279fb965%22%2C%22credential_configuration_ids%22%3A%5B%22CredentialSchemaId%22%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%"#)
    );
    assert!(
        result
            .url
            .contains("%22issuer_did%22%3A%22did%3Aexample%3A123%22")
    )
}

#[tokio::test]
async fn test_handle_invitation_credential_by_ref_with_did_success() {
    let credential = generic_credential_did();

    let mut identifier_creator = MockIdentifierCreator::default();
    let credential_clone = credential.clone();
    identifier_creator
        .expect_get_or_create_remote_identifier()
        .times(1)
        .returning(move |_, _, _| {
            let did = credential_clone
                .issuer_identifier
                .as_ref()
                .unwrap()
                .did
                .as_ref()
                .unwrap()
                .clone();
            let relation = RemoteIdentifierRelation::Did(did.clone());
            Ok((
                Identifier {
                    id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
                        .unwrap()
                        .into(),
                    did: Some(did.clone()),
                    created_date: did.created_date,
                    last_modified: did.last_modified,
                    name: did.name,
                    r#type: IdentifierType::Did,
                    is_remote: true,
                    state: IdentifierState::Active,
                    deleted_at: None,
                    organisation: did.organisation,
                    key: None,
                    certificates: None,
                },
                relation,
            ))
        });

    inner_test_handle_invitation_credential_by_ref_success(
        identifier_creator,
        MockStorageProxy::default(),
        credential,
        Some("did:example:123".to_string()),
        true,
    )
    .await;
}

#[tokio::test]
async fn test_holder_accept_credential_success() {
    let mock_server = MockServer::start().await;
    let mut formatter_provider = MockCredentialFormatterProvider::default();
    let mut storage_access = MockStorageProxy::default();
    let mut key_provider = MockKeyProvider::default();

    let interaction_data = HolderInteractionData {
        issuer_url: mock_server.uri(),
        credential_endpoint: format!("{}/credential", mock_server.uri()),
        token_endpoint: Some(format!("{}/token", mock_server.uri())),
        notification_endpoint: Some(format!("{}/notification", mock_server.uri())),
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
        nonce: None,
        refresh_token_expires_at: None,
        cryptographic_binding_methods_supported: None,
        credential_signing_alg_values_supported: None,
        proof_types_supported: None,
        continue_issuance: None,
        notification_id: None,
    };

    let interaction = Interaction {
        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965").unwrap(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        data: Some(serde_json::to_vec(&interaction_data).unwrap()),
        organisation: None,
        nonce_id: None,
        interaction_type: InteractionType::Issuance,
    };
    let credential = Credential {
        interaction: Some(interaction.clone()),
        ..generic_credential_did()
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
        .and(path("/credential"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "credential": "credential",
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

    formatter_provider
        .expect_get_credential_formatter()
        .with(predicate::eq("JWT"))
        .returning(move |_| {
            let mut formatter = MockCredentialFormatter::new();
            formatter.expect_get_leeway().returning(|| 1000);

            formatter
                .expect_extract_credentials()
                .returning(move |_, _, _, _| {
                    Ok(DetailCredential {
                        id: None,
                        issuance_date: None,
                        valid_from: Some(OffsetDateTime::now_utc() - Duration::days(1)),
                        valid_until: Some(OffsetDateTime::now_utc() + Duration::days(1)),
                        update_at: None,
                        invalid_before: None,
                        issuer: IdentifierDetails::Did(dummy_did().did),
                        subject: None,
                        claims: CredentialSubject {
                            id: None,
                            claims: HashMap::new(),
                        },
                        status: vec![],
                        credential_schema: None,
                    })
                });

            Some(Arc::new(formatter))
        });

    storage_access
        .expect_get_credential_by_interaction_id()
        .returning({
            let clone = credential.clone();
            move |_| Ok(clone.clone())
        });

    storage_access
        .expect_update_interaction()
        .returning(|_, _| Ok(()));

    storage_access
        .expect_get_did_by_value()
        .returning(|_, _| Ok(Some(dummy_did())));

    let identifier = dummy_identifier();
    storage_access.expect_get_identifier_for_did().returning({
        let identifier = identifier.clone();
        move |_| Ok(identifier.clone())
    });

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
                Ok(PublicKeyJwk::Ec(PublicKeyJwkEllipticData {
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

    let openid_provider = setup_protocol(TestInputs {
        formatter_provider,
        key_provider,
        key_algorithm_provider,
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

    let update_credential = result.update_credential.unwrap();
    assert_eq!(update_credential.0, credential.id);
    assert_eq!(
        update_credential.1.issuer_identifier_id.unwrap(),
        identifier.id
    );
}

#[tokio::test]
async fn test_holder_accept_credential_none_existing_issuer_key_id_success() {
    let mock_server = MockServer::start().await;
    let mut formatter_provider = MockCredentialFormatterProvider::default();
    let mut storage_access = MockStorageProxy::default();
    let mut key_provider = MockKeyProvider::default();

    let interaction_data = HolderInteractionData {
        issuer_url: mock_server.uri(),
        credential_endpoint: format!("{}/credential", mock_server.uri()),
        token_endpoint: Some(format!("{}/token", mock_server.uri())),
        notification_endpoint: None,
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
        nonce: None,
        refresh_token_expires_at: None,
        cryptographic_binding_methods_supported: None,
        credential_signing_alg_values_supported: None,
        proof_types_supported: None,
        continue_issuance: None,
        notification_id: None,
    };

    let interaction = Interaction {
        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965").unwrap(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        data: Some(serde_json::to_vec(&interaction_data).unwrap()),
        organisation: None,
        nonce_id: None,
        interaction_type: InteractionType::Issuance,
    };

    let credential = Credential {
        interaction: Some(interaction.clone()),
        ..generic_credential_key()
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
        .and(path("/credential"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "credential": "credential",
                "notification_id": "notification_id"
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    formatter_provider
        .expect_get_credential_formatter()
        .with(predicate::eq("JWT"))
        .returning(move |_| {
            let mut formatter = MockCredentialFormatter::new();
            formatter.expect_get_leeway().returning(|| 1000);

            formatter
                .expect_extract_credentials()
                .returning(move |_, _, _, _| {
                    Ok(DetailCredential {
                        id: None,
                        issuance_date: None,
                        valid_from: Some(OffsetDateTime::now_utc() - Duration::days(1)),
                        valid_until: Some(OffsetDateTime::now_utc() + Duration::days(1)),
                        update_at: None,
                        invalid_before: None,
                        issuer: IdentifierDetails::Key(PublicKeyJwk::Ec(
                            PublicKeyJwkEllipticData {
                                alg: None,
                                r#use: None,
                                kid: None,
                                crv: "P-256".to_string(),
                                x: "ShVYnVH7gJEbuydvCuxK3erCLINJQ27Ym_HU-I2uSkQ".to_string(),
                                y: Some("4oKwI2kCcDpDpC6ZNVpkO9v0UjLKqMNEXuMDHjRMnPM".to_string()),
                            },
                        )),
                        subject: None,
                        claims: CredentialSubject {
                            id: None,
                            claims: HashMap::new(),
                        },
                        status: vec![],
                        credential_schema: None,
                    })
                });

            Some(Arc::new(formatter))
        });

    storage_access
        .expect_get_credential_by_interaction_id()
        .returning({
            let clone = credential.clone();
            move |_| Ok(clone.clone())
        });

    storage_access
        .expect_update_interaction()
        .returning(|_, _| Ok(()));

    storage_access
        .expect_get_key_by_raw_key_and_type()
        .returning(|_, _, _| Ok(None));

    storage_access
        .expect_get_identifier_for_key()
        .returning(move |_, _| Ok(None));

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

    key_algorithm_provider
        .expect_reconstruct_key()
        .returning(|_, _, _, _| {
            let mut key_handle = MockSignaturePublicKeyHandle::default();
            key_handle.expect_as_jwk().return_once(|| {
                Ok(PublicKeyJwk::Ec(PublicKeyJwkEllipticData {
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

    let openid_provider = setup_protocol(TestInputs {
        formatter_provider,
        key_provider,
        key_algorithm_provider,
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

    let create_key = result.create_key.expect("should return create key");
    let create_identifier = result
        .create_identifier
        .expect("should return create identifier");
    assert_eq!(Some(create_key), create_identifier.key);

    let update_credential = result.update_credential.unwrap();
    assert_eq!(update_credential.0, credential.id);
    assert_eq!(
        update_credential.1.issuer_identifier_id.unwrap(),
        create_identifier.id
    );
}

#[tokio::test]
async fn test_holder_accept_expired_credential_fails() {
    let mock_server = MockServer::start().await;
    let mut formatter_provider = MockCredentialFormatterProvider::default();
    let mut storage_access = MockStorageProxy::default();
    let mut key_provider = MockKeyProvider::default();

    let interaction_data = HolderInteractionData {
        issuer_url: mock_server.uri(),
        credential_endpoint: format!("{}/credential", mock_server.uri()),
        token_endpoint: Some(format!("{}/token", mock_server.uri())),
        notification_endpoint: Some(format!("{}/notification", mock_server.uri())),
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
        nonce: None,
        refresh_token_expires_at: None,
        cryptographic_binding_methods_supported: None,
        credential_signing_alg_values_supported: None,
        proof_types_supported: None,
        continue_issuance: None,
        notification_id: None,
    };

    let interaction = Interaction {
        id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965").unwrap(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        data: Some(serde_json::to_vec(&interaction_data).unwrap()),
        organisation: None,
        nonce_id: None,
        interaction_type: InteractionType::Issuance,
    };

    let credential = Credential {
        interaction: Some(interaction.clone()),
        ..generic_credential_did()
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
        .and(path("/credential"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "credential": "credential",
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
            "event": "credential_failure",
            "event_description": "Issuance protocol failure: `Validation error: `Expired``"
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&mock_server)
        .await;

    formatter_provider
        .expect_get_credential_formatter()
        .with(predicate::eq("JWT"))
        .returning(move |_| {
            let mut formatter = MockCredentialFormatter::new();
            formatter.expect_get_leeway().returning(|| 1000);

            formatter
                .expect_extract_credentials()
                .returning(move |_, _, _, _| {
                    Ok(DetailCredential {
                        id: None,
                        issuance_date: None,
                        valid_from: Some(get_dummy_date() - Duration::weeks(2)),
                        valid_until: Some(get_dummy_date() - Duration::weeks(1)),
                        update_at: None,
                        invalid_before: None,
                        issuer: IdentifierDetails::Did(dummy_did().did),
                        subject: None,
                        claims: CredentialSubject {
                            id: None,
                            claims: HashMap::new(),
                        },
                        status: vec![],
                        credential_schema: None,
                    })
                });

            Some(Arc::new(formatter))
        });

    storage_access
        .expect_get_credential_by_interaction_id()
        .returning({
            let clone = credential.clone();
            move |_| Ok(clone.clone())
        });

    storage_access
        .expect_update_interaction()
        .returning(|_, _| Ok(()));

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
                Ok(PublicKeyJwk::Ec(PublicKeyJwkEllipticData {
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

    let openid_provider = setup_protocol(TestInputs {
        formatter_provider,
        key_provider,
        key_algorithm_provider,
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
        .await;

    assert!(result.is_err());
    assert!(
        result
            .err()
            .unwrap()
            .to_string()
            .contains("Validation error: `Expired`")
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
            notification_endpoint: Some(format!("{}/notification", mock_server.uri())),
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
            nonce: None,
            refresh_token_expires_at: None,
            cryptographic_binding_methods_supported: None,
            credential_signing_alg_values_supported: None,
            proof_types_supported: None,
            continue_issuance: None,
            notification_id: Some("notification_id".to_string()),
        };

        credential.interaction = Some(Interaction {
            id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965").unwrap(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            data: Some(serde_json::to_vec(&interaction_data).unwrap()),
            organisation: None,
            nonce_id: None,
            interaction_type: InteractionType::Issuance,
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
                    Ok(PublicKeyJwk::Ec(PublicKeyJwkEllipticData {
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
        params: Some(OpenID4VCIDraft13Params {
            pre_authorized_code_expires_in: 10,
            token_expires_in: 10,
            credential_offer_by_value: true,
            refresh_expires_in: 1000,
            encryption,
            url_scheme: "openid-credential-offer".to_string(),
            redirect_uri: OpenID4VCRedirectUriParams {
                enabled: true,
                allowed_schemes: vec!["https".to_string()],
            },
            enable_credential_preview: true,
        }),
        ..Default::default()
    });

    openid_provider
        .holder_reject_credential(credential, &storage_access)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_handle_invitation_credential_by_ref_without_did_success() {
    inner_test_handle_invitation_credential_by_ref_success(
        MockIdentifierCreator::default(),
        MockStorageProxy::default(),
        generic_credential_did(),
        None,
        true,
    )
    .await;
}

#[tokio::test]
async fn test_handle_invitation_credential_no_openid_configuration_success() {
    inner_test_handle_invitation_credential_by_ref_success(
        MockIdentifierCreator::default(),
        MockStorageProxy::default(),
        generic_credential_did(),
        None,
        false,
    )
    .await;
}

async fn inner_test_handle_invitation_credential_by_ref_success(
    identifier_creator: MockIdentifierCreator,
    mut storage_proxy: MockStorageProxy,
    credential: Credential,
    issuer_did: Option<String>,
    openid_configuration_enabled: bool,
) {
    let mock_server = MockServer::start().await;
    let issuer_url = Url::from_str(&mock_server.uri()).unwrap();

    let credential_schema_id = credential.schema.clone().unwrap().id;
    let credential_issuer = format!("{issuer_url}/ssi/openid4vci/draft-13/{credential_schema_id}",);

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
                    "value_type": "NUMBER"
                }
            },
            "wallet_storage_type": "SOFTWARE"
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
            "/ssi/openid4vci/draft-13/{}/offer/{}",
            credential_schema_id, credential.id
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(credential_offer))
        .expect(1)
        .mount(&mock_server)
        .await;

    let mut metadata_cache = MockOpenIDMetadataFetcher::new();
    if openid_configuration_enabled {
        let token_endpoint = format!("{credential_issuer}/token");
        metadata_cache
            .expect_get()
            .with(eq(format!(
                "{credential_issuer}/.well-known/oauth-authorization-server"
            )))
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
                            "token_endpoint": token_endpoint
                        }
                    )
                    .to_string()
                    .into_bytes())
                }
            });
    } else {
        metadata_cache
            .expect_get()
            .with(eq(format!(
                "{credential_issuer}/.well-known/oauth-authorization-server"
            )))
            .once()
            .returning(|_| {
                Err(CacheError::Resolver(ResolverError::InvalidResponse(
                    "".to_string(),
                )))
            });
    }

    metadata_cache
        .expect_get()
        .with(eq(format!(
            "{credential_issuer}/.well-known/openid-credential-issuer"
        )))
        .once()
        .returning(move |_| {
            Ok(json!({
                "credential_endpoint": format!("{credential_issuer}/credential"),
                "credential_issuer": credential_issuer,
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
            })
            .to_string()
            .into_bytes())
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
    storage_proxy
        .expect_get_schema()
        .times(1)
        .returning(|_, _| Ok(None));
    storage_proxy
        .expect_create_credential()
        .times(1)
        .returning(|c| Ok(c.id));

    let mut operations = MockHandleInvitationOperations::default();
    operations
        .expect_create_new_schema()
        .once()
        .returning(move |_, _, _, _, _, _| {
            Ok(BuildCredentialSchemaResponse {
                claims: credential.claims.clone().unwrap(),
                schema: credential.schema.clone().unwrap(),
            })
        });

    let url = Url::parse(&format!("openid-credential-offer://?credential_offer_uri=http%3A%2F%2F{}%2Fssi%2Fopenid4vci%2Fdraft-13%2F{credential_schema_id}%2Foffer%2F{}", issuer_url.authority(), credential.id)).unwrap();

    let protocol = setup_protocol(TestInputs {
        handle_invitation_operations: operations,
        metadata_cache,
        identifier_creator,
        ..Default::default()
    });
    let result = protocol
        .holder_handle_invitation(url, dummy_organisation(None), &storage_proxy, None)
        .await
        .unwrap();

    let InvitationResponseEnum::Credential { interaction_id, .. } = result else {
        panic!("Invalid response type");
    };
    assert_eq!(
        capture_integration_id.lock().unwrap().unwrap(),
        interaction_id
    );
}

#[tokio::test]
async fn test_continue_issuance_no_openid_configuration_and_scope_success() {
    inner_continue_issuance_test(false, true, false).await;
}

#[tokio::test]
async fn test_continue_issuance_with_openid_configuration_and_credential_configuration_ids_success()
{
    inner_continue_issuance_test(true, false, true).await;
}

#[tokio::test]
async fn test_continue_issuance_with_openid_configuration_and_scope_and_credential_configuration_ids_success()
 {
    inner_continue_issuance_test(true, true, true).await;
}

async fn inner_continue_issuance_test(
    openid_configuration_enabled: bool,
    with_scope: bool,
    with_credential_configuration_ids: bool,
) {
    let mut storage_proxy = MockStorageProxy::default();
    let credential = generic_credential_did();

    let credential_schema_id = credential.schema.clone().unwrap().id;
    let credential_issuer = format!("http://issuer/ssi/openid4vci/draft-13/{credential_schema_id}");

    let mut metadata_cache = MockOpenIDMetadataFetcher::new();

    let auth_server_metadata_url =
        format!("{credential_issuer}/.well-known/oauth-authorization-server");
    if openid_configuration_enabled {
        metadata_cache
            .expect_get()
            .with(eq(auth_server_metadata_url))
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
    } else {
        metadata_cache
            .expect_get()
            .with(eq(auth_server_metadata_url))
            .once()
            .returning(|_| {
                Err(CacheError::Resolver(ResolverError::InvalidResponse(
                    "".to_string(),
                )))
            });
    }

    metadata_cache
        .expect_get()
        .with(eq(format!(
            "{credential_issuer}/.well-known/openid-credential-issuer"
        )))
        .once()
        .returning({
            let credential_issuer = credential_issuer.clone();
            move |_| {
                Ok(json!({
                    "credential_endpoint": format!("{credential_issuer}/credential"),
                    "credential_issuer": credential_issuer,
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

    storage_proxy
        .expect_create_credential()
        .times(1)
        .returning(|_| Ok(Uuid::new_v4().into()));

    storage_proxy
        .expect_create_interaction()
        .times(1)
        .returning(|_| Ok(Uuid::new_v4()));
    storage_proxy
        .expect_get_schema()
        .times(1)
        .returning(|_, _| Ok(None));

    let mut operations = MockHandleInvitationOperations::default();
    operations
        .expect_create_new_schema()
        .once()
        .returning(move |_, _, _, _, _, _| {
            Ok(BuildCredentialSchemaResponse {
                claims: credential.claims.clone().unwrap(),
                schema: credential.schema.clone().unwrap(),
            })
        });

    let protocol = setup_protocol(TestInputs {
        handle_invitation_operations: operations,
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
        .await;
    let_assert!(Ok(_) = result);
}

#[test]
fn test_get_parent_claim_paths() {
    assert!(get_parent_claim_paths("").is_empty());
    assert!(get_parent_claim_paths("this_is_not_yellow").is_empty());
    assert_eq!(
        vec!["this", "this/is", "this/is/yellow"],
        get_parent_claim_paths("this/is/yellow/man")
    );
}

fn generic_schema() -> CredentialSchema {
    CredentialSchema {
        id: Uuid::new_v4().into(),
        deleted_at: None,
        imported_source_url: "CORE_URL".to_string(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        name: "LPTestNestedSelectiveZug".to_string(),
        format: "JSON_LD_BBSPLUS".to_string(),
        revocation_method: "NONE".to_string(),
        key_storage_security: None,
        layout_type: LayoutType::Card,
        layout_properties: None,
        schema_id: "http://127.0.0.1/ssi/schema/v1/id".to_string(),
        claim_schemas: Some(vec![
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "First Name".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
                    metadata: false,
                },
                required: true,
            },
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "Last Name".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
                    metadata: false,
                },
                required: true,
            },
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "Address".to_string(),
                    data_type: "OBJECT".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
                    metadata: false,
                },
                required: false,
            },
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "Address/Street".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
                    metadata: false,
                },
                required: true,
            },
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "Address/Number".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
                    metadata: false,
                },
                required: true,
            },
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "Address/Apartment".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
                    metadata: false,
                },
                required: false,
            },
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "Address/Zip".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
                    metadata: false,
                },
                required: true,
            },
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "Address/City".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
                    metadata: false,
                },
                required: true,
            },
        ]),
        organisation: Some(dummy_organisation(None)),
        allow_suspension: true,
        requires_app_attestation: false,
    }
}

fn generic_schema_array_object() -> CredentialSchema {
    CredentialSchema {
        id: Uuid::new_v4().into(),
        deleted_at: None,
        created_date: get_dummy_date(),
        imported_source_url: "CORE_URL".to_string(),
        last_modified: get_dummy_date(),
        name: "LPTestNestedSelectiveZug".to_string(),
        format: "JSON_LD_CLASSIC".to_string(),
        revocation_method: "NONE".to_string(),
        key_storage_security: None,
        layout_type: LayoutType::Card,
        layout_properties: None,
        schema_id: "http://127.0.0.1/ssi/schema/v1/id".to_string(),
        claim_schemas: Some(vec![
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "array_string".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: true,
                    metadata: false,
                },
                required: true,
            },
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "optional_array_string".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: true,
                    metadata: false,
                },
                required: false,
            },
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "array_object".to_string(),
                    data_type: "OBJECT".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: true,
                    metadata: false,
                },
                required: true,
            },
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "array_object/Field 1".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
                    metadata: false,
                },
                required: true,
            },
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "array_object/Field 2".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
                    metadata: false,
                },
                required: false,
            },
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "array_object/Field array".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: true,
                    metadata: false,
                },
                required: false,
            },
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "Address".to_string(),
                    data_type: "OBJECT".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
                    metadata: false,
                },
                required: true,
            },
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "Address/Street".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
                    metadata: false,
                },
                required: true,
            },
        ]),
        organisation: Some(dummy_organisation(None)),
        allow_suspension: true,
        requires_app_attestation: false,
    }
}

fn generic_schema_object_hell() -> CredentialSchema {
    CredentialSchema {
        id: Uuid::new_v4().into(),
        deleted_at: None,
        created_date: get_dummy_date(),
        imported_source_url: "CORE_URL".to_string(),
        last_modified: get_dummy_date(),
        name: "LPTestNestedSelectiveZug".to_string(),
        format: "JSON_LD_CLASSIC".to_string(),
        revocation_method: "NONE".to_string(),
        key_storage_security: None,
        layout_type: LayoutType::Card,
        layout_properties: None,
        schema_id: "http://127.0.0.1/ssi/schema/v1/id".to_string(),
        claim_schemas: Some(vec![
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "opt_obj".to_string(),
                    data_type: "OBJECT".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
                    metadata: false,
                },
                required: false,
            },
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "opt_obj/obj_str".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
                    metadata: false,
                },
                required: true,
            },
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "opt_obj/opt_obj".to_string(),
                    data_type: "OBJECT".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
                    metadata: false,
                },
                required: false,
            },
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "opt_obj/opt_obj/field_man".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
                    metadata: false,
                },
                required: true,
            },
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "opt_obj/opt_obj/field_opt".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
                    metadata: false,
                },
                required: false,
            },
        ]),
        organisation: Some(dummy_organisation(None)),
        allow_suspension: true,
        requires_app_attestation: false,
    }
}

#[test]
fn test_extract_offered_claims_success_missing_optional_object() {
    let schema = generic_schema();

    let claim_keys = IndexMap::from([
        (
            "Last Name".to_string(),
            OpenID4VCICredentialValueDetails {
                value: Some("Last Name Value".to_string()),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "First Name".to_string(),
            OpenID4VCICredentialValueDetails {
                value: Some("First Name Value".to_string()),
                value_type: "STRING".to_string(),
            },
        ),
    ]);

    let result = extract_offered_claims(&schema, Uuid::new_v4().into(), &claim_keys).unwrap();
    assert_eq!(2, result.len());

    let result = result
        .into_iter()
        .map(|v| (v.path, v.value))
        .collect::<HashMap<_, _>>();

    assert_eq!(claim_keys["First Name"].value, result["First Name"]);
    assert_eq!(claim_keys["Last Name"].value, result["Last Name"]);
}

#[test]
fn test_extract_offered_claims_failed_partially_missing_optional_object() {
    let schema = generic_schema();

    let claim_keys = IndexMap::from([
        (
            "Last Name".to_string(),
            OpenID4VCICredentialValueDetails {
                value: Some("Last Name Value".to_string()),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "First Name".to_string(),
            OpenID4VCICredentialValueDetails {
                value: Some("First Name Value".to_string()),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "Address/Street".to_string(),
            OpenID4VCICredentialValueDetails {
                value: Some("Street Value".to_string()),
                value_type: "STRING".to_string(),
            },
        ),
    ]);

    let result = extract_offered_claims(&schema, Uuid::new_v4().into(), &claim_keys);
    assert!(matches!(result, Err(IssuanceProtocolError::Failed(_))));
}

#[test]
fn test_extract_offered_claims_success_object_array() {
    let schema = generic_schema_array_object();

    let claim_keys = IndexMap::from([
        (
            "array_string/0".to_string(),
            OpenID4VCICredentialValueDetails {
                value: Some("111".to_string()),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "array_string/1".to_string(),
            OpenID4VCICredentialValueDetails {
                value: Some("222".to_string()),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "array_string/2".to_string(),
            OpenID4VCICredentialValueDetails {
                value: Some("333".to_string()),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "optional_array_string/0".to_string(),
            OpenID4VCICredentialValueDetails {
                value: Some("opt111".to_string()),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "array_object/0/Field 1".to_string(),
            OpenID4VCICredentialValueDetails {
                value: Some("01".to_string()),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "array_object/0/Field 2".to_string(),
            OpenID4VCICredentialValueDetails {
                value: Some("02".to_string()),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "array_object/0/Field array/0".to_string(),
            OpenID4VCICredentialValueDetails {
                value: Some("0array0".to_string()),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "array_object/0/Field array/1".to_string(),
            OpenID4VCICredentialValueDetails {
                value: Some("0array1".to_string()),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "array_object/1/Field 1".to_string(),
            OpenID4VCICredentialValueDetails {
                value: Some("11".to_string()),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "Address/Street".to_string(),
            OpenID4VCICredentialValueDetails {
                value: Some("Street Value".to_string()),
                value_type: "STRING".to_string(),
            },
        ),
        // Field 2 and array is missing for array object 2
    ]);

    let result = extract_offered_claims(&schema, Uuid::new_v4().into(), &claim_keys).unwrap();
    assert_eq!(17, result.len());

    for claim in result {
        if claim.value.is_some() {
            assert_eq!(claim_keys[claim.path.as_str()].value, claim.value)
        }
    }
}

#[test]
fn test_extract_offered_claims_success_optional_array_missing() {
    let schema = generic_schema_array_object();

    let claim_keys = IndexMap::from([
        (
            "array_string/0".to_string(),
            OpenID4VCICredentialValueDetails {
                value: Some("1".to_string()),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "array_object/0/Field 1".to_string(),
            OpenID4VCICredentialValueDetails {
                value: Some("01".to_string()),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "array_object/0/Field 2".to_string(),
            OpenID4VCICredentialValueDetails {
                value: Some("02".to_string()),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "Address/Street".to_string(),
            OpenID4VCICredentialValueDetails {
                value: Some("Street Value".to_string()),
                value_type: "STRING".to_string(),
            },
        ),
    ]);

    let result = extract_offered_claims(&schema, Uuid::new_v4().into(), &claim_keys).unwrap();
    assert_eq!(8, result.len());

    for claim in result {
        if claim.value.is_some() {
            assert_eq!(claim_keys[claim.path.as_str()].value, claim.value)
        }
    }
}

#[test]
fn test_extract_offered_claims_mandatory_array_missing_error() {
    let schema = generic_schema_array_object();

    let claim_keys = IndexMap::from([
        (
            "array_object/0/Field 1".to_string(),
            OpenID4VCICredentialValueDetails {
                value: Some("01".to_string()),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "array_object/0/Field 2".to_string(),
            OpenID4VCICredentialValueDetails {
                value: Some("02".to_string()),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "Address/Street".to_string(),
            OpenID4VCICredentialValueDetails {
                value: Some("Street Value".to_string()),
                value_type: "STRING".to_string(),
            },
        ),
    ]);

    assert!(extract_offered_claims(&schema, Uuid::new_v4().into(), &claim_keys).is_err())
}

#[test]
fn test_extract_offered_claims_mandatory_array_object_field_missing_error() {
    let schema = generic_schema_array_object();

    let claim_keys = IndexMap::from([
        (
            "array_string/0".to_string(),
            OpenID4VCICredentialValueDetails {
                value: Some("1".to_string()),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "array_object/0/Field 2".to_string(),
            OpenID4VCICredentialValueDetails {
                value: Some("02".to_string()),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "Address/Street".to_string(),
            OpenID4VCICredentialValueDetails {
                value: Some("Street Value".to_string()),
                value_type: "STRING".to_string(),
            },
        ),
    ]);

    assert!(extract_offered_claims(&schema, Uuid::new_v4().into(), &claim_keys).is_err())
}

#[test]
fn test_extract_offered_claims_mandatory_object_error() {
    let schema = generic_schema_array_object();

    let claim_keys = IndexMap::from([
        (
            "array_string/0".to_string(),
            OpenID4VCICredentialValueDetails {
                value: Some("1".to_string()),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "array_object/0/Field 1".to_string(),
            OpenID4VCICredentialValueDetails {
                value: Some("02".to_string()),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "array_object/0/Field 2".to_string(),
            OpenID4VCICredentialValueDetails {
                value: Some("02".to_string()),
                value_type: "STRING".to_string(),
            },
        ),
    ]);

    assert!(extract_offered_claims(&schema, Uuid::new_v4().into(), &claim_keys).is_err())
}

#[test]
fn test_extract_offered_claims_opt_object_opt_obj_present() {
    let schema = generic_schema_object_hell();

    let claim_keys = IndexMap::from([
        (
            "opt_obj/obj_str".to_string(),
            OpenID4VCICredentialValueDetails {
                value: Some("os".to_string()),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "opt_obj/opt_obj/field_man".to_string(),
            OpenID4VCICredentialValueDetails {
                value: Some("oofm".to_string()),
                value_type: "STRING".to_string(),
            },
        ),
    ]);

    let result = extract_offered_claims(&schema, Uuid::new_v4().into(), &claim_keys).unwrap();
    assert_eq!(4, result.len());

    for claim in result {
        if claim.value.is_some() {
            assert_eq!(claim_keys[claim.path.as_str()].value, claim.value)
        }
    }
}

#[test]
fn test_extract_offered_claims_opt_object_opt_obj_missing() {
    let schema = generic_schema_object_hell();

    let claim_keys = IndexMap::from([(
        "opt_obj/obj_str".to_string(),
        OpenID4VCICredentialValueDetails {
            value: Some("os".to_string()),
            value_type: "STRING".to_string(),
        },
    )]);

    let result = extract_offered_claims(&schema, Uuid::new_v4().into(), &claim_keys).unwrap();
    assert_eq!(2, result.len());

    for claim in result {
        if claim.value.is_some() {
            assert_eq!(claim_keys[claim.path.as_str()].value, claim.value)
        }
    }
}

#[test]
fn test_extract_offered_claims_opt_object_opt_obj_present_man_field_missing_error() {
    let schema = generic_schema_object_hell();

    let claim_keys = IndexMap::from([
        (
            "opt_obj/obj_str".to_string(),
            OpenID4VCICredentialValueDetails {
                value: Some("os".to_string()),
                value_type: "STRING".to_string(),
            },
        ),
        (
            "opt_obj/opt_obj/field_opt".to_string(),
            OpenID4VCICredentialValueDetails {
                value: Some("oofm".to_string()),
                value_type: "STRING".to_string(),
            },
        ),
    ]);

    assert!(extract_offered_claims(&schema, Uuid::new_v4().into(), &claim_keys).is_err())
}

#[test]
fn test_extract_offered_claims_opt_object_opt_obj_present_man_root_field_missing_error() {
    let schema = generic_schema_object_hell();

    let claim_keys = IndexMap::from([(
        "opt_obj/opt_obj/field_man".to_string(),
        OpenID4VCICredentialValueDetails {
            value: Some("oofm".to_string()),
            value_type: "STRING".to_string(),
        },
    )]);

    assert!(extract_offered_claims(&schema, Uuid::new_v4().into(), &claim_keys).is_err())
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

fn test_params(issuance_url_scheme: &str) -> OpenID4VCIDraft13Params {
    OpenID4VCIDraft13Params {
        pre_authorized_code_expires_in: 10,
        token_expires_in: 10,
        credential_offer_by_value: true,
        refresh_expires_in: 1000,
        encryption: SecretSlice::from(vec![0; 32]),
        url_scheme: issuance_url_scheme.to_string(),
        redirect_uri: OpenID4VCRedirectUriParams {
            enabled: true,
            allowed_schemes: vec!["https".to_string()],
        },
        enable_credential_preview: true,
    }
}
