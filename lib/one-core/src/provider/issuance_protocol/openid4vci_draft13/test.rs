use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use indexmap::IndexMap;
use mockall::predicate;
use secrecy::SecretSlice;
use serde_json::{Value, json};
use shared_types::DidValue;
use time::{Duration, OffsetDateTime};
use url::Url;
use uuid::Uuid;
use wiremock::http::Method;
use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::config::core_config::{CoreConfig, Fields, FormatType, KeyAlgorithmType};
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{Credential, CredentialRole, CredentialStateEnum};
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaClaim, CredentialSchemaType, LayoutType,
    WalletStorageTypeEnum,
};
use crate::model::did::{Did, DidType};
use crate::model::identifier::{Identifier, IdentifierState, IdentifierType};
use crate::model::interaction::Interaction;
use crate::provider::credential_formatter::MockCredentialFormatter;
use crate::provider::credential_formatter::model::{
    CredentialSubject, DetailCredential, IssuerDetails, MockSignatureProvider,
};
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::did_method::{DidCreated, MockDidMethod};
use crate::provider::http_client::reqwest_client::ReqwestClient;
use crate::provider::issuance_protocol::openid4vci_draft13::mapper::{
    extract_offered_claims, get_parent_claim_paths,
};
use crate::provider::issuance_protocol::openid4vci_draft13::model::{
    HolderInteractionData, OpenID4VCICredentialValueDetails, OpenID4VCIGrant, OpenID4VCIGrants,
    OpenID4VCIParams, OpenID4VCRedirectUriParams, OpenID4VCRejectionIdentifierParams,
};
use crate::provider::issuance_protocol::openid4vci_draft13::service::create_credential_offer;
use crate::provider::issuance_protocol::openid4vci_draft13::{IssuanceProtocolError, OpenID4VCI13};
use crate::provider::issuance_protocol::{
    BasicSchemaData, BuildCredentialSchemaResponse, IssuanceProtocol,
    MockHandleInvitationOperations,
};
use crate::provider::key_algorithm::MockKeyAlgorithm;
use crate::provider::key_algorithm::key::{
    KeyHandle, MockSignaturePrivateKeyHandle, MockSignaturePublicKeyHandle, SignatureKeyHandle,
};
use crate::provider::key_algorithm::model::GeneratedKey;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::key_storage::provider::MockKeyProvider;
use crate::provider::revocation::provider::MockRevocationMethodProvider;
use crate::repository::credential_repository::MockCredentialRepository;
use crate::repository::history_repository::MockHistoryRepository;
use crate::repository::revocation_list_repository::MockRevocationListRepository;
use crate::repository::validity_credential_repository::MockValidityCredentialRepository;
use crate::service::certificate::validator::MockCertificateValidator;
use crate::service::oid4vci_draft13::service::credentials_format;
use crate::service::storage_proxy::MockStorageProxy;
use crate::service::test_utilities::{
    dummy_did, dummy_identifier, dummy_key, dummy_organisation, get_dummy_date,
};

#[derive(Default)]
struct TestInputs {
    pub credential_repository: MockCredentialRepository,
    pub validity_credential_repository: MockValidityCredentialRepository,
    pub revocation_list_repository: MockRevocationListRepository,
    pub history_repository: MockHistoryRepository,
    pub formatter_provider: MockCredentialFormatterProvider,
    pub revocation_provider: MockRevocationMethodProvider,
    pub key_algorithm_provider: MockKeyAlgorithmProvider,
    pub key_provider: MockKeyProvider,
    pub did_method_provider: MockDidMethodProvider,
    pub certificate_validator: MockCertificateValidator,
    pub config: CoreConfig,
    pub params: Option<OpenID4VCIParams>,
}

fn setup_protocol(inputs: TestInputs) -> OpenID4VCI13 {
    OpenID4VCI13::new(
        Arc::new(ReqwestClient::default()),
        Arc::new(inputs.credential_repository),
        Arc::new(inputs.validity_credential_repository),
        Arc::new(inputs.revocation_list_repository),
        Arc::new(inputs.history_repository),
        Arc::new(inputs.formatter_provider),
        Arc::new(inputs.revocation_provider),
        Arc::new(inputs.did_method_provider),
        Arc::new(inputs.key_algorithm_provider),
        Arc::new(inputs.key_provider),
        Arc::new(inputs.certificate_validator),
        Some("http://base_url".to_string()),
        Arc::new(inputs.config),
        inputs.params.unwrap_or(OpenID4VCIParams {
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
            rejection_identifier: None,
        }),
    )
}

fn generic_credential() -> Credential {
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
    };

    let credential_id = Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
        .unwrap()
        .into();
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
    Credential {
        id: credential_id,
        created_date: now,
        issuance_date: now,
        last_modified: now,
        deleted_at: None,
        credential: vec![],
        exchange: "OPENID4VCI_DRAFT13".to_string(),
        redirect_uri: None,
        role: CredentialRole::Issuer,
        state: CredentialStateEnum::Created,
        suspend_end_date: None,
        claims: Some(vec![Claim {
            id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965").unwrap(),
            credential_id,
            created_date: now,
            last_modified: now,
            value: "123".to_string(),
            path: claim_schema.key.to_owned(),
            schema: Some(claim_schema.clone()),
        }]),
        issuer_identifier: Some(issuer_identifier),
        issuer_certificate: None,
        holder_identifier: None,
        schema: Some(CredentialSchema {
            id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965")
                .unwrap()
                .into(),
            deleted_at: None,
            imported_source_url: "CORE_URL".to_string(),
            created_date: now,
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            external_schema: false,
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
            schema_type: CredentialSchemaType::ProcivisOneSchema2024,
            schema_id: "CredentialSchemaId".to_owned(),
            organisation: Some(dummy_organisation(None)),
            allow_suspension: true,
        }),
        interaction: Some(Interaction {
            id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965").unwrap(),
            created_date: now,
            host: Some("http://host.co".parse().unwrap()),
            data: Some(vec![1, 2, 3]),
            last_modified: now,
            organisation: None,
        }),
        key: None,
        revocation_list: None,
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
async fn test_generate_offer() {
    let protocol_base_url = "BASE_URL/ssi/openid4vci/draft-13".to_string();
    let interaction_id = Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965").unwrap();
    let credential = generic_credential();

    let keys = credential.claims.unwrap_or_default();

    let credential_subject =
        credentials_format(Some(WalletStorageTypeEnum::Software), &keys).unwrap();

    let offer = create_credential_offer(
        &protocol_base_url,
        &interaction_id.to_string(),
        Some(credential.issuer_identifier.unwrap().did.unwrap().did),
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
async fn test_generate_share_credentials() {
    let credential = generic_credential();
    let protocol = setup_protocol(Default::default());

    let result = protocol.issuer_share_credential(&credential).await.unwrap();
    assert_eq!(
        result.url,
        "openid-credential-offer://?credential_offer_uri=http%3A%2F%2Fbase_url%2Fssi%2Fopenid4vci%2Fdraft-13%2Fc322aa7f-9803-410d-b891-939b279fb965%2Foffer%2Fc322aa7f-9803-410d-b891-939b279fb965"
    );
}

#[tokio::test]
async fn test_generate_share_credentials_offer_by_value() {
    let credential = generic_credential();

    let protocol = setup_protocol(TestInputs {
        params: Some(OpenID4VCIParams {
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
            rejection_identifier: None,
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
    let credential = generic_credential();

    let mut storage_proxy = MockStorageProxy::default();
    let credential_clone = credential.clone();
    storage_proxy
        .expect_get_or_create_did_and_identifier()
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
            Ok((
                did.clone(),
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
            ))
        });

    inner_test_handle_invitation_credential_by_ref_success(
        storage_proxy,
        credential,
        Some("did:example:123".to_string()),
    )
    .await;
}

#[tokio::test]
async fn test_holder_accept_credential_success() {
    let mock_server = MockServer::start().await;
    let mut formatter_provider = MockCredentialFormatterProvider::default();
    let mut storage_access = MockStorageProxy::default();
    let mut key_provider = MockKeyProvider::default();

    let credential = {
        let mut credential = generic_credential();

        let interaction_data = HolderInteractionData {
            issuer_url: mock_server.uri(),
            credential_endpoint: format!("{}/credential", mock_server.uri()),
            token_endpoint: Some(format!("{}/token", mock_server.uri())),
            notification_endpoint: Some(format!("{}/notification", mock_server.uri())),
            grants: Some(OpenID4VCIGrants {
                code: OpenID4VCIGrant {
                    pre_authorized_code: "code".to_string(),
                    tx_code: None,
                },
            }),
            access_token: None,
            access_token_expires_at: None,
            refresh_token: None,
            nonce: None,
            refresh_token_expires_at: None,
            cryptographic_binding_methods_supported: None,
            credential_signing_alg_values_supported: None,
        };

        credential.interaction = Some(Interaction {
            id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965").unwrap(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            host: Some(mock_server.uri().parse().unwrap()),
            data: Some(serde_json::to_vec(&interaction_data).unwrap()),
            organisation: None,
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
        .expect_get_formatter()
        .with(predicate::eq("JWT"))
        .returning(move |_| {
            let mut formatter = MockCredentialFormatter::new();
            formatter.expect_get_leeway().returning(|| 1000);

            formatter
                .expect_extract_credentials()
                .returning(move |_, _, _, _| {
                    Ok(DetailCredential {
                        id: None,
                        valid_from: Some(OffsetDateTime::now_utc() - Duration::days(1)),
                        valid_until: Some(OffsetDateTime::now_utc() + Duration::days(1)),
                        update_at: None,
                        invalid_before: None,
                        issuer: IssuerDetails::Did(dummy_did().did),
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
        .expect_update_interaction()
        .returning(|_| Ok(()));

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

    let openid_provider = setup_protocol(TestInputs {
        formatter_provider,
        key_provider,
        config: dummy_config(),
        ..Default::default()
    });

    let result = openid_provider
        .holder_accept_credential(
            &credential,
            &dummy_did(),
            &dummy_key(),
            None,
            &storage_access,
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
async fn test_holder_accept_expired_credential_fails() {
    let mock_server = MockServer::start().await;
    let mut formatter_provider = MockCredentialFormatterProvider::default();
    let mut storage_access = MockStorageProxy::default();
    let mut key_provider = MockKeyProvider::default();

    let credential = {
        let mut credential = generic_credential();

        let interaction_data = HolderInteractionData {
            issuer_url: mock_server.uri(),
            credential_endpoint: format!("{}/credential", mock_server.uri()),
            token_endpoint: Some(format!("{}/token", mock_server.uri())),
            notification_endpoint: Some(format!("{}/notification", mock_server.uri())),
            grants: Some(OpenID4VCIGrants {
                code: OpenID4VCIGrant {
                    pre_authorized_code: "code".to_string(),
                    tx_code: None,
                },
            }),
            access_token: None,
            access_token_expires_at: None,
            refresh_token: None,
            nonce: None,
            refresh_token_expires_at: None,
            cryptographic_binding_methods_supported: None,
            credential_signing_alg_values_supported: None,
        };

        credential.interaction = Some(Interaction {
            id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965").unwrap(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            host: Some(mock_server.uri().parse().unwrap()),
            data: Some(serde_json::to_vec(&interaction_data).unwrap()),
            organisation: None,
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
        .expect_get_formatter()
        .with(predicate::eq("JWT"))
        .returning(move |_| {
            let mut formatter = MockCredentialFormatter::new();
            formatter.expect_get_leeway().returning(|| 1000);

            formatter
                .expect_extract_credentials()
                .returning(move |_, _, _, _| {
                    Ok(DetailCredential {
                        id: None,
                        valid_from: Some(get_dummy_date() - Duration::weeks(2)),
                        valid_until: Some(get_dummy_date() - Duration::weeks(1)),
                        update_at: None,
                        invalid_before: None,
                        issuer: IssuerDetails::Did(dummy_did().did),
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
        .expect_update_interaction()
        .returning(|_| Ok(()));

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

    let openid_provider = setup_protocol(TestInputs {
        formatter_provider,
        key_provider,
        config: dummy_config(),
        ..Default::default()
    });

    let result = openid_provider
        .holder_accept_credential(
            &credential,
            &dummy_did(),
            &dummy_key(),
            None,
            &storage_access,
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
    let mut did_method_provider = MockDidMethodProvider::default();
    let mut key_algorithm_provider = MockKeyAlgorithmProvider::default();

    let credential = {
        let mut credential = generic_credential();

        let interaction_data = HolderInteractionData {
            issuer_url: mock_server.uri(),
            credential_endpoint: format!("{}/credential", mock_server.uri()),
            token_endpoint: Some(format!("{}/token", mock_server.uri())),
            notification_endpoint: Some(format!("{}/notification", mock_server.uri())),
            grants: Some(OpenID4VCIGrants {
                code: OpenID4VCIGrant {
                    pre_authorized_code: "code".to_string(),
                    tx_code: None,
                },
            }),
            access_token: None,
            access_token_expires_at: None,
            refresh_token: None,
            nonce: None,
            refresh_token_expires_at: None,
            cryptographic_binding_methods_supported: None,
            credential_signing_alg_values_supported: None,
        };

        credential.interaction = Some(Interaction {
            id: Uuid::from_str("c322aa7f-9803-410d-b891-939b279fb965").unwrap(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            host: Some(mock_server.uri().parse().unwrap()),
            data: Some(serde_json::to_vec(&interaction_data).unwrap()),
            organisation: None,
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

                let public_key = MockSignaturePublicKeyHandle::default();
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

        Some(Arc::new(method))
    });

    did_method_provider
        .expect_get_verification_method_id_from_did_and_key()
        .returning(|_, _| Ok("key-id".to_string()));

    let openid_provider = setup_protocol(TestInputs {
        did_method_provider,
        key_algorithm_provider,
        config: dummy_config(),
        params: Some(OpenID4VCIParams {
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
            rejection_identifier: Some(OpenID4VCRejectionIdentifierParams {
                did_method: "KEY".to_string(),
                key_algorithm: KeyAlgorithmType::Ecdsa,
            }),
        }),
        ..Default::default()
    });

    openid_provider
        .holder_reject_credential(&credential)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_handle_invitation_credential_by_ref_without_did_success() {
    inner_test_handle_invitation_credential_by_ref_success(
        MockStorageProxy::default(),
        generic_credential(),
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
    let credential_issuer = format!("{issuer_url}ssi/openid4vci/draft-13/{credential_schema_id}");

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
    let token_endpoint = format!("{credential_issuer}/token");
    Mock::given(method(Method::GET))
        .and(path(format!(
            "/ssi/openid4vci/draft-13/{credential_schema_id}/.well-known/openid-configuration"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
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
        )))
        .expect(1)
        .mount(&mock_server)
        .await;
    Mock::given(method(Method::GET))
        .and(path(format!(
            "/ssi/openid4vci/draft-13/{credential_schema_id}/.well-known/openid-credential-issuer"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
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
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    storage_proxy
        .expect_create_interaction()
        .times(1)
        .returning(|_| Ok(Uuid::new_v4()));
    storage_proxy
        .expect_get_schema()
        .times(1)
        .returning(|_, _, _| Ok(None));

    let mut operations = MockHandleInvitationOperations::default();
    let credential_clone = credential.clone();
    operations
        .expect_find_schema_data()
        .once()
        .returning(move |_, _| {
            Ok(BasicSchemaData {
                id: credential_schema_id.to_string(),
                r#type: "SD_JWT_VC".to_string(),
                external_schema: false,
                offer_id: credential_clone.id.to_string(),
            })
        });
    operations
        .expect_create_new_schema()
        .once()
        .returning(move |_, _, _, _, _, _| {
            Ok(BuildCredentialSchemaResponse {
                claims: credential.claims.clone().unwrap(),
                schema: credential.schema.clone().unwrap(),
            })
        });

    let url = Url::parse(&format!("openid-credential-offer://?credential_offer_uri=http%3A%2F%2F{}%2Fssi%2Fopenid4vci%2Fdraft-13%2F{}%2Foffer%2F{}", issuer_url.authority(), credential_schema_id, credential.id)).unwrap();

    let protocol = setup_protocol(Default::default());
    let result = protocol
        .holder_handle_invitation(url, dummy_organisation(None), &storage_proxy, &operations)
        .await
        .unwrap();

    let credentials = result.credentials;

    assert_eq!(credentials.len(), 1);

    if let Some(issuer_did) = issuer_did {
        assert_eq!(
            credentials[0]
                .issuer_identifier
                .as_ref()
                .unwrap()
                .did
                .as_ref()
                .unwrap()
                .did,
            DidValue::from_str(issuer_did.as_str()).unwrap()
        );
    } else {
        assert!(credentials[0].issuer_identifier.is_none());
    }
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
        wallet_storage_type: None,
        layout_type: LayoutType::Card,
        layout_properties: None,
        schema_id: "http://127.0.0.1/ssi/schema/v1/id".to_string(),
        external_schema: false,
        schema_type: CredentialSchemaType::ProcivisOneSchema2024,
        claim_schemas: Some(vec![
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "First Name".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
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
                },
                required: true,
            },
        ]),
        organisation: Some(dummy_organisation(None)),
        allow_suspension: true,
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
        wallet_storage_type: None,
        layout_type: LayoutType::Card,
        layout_properties: None,
        external_schema: false,
        schema_id: "http://127.0.0.1/ssi/schema/v1/id".to_string(),
        schema_type: CredentialSchemaType::ProcivisOneSchema2024,
        claim_schemas: Some(vec![
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "array_string".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: true,
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
                },
                required: true,
            },
        ]),
        organisation: Some(dummy_organisation(None)),
        allow_suspension: true,
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
        wallet_storage_type: None,
        layout_type: LayoutType::Card,
        layout_properties: None,
        schema_id: "http://127.0.0.1/ssi/schema/v1/id".to_string(),
        schema_type: CredentialSchemaType::ProcivisOneSchema2024,
        external_schema: false,
        claim_schemas: Some(vec![
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4().into(),
                    key: "opt_obj".to_string(),
                    data_type: "OBJECT".to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    array: false,
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
                },
                required: false,
            },
        ]),
        organisation: Some(dummy_organisation(None)),
        allow_suspension: true,
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

    assert_eq!(
        *claim_keys["First Name"].value.as_ref().unwrap(),
        result["First Name"]
    );
    assert_eq!(
        *claim_keys["Last Name"].value.as_ref().unwrap(),
        result["Last Name"]
    );
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
    assert_eq!(10, result.len());

    for claim in result {
        assert_eq!(
            *claim_keys[claim.path.as_str()].value.as_ref().unwrap(),
            claim.value
        )
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
    assert_eq!(4, result.len());

    for claim in result {
        assert_eq!(
            *claim_keys[claim.path.as_str()].value.as_ref().unwrap(),
            claim.value
        )
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
    assert_eq!(2, result.len());

    for claim in result {
        assert_eq!(
            *claim_keys[claim.path.as_str()].value.as_ref().unwrap(),
            claim.value
        )
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
    assert_eq!(1, result.len());

    for claim in result {
        assert_eq!(
            *claim_keys[claim.path.as_str()].value.as_ref().unwrap(),
            claim.value
        )
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

#[tokio::test]
async fn test_can_handle_issuance_success_with_custom_url_scheme() {
    let url_scheme = "my-custom-scheme";

    let protocol = setup_protocol(TestInputs {
        params: Some(test_params(url_scheme)),
        ..Default::default()
    });

    let test_url = format!(
        "{url_scheme}://?credential_offer_uri=http%3A%2F%2Fbase_url%2Fssi%2Foidc-issuer%2Fv1%2Fc322aa7f-9803-410d-b891-939b279fb965%2Foffer%2Fc322aa7f-9803-410d-b891-939b279fb965"
    );
    assert!(protocol.holder_can_handle(&test_url.parse().unwrap()))
}

#[test]
fn test_can_handle_issuance_fail_with_custom_url_scheme() {
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

#[test]
fn test_can_handle_presentation_fail_with_custom_url_scheme() {
    let other_url_scheme = "my-different-scheme";

    let protocol = setup_protocol(TestInputs {
        params: Some(test_params("issuance-url-scheme")),
        ..Default::default()
    });

    let test_url = format!(
        "{other_url_scheme}://?credential_offer_uri=http%3A%2F%2Fbase_url%2Fssi%2Foidc-issuer%2Fv1%2Fc322aa7f-9803-410d-b891-939b279fb965%2Foffer%2Fc322aa7f-9803-410d-b891-939b279fb965"
    );
    assert!(!protocol.holder_can_handle(&test_url.parse().unwrap()))
}

#[tokio::test]
async fn test_generate_share_credentials_custom_scheme() {
    let credential = generic_credential();
    let url_scheme = "my-custom-scheme";
    let protocol = setup_protocol(TestInputs {
        params: Some(test_params(url_scheme)),
        ..Default::default()
    });

    let result = protocol.issuer_share_credential(&credential).await.unwrap();
    assert!(result.url.starts_with(url_scheme));
}

fn test_params(issuance_url_scheme: &str) -> OpenID4VCIParams {
    OpenID4VCIParams {
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
        rejection_identifier: None,
    }
}
