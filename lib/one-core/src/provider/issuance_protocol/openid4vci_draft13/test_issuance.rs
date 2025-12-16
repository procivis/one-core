use std::collections::HashMap;
use std::sync::Arc;

use mockall::predicate::eq;
use secrecy::SecretSlice;
use serde_json::json;
use shared_types::CredentialId;
use similar_asserts::assert_eq;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::config::core_config::{
    CoreConfig, DatatypeType, Fields, FormatType, Params, RevocationType,
};
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{Credential, CredentialRole, CredentialStateEnum};
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaClaim, KeyStorageSecurity, LayoutType,
};
use crate::model::did::{Did, DidType, KeyRole, RelatedKey};
use crate::model::identifier::Identifier;
use crate::model::interaction::{Interaction, InteractionType};
use crate::model::key::Key;
use crate::model::validity_credential::{ValidityCredential, ValidityCredentialType};
use crate::proto::certificate_validator::MockCertificateValidator;
use crate::proto::http_client::MockHttpClient;
use crate::proto::identifier_creator::MockIdentifierCreator;
use crate::provider::blob_storage_provider::{MockBlobStorage, MockBlobStorageProvider};
use crate::provider::caching_loader::openid_metadata::MockOpenIDMetadataFetcher;
use crate::provider::credential_formatter::MockCredentialFormatter;
use crate::provider::credential_formatter::model::{CredentialStatus, MockSignatureProvider};
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::issuance_protocol::IssuanceProtocol;
use crate::provider::issuance_protocol::error::IssuanceProtocolError;
use crate::provider::issuance_protocol::model::OpenID4VCRedirectUriParams;
use crate::provider::issuance_protocol::openid4vci_draft13::OpenID4VCI13;
use crate::provider::issuance_protocol::openid4vci_draft13::handle_invitation_operations::MockHandleInvitationOperations;
use crate::provider::issuance_protocol::openid4vci_draft13::model::OpenID4VCIDraft13Params;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::key_security_level::provider::MockKeySecurityLevelProvider;
use crate::provider::key_storage::provider::MockKeyProvider;
use crate::provider::revocation::MockRevocationMethod;
use crate::provider::revocation::model::{CredentialRevocationInfo, JsonLdContext};
use crate::provider::revocation::none::NoneRevocation;
use crate::provider::revocation::provider::MockRevocationMethodProvider;
use crate::repository::credential_repository::MockCredentialRepository;
use crate::repository::key_repository::MockKeyRepository;
use crate::repository::validity_credential_repository::MockValidityCredentialRepository;
use crate::service::test_utilities::{dummy_identifier, dummy_organisation, generic_config};

#[tokio::test]
async fn test_issuer_submit_succeeds() {
    let credential_id: CredentialId = Uuid::new_v4().into();
    let key_storage_type = "storage type";
    let key_type = "EDDSA";

    let key = Key {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        public_key: b"public_key".to_vec(),
        name: "key name".to_string(),
        key_reference: Some(b"private_key".to_vec()),
        storage_type: key_storage_type.to_string(),
        key_type: key_type.to_string(),
        organisation: Some(dummy_organisation(None)),
    };

    let credential = Credential {
        state: CredentialStateEnum::Offered,
        suspend_end_date: None,
        holder_identifier: Some(Identifier {
            did: Some(dummy_did()),
            ..dummy_identifier()
        }),
        issuer_identifier: Some(Identifier {
            did: Some(Did {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: key.to_owned(),
                    reference: "1".to_string(),
                }]),
                ..dummy_did()
            }),
            ..dummy_identifier()
        }),
        key: Some(key),
        ..dummy_credential()
    };

    let credential_copy = credential.clone();
    let mut credential_repository = MockCredentialRepository::new();
    credential_repository
        .expect_get_credential()
        .withf(move |_credential_id, _| {
            assert_eq!(_credential_id, &credential_id);
            true
        })
        .once()
        .return_once(move |_, _| {
            let mut credential = credential_copy;
            credential.schema = Some(crate::model::credential_schema::CredentialSchema {
                organisation: Some(dummy_organisation(None)),
                ..credential.schema.unwrap()
            });
            Ok(Some(credential))
        });

    credential_repository
        .expect_update_credential()
        .once()
        .return_once(|_, _| Ok(()));

    let mut revocation_method = MockRevocationMethod::new();
    revocation_method
        .expect_get_json_ld_context()
        .once()
        .return_once(|| Ok(JsonLdContext::default()));
    revocation_method
        .expect_add_issued_credential()
        .once()
        .return_once(|_| {
            Ok(vec![CredentialRevocationInfo {
                credential_status: CredentialStatus {
                    id: Some(Uuid::new_v4().urn().to_string().parse().unwrap()),
                    r#type: "type".to_string(),
                    status_purpose: Some("type".to_string()),
                    additional_fields: HashMap::new(),
                },
            }])
        });

    let mut revocation_method_provider = MockRevocationMethodProvider::new();
    revocation_method_provider
        .expect_get_revocation_method()
        .once()
        .return_once(move |_| Some(Arc::new(revocation_method)));

    let mut formatter = MockCredentialFormatter::new();
    formatter
        .expect_format_credential()
        .once()
        .returning(|_, _| Ok("token".to_string()));

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .return_once(move |_| Some(Arc::new(formatter)));

    let mut key_provider = MockKeyProvider::new();
    key_provider
        .expect_get_signature_provider()
        .once()
        .returning(|_, _, _| Ok(Box::<MockSignatureProvider>::default()));

    let mut blob_storage = MockBlobStorage::new();
    blob_storage.expect_create().once().return_once(|_| Ok(()));

    let blob_storage = Arc::new(blob_storage);
    let mut blob_storage_provider = MockBlobStorageProvider::new();
    blob_storage_provider
        .expect_get_blob_storage()
        .once()
        .returning(move |_| Some(blob_storage.clone()));

    let provider = OpenID4VCI13::new(
        Arc::new(MockHttpClient::new()),
        Arc::new(MockOpenIDMetadataFetcher::new()),
        Arc::new(credential_repository),
        Arc::new(MockKeyRepository::new()),
        Arc::new(MockValidityCredentialRepository::new()),
        Arc::new(formatter_provider),
        Arc::new(revocation_method_provider),
        Arc::new(MockDidMethodProvider::new()),
        Arc::new(MockKeyAlgorithmProvider::new()),
        Arc::new(MockKeySecurityLevelProvider::new()),
        Arc::new(key_provider),
        Arc::new(MockCertificateValidator::new()),
        Arc::new(MockIdentifierCreator::new()),
        Arc::new(blob_storage_provider),
        Some("http://example.com/".to_string()),
        Arc::new(generic_config().core),
        OpenID4VCIDraft13Params {
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
        },
        Arc::new(MockHandleInvitationOperations::new()),
    );

    let result = provider
        .issuer_issue_credential(
            &credential_id,
            dummy_identifier(),
            format!("{}#0", dummy_did().did),
        )
        .await;

    assert!(result.is_ok());
    assert!(result.unwrap().notification_id.is_some());
}

fn generic_mdoc_credential(format: &str, state: CredentialStateEnum) -> Credential {
    let key = dummy_key();

    Credential {
        state,
        suspend_end_date: None,
        holder_identifier: Some(Identifier {
            did: Some(dummy_did()),
            ..dummy_identifier()
        }),
        issuer_identifier: Some(Identifier {
            did: Some(Did {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: key.to_owned(),
                    reference: "1".to_string(),
                }]),
                ..dummy_did()
            }),
            ..dummy_identifier()
        }),
        key: Some(key),
        schema: Some(CredentialSchema {
            format: format.to_string(),
            ..dummy_credential().schema.unwrap()
        }),
        ..dummy_credential()
    }
}

#[tokio::test]
async fn test_issue_credential_for_mdoc_creates_validity_credential() {
    let credential_id: CredentialId = Uuid::new_v4().into();
    let format = "MDOC";

    let mut credential_repository = MockCredentialRepository::new();

    let credential = generic_mdoc_credential(format, CredentialStateEnum::Offered);
    let credential_copy = credential.clone();
    credential_repository
        .expect_get_credential()
        .withf(move |_credential_id, _| {
            assert_eq!(_credential_id, &credential_id);
            true
        })
        .once()
        .return_once(move |_, _| {
            let mut credential = credential_copy;
            credential.schema = Some(CredentialSchema {
                organisation: Some(dummy_organisation(None)),
                ..credential.schema.unwrap()
            });
            Ok(Some(credential))
        });

    credential_repository
        .expect_update_credential()
        .once()
        .return_once(|_, _| Ok(()));

    let mut revocation_method_provider = MockRevocationMethodProvider::new();
    revocation_method_provider
        .expect_get_revocation_method()
        .once()
        .return_once(move |_| Some(Arc::new(NoneRevocation {})));

    let mut formatter = MockCredentialFormatter::new();
    formatter
        .expect_format_credential()
        .once()
        .returning(|_, _| Ok("token".to_string()));

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .with(eq(format))
        .once()
        .return_once(move |_| Some(Arc::new(formatter)));

    let mut key_provider = MockKeyProvider::new();
    key_provider
        .expect_get_signature_provider()
        .once()
        .returning(|_, _, _| Ok(Box::<MockSignatureProvider>::default()));

    let mut validity_credential_repository = MockValidityCredentialRepository::new();
    validity_credential_repository
        .expect_insert()
        .once()
        .withf(move |validity_credential| {
            assert_eq!(ValidityCredentialType::Mdoc, validity_credential.r#type);
            assert_eq!(credential_id, validity_credential.linked_credential_id);
            assert_eq!(b"token", &validity_credential.credential.as_ref());
            true
        })
        .return_once(|_| Ok(()));

    let mut blob_storage = MockBlobStorage::new();
    blob_storage.expect_create().once().return_once(|_| Ok(()));

    let blob_storage = Arc::new(blob_storage);
    let mut blob_storage_provider = MockBlobStorageProvider::new();
    blob_storage_provider
        .expect_get_blob_storage()
        .once()
        .returning(move |_| Some(blob_storage.clone()));

    let service = OpenID4VCI13::new(
        Arc::new(MockHttpClient::new()),
        Arc::new(MockOpenIDMetadataFetcher::new()),
        Arc::new(credential_repository),
        Arc::new(MockKeyRepository::new()),
        Arc::new(validity_credential_repository),
        Arc::new(formatter_provider),
        Arc::new(revocation_method_provider),
        Arc::new(MockDidMethodProvider::new()),
        Arc::new(MockKeyAlgorithmProvider::new()),
        Arc::new(MockKeySecurityLevelProvider::new()),
        Arc::new(key_provider),
        Arc::new(MockCertificateValidator::new()),
        Arc::new(MockIdentifierCreator::new()),
        Arc::new(blob_storage_provider),
        Some("https://example.com/test/".to_string()),
        Arc::new(dummy_config()),
        OpenID4VCIDraft13Params {
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
        },
        Arc::new(MockHandleInvitationOperations::new()),
    );

    service
        .issuer_issue_credential(
            &credential_id,
            dummy_identifier(),
            format!("{}#0", dummy_did().did),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn test_issue_credential_for_existing_mdoc_creates_new_validity_credential() {
    let credential_id: CredentialId = Uuid::new_v4().into();
    let format = "MDOC";

    let credential = generic_mdoc_credential(format, CredentialStateEnum::Accepted);
    let credential_copy = credential.clone();
    let mut credential_repository = MockCredentialRepository::new();
    credential_repository
        .expect_get_credential()
        .withf(move |_credential_id, _| {
            assert_eq!(_credential_id, &credential_id);
            true
        })
        .once()
        .return_once(move |_, _| {
            let mut credential = credential_copy;
            credential.schema = Some(crate::model::credential_schema::CredentialSchema {
                organisation: Some(dummy_organisation(None)),
                ..credential.schema.unwrap()
            });
            Ok(Some(credential))
        });

    let mut revocation_method_provider = MockRevocationMethodProvider::new();
    revocation_method_provider
        .expect_get_revocation_method()
        .once()
        .return_once(move |_| Some(Arc::new(NoneRevocation {})));

    let mut formatter = MockCredentialFormatter::new();
    formatter
        .expect_format_credential()
        .once()
        .returning(|_, _| Ok("token".to_string()));

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .with(eq(format))
        .once()
        .return_once(move |_| Some(Arc::new(formatter)));

    let mut key_provider = MockKeyProvider::new();
    key_provider
        .expect_get_signature_provider()
        .once()
        .returning(|_, _, _| Ok(Box::<MockSignatureProvider>::default()));

    let mut validity_credential_repository = MockValidityCredentialRepository::new();

    validity_credential_repository
        .expect_get_latest_by_credential_id()
        .once()
        .with(eq(credential_id), eq(ValidityCredentialType::Mdoc))
        .return_once(move |_, _| {
            Ok(Some(ValidityCredential {
                id: Uuid::new_v4(),
                created_date: OffsetDateTime::now_utc() - Duration::days(5),
                credential: vec![1, 2, 3],
                linked_credential_id: credential_id,
                r#type: ValidityCredentialType::Mdoc,
            }))
        });
    validity_credential_repository
        .expect_insert()
        .once()
        .withf(move |validity_credential| {
            assert_eq!(ValidityCredentialType::Mdoc, validity_credential.r#type);
            assert_eq!(credential_id, validity_credential.linked_credential_id);
            assert_eq!(b"token", &validity_credential.credential.as_ref());
            true
        })
        .return_once(|_| Ok(()));

    let mut config = dummy_config();

    config.format.insert(
        "MDOC".to_string(),
        Fields {
            r#type: FormatType::Mdoc,
            display: "display".into(),
            order: None,
            priority: None,
            enabled: None,
            capabilities: None,
            params: Some(Params {
                public: Some(json!({
                    "msoExpectedUpdateIn": Duration::days(3).whole_seconds(),
                    "msoMinimumRefreshTime": Duration::days(3).whole_seconds(),
                    "msoExpiresIn": 10,
                    "leeway": 5,
                })),
                private: None,
            }),
        },
    );

    let service = OpenID4VCI13::new(
        Arc::new(MockHttpClient::new()),
        Arc::new(MockOpenIDMetadataFetcher::new()),
        Arc::new(credential_repository),
        Arc::new(MockKeyRepository::new()),
        Arc::new(validity_credential_repository),
        Arc::new(formatter_provider),
        Arc::new(revocation_method_provider),
        Arc::new(MockDidMethodProvider::new()),
        Arc::new(MockKeyAlgorithmProvider::new()),
        Arc::new(MockKeySecurityLevelProvider::new()),
        Arc::new(key_provider),
        Arc::new(MockCertificateValidator::new()),
        Arc::new(MockIdentifierCreator::new()),
        Arc::new(MockBlobStorageProvider::new()),
        Some("https://example.com/test/".to_string()),
        Arc::new(config),
        OpenID4VCIDraft13Params {
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
        },
        Arc::new(MockHandleInvitationOperations::new()),
    );

    service
        .issuer_issue_credential(
            &credential_id,
            dummy_identifier(),
            format!("{}#0", dummy_did().did),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn test_issue_credential_for_existing_mdoc_with_expected_update_in_the_future_fails() {
    let credential_id: CredentialId = Uuid::new_v4().into();
    let format = "MDOC";

    let credential = generic_mdoc_credential(format, CredentialStateEnum::Accepted);

    let credential_copy = credential.clone();
    let mut credential_repository = MockCredentialRepository::new();
    credential_repository
        .expect_get_credential()
        .withf(move |_credential_id, _| {
            assert_eq!(_credential_id, &credential_id);
            true
        })
        .once()
        .return_once(move |_, _| Ok(Some(credential_copy)));

    let mut validity_credential_repository = MockValidityCredentialRepository::new();
    validity_credential_repository
        .expect_get_latest_by_credential_id()
        .once()
        .with(eq(credential_id), eq(ValidityCredentialType::Mdoc))
        .return_once(move |_, _| {
            Ok(Some(ValidityCredential {
                id: Uuid::new_v4(),
                created_date: OffsetDateTime::now_utc() - Duration::days(1),
                credential: vec![1, 2, 3],
                linked_credential_id: credential_id,
                r#type: ValidityCredentialType::Mdoc,
            }))
        });

    let mut config = dummy_config();
    config.format.insert(
        format.to_string(),
        Fields {
            r#type: FormatType::Mdoc,
            display: "display".into(),
            order: None,
            priority: None,
            enabled: None,
            capabilities: None,
            params: Some(Params {
                public: Some(json!({
                    "msoExpectedUpdateIn": Duration::days(3).whole_seconds(),
                    "msoMinimumRefreshTime": Duration::days(3).whole_seconds(),
                    "msoExpiresIn": 10,
                    "leeway": 5,
                })),
                private: None,
            }),
        },
    );

    let service = OpenID4VCI13::new(
        Arc::new(MockHttpClient::new()),
        Arc::new(MockOpenIDMetadataFetcher::new()),
        Arc::new(credential_repository),
        Arc::new(MockKeyRepository::new()),
        Arc::new(validity_credential_repository),
        Arc::new(MockCredentialFormatterProvider::new()),
        Arc::new(MockRevocationMethodProvider::new()),
        Arc::new(MockDidMethodProvider::new()),
        Arc::new(MockKeyAlgorithmProvider::new()),
        Arc::new(MockKeySecurityLevelProvider::new()),
        Arc::new(MockKeyProvider::new()),
        Arc::new(MockCertificateValidator::new()),
        Arc::new(MockIdentifierCreator::new()),
        Arc::new(MockBlobStorageProvider::new()),
        Some("base_url".to_string()),
        Arc::new(config),
        OpenID4VCIDraft13Params {
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
        },
        Arc::new(MockHandleInvitationOperations::new()),
    );

    assert!(matches!(
        service
            .issuer_issue_credential(
                &credential_id,
                dummy_identifier(),
                format!("{}#0", dummy_did().did)
            )
            .await,
        Err(IssuanceProtocolError::RefreshTooSoon),
    ));
}

fn dummy_config() -> CoreConfig {
    let mut config = CoreConfig::default();

    config.datatype.insert(
        "STRING".to_string(),
        Fields {
            r#type: DatatypeType::String,
            display: "display".into(),
            order: None,
            priority: None,
            enabled: None,
            capabilities: None,
            params: None,
        },
    );

    config.revocation.insert(
        "NONE".to_string(),
        Fields {
            r#type: RevocationType::None,
            display: "display".into(),
            order: None,
            priority: None,
            enabled: None,
            capabilities: None,
            params: None,
        },
    );

    config.format.insert(
        "MDOC".to_string(),
        Fields {
            r#type: FormatType::Mdoc,
            display: "mdoc".into(),
            order: None,
            priority: None,
            enabled: None,
            capabilities: None,
            params: None,
        },
    );

    config
}

fn dummy_credential() -> Credential {
    let claim_schema_id = Uuid::new_v4().into();
    let credential_id = Uuid::new_v4().into();
    Credential {
        id: credential_id,
        created_date: OffsetDateTime::now_utc(),
        issuance_date: None,
        last_modified: OffsetDateTime::now_utc(),
        deleted_at: None,
        protocol: "protocol".to_string(),
        redirect_uri: None,
        role: CredentialRole::Holder,
        state: CredentialStateEnum::Pending,
        suspend_end_date: None,
        claims: Some(vec![Claim {
            id: Uuid::new_v4().into(),
            credential_id,
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            value: Some("claim value".to_string()),
            path: "key".to_string(),
            selectively_disclosable: false,
            schema: Some(ClaimSchema {
                id: claim_schema_id,
                key: "key".to_string(),
                data_type: "STRING".to_string(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                array: false,
                metadata: false,
            }),
        }]),
        issuer_identifier: None,
        issuer_certificate: None,
        holder_identifier: None,
        schema: Some(CredentialSchema {
            id: Uuid::new_v4().into(),
            imported_source_url: "CORE_URL".to_string(),
            deleted_at: None,
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            key_storage_security: Some(KeyStorageSecurity::Basic),
            name: "schema".to_string(),
            format: "JWT".to_string(),
            revocation_method: "NONE".to_string(),
            claim_schemas: Some(vec![CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: claim_schema_id,
                    key: "key".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    array: false,
                    metadata: false,
                },
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
            id: Uuid::new_v4(),
            created_date: OffsetDateTime::now_utc(),
            data: Some(b"interaction data".to_vec()),
            last_modified: OffsetDateTime::now_utc(),
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

fn dummy_did() -> Did {
    Did {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        name: "John".to_string(),
        did: "did:example:123".parse().unwrap(),
        did_type: DidType::Local,
        did_method: "John".to_string(),
        keys: None,
        organisation: None,
        deactivated: false,
        log: None,
    }
}

fn dummy_key() -> Key {
    Key {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        public_key: b"public_key".to_vec(),
        name: "key name".to_string(),
        key_reference: Some(b"private_key".to_vec()),
        storage_type: "SOFTWARE".to_string(),
        key_type: "EDDSA".to_string(),
        organisation: Some(dummy_organisation(None)),
    }
}
