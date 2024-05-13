use std::collections::HashSet;
use std::{collections::HashMap, sync::Arc};

use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use serde_json::{json, Value};
use shared_types::CredentialId;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::provider::credential_formatter::test_utilities::get_dummy_date;
use crate::provider::did_method::dto::{
    DidDocumentDTO, DidVerificationMethodDTO, PublicKeyJwkDTO, PublicKeyJwkEllipticDataDTO,
};
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::transport_protocol::dto::{CredentialGroup, CredentialGroupItem};
use crate::provider::transport_protocol::mapper::get_relevant_credentials_to_credential_schemas;
use crate::repository::credential_repository::CredentialRepository;
use crate::service::test_utilities::generic_config;
use crate::{
    config::core_config::{CoreConfig, Fields, KeyAlgorithmType, Params},
    model::{
        claim::Claim,
        claim_schema::ClaimSchema,
        credential::{Credential, CredentialRole, CredentialState, CredentialStateEnum},
        credential_schema::{
            CredentialSchema, CredentialSchemaClaim, CredentialSchemaType, LayoutType,
            WalletStorageTypeEnum,
        },
        did::{Did, DidType, KeyRole, RelatedKey},
        interaction::Interaction,
        key::Key,
        organisation::Organisation,
    },
    provider::{
        credential_formatter::{
            model::CredentialStatus, provider::MockCredentialFormatterProvider,
            MockCredentialFormatter, MockSignatureProvider,
        },
        key_storage::provider::MockKeyProvider,
        revocation::{
            provider::MockRevocationMethodProvider, CredentialRevocationInfo, JsonLdContext,
            MockRevocationMethod,
        },
        transport_protocol::provider::{TransportProtocolProvider, TransportProtocolProviderImpl},
    },
    repository::{
        credential_repository::MockCredentialRepository, history_repository::MockHistoryRepository,
    },
};

#[tokio::test]
async fn test_issuer_submit_succeeds() {
    let credential_id: CredentialId = Uuid::new_v4().into();
    let key_storage_type = "storage type";
    let key_type = "EDDSA";
    let algorithm = "algorithm";

    let mut credential_repository = MockCredentialRepository::new();
    credential_repository
        .expect_get_credential()
        .withf(move |_credential_id, _| {
            assert_eq!(_credential_id, &credential_id);
            true
        })
        .once()
        .return_once(move |_, _| {
            let key = Key {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                public_key: b"public_key".to_vec(),
                name: "key name".to_string(),
                key_reference: b"private_key".to_vec(),
                storage_type: key_storage_type.to_string(),
                key_type: key_type.to_string(),
                organisation: Some(Organisation {
                    id: Uuid::new_v4().into(),
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                }),
            };

            Ok(Some(Credential {
                state: Some(vec![CredentialState {
                    created_date: OffsetDateTime::now_utc(),
                    state: CredentialStateEnum::Offered,
                    suspend_end_date: None,
                }]),
                holder_did: Some(dummy_did()),
                issuer_did: Some(Did {
                    keys: Some(vec![RelatedKey {
                        role: KeyRole::AssertionMethod,
                        key: key.to_owned(),
                    }]),
                    ..dummy_did()
                }),
                key: Some(key),
                ..dummy_credential()
            }))
        });

    credential_repository
        .expect_update_credential()
        .once()
        .return_once(|_| Ok(()));

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
                    id: Uuid::new_v4().to_string(),
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
        .expect_format_credentials()
        .once()
        .returning(|_, _, _, _, _, _, _, _| Ok("token".to_string()));

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_formatter()
        .once()
        .return_once(move |_| Some(Arc::new(formatter)));

    let mut key_provider = MockKeyProvider::new();
    key_provider
        .expect_get_signature_provider()
        .once()
        .returning(|_, _| Ok(Box::<MockSignatureProvider>::default()));

    let mut config = dummy_config();
    config.key_algorithm.insert(
        "EDDSA".to_string(),
        Fields {
            r#type: KeyAlgorithmType::Eddsa,
            display: Value::String("display".to_string()),
            order: None,
            disabled: None,
            capabilities: None,
            params: Some(Params {
                public: Some(json!({
                    "algorithm": algorithm
                })),
                private: None,
            }),
        },
    );
    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .once()
        .returning(|_| Ok(Uuid::new_v4().into()));

    let mut did_method_provider = MockDidMethodProvider::new();
    did_method_provider
        .expect_resolve()
        .once()
        .returning(move |_| {
            Ok(DidDocumentDTO {
                context: json!({}),
                id: dummy_did().did,
                verification_method: vec![DidVerificationMethodDTO {
                    id: "did-vm-id".to_string(),
                    r#type: "did-vm-type".to_string(),
                    controller: "did-vm-controller".to_string(),
                    public_key_jwk: PublicKeyJwkDTO::Ec(PublicKeyJwkEllipticDataDTO {
                        r#use: None,
                        crv: "P-256".to_string(),
                        x: Base64UrlSafeNoPadding::encode_to_string("xabc").unwrap(),
                        y: Some(Base64UrlSafeNoPadding::encode_to_string("yabc").unwrap()),
                    }),
                }],
                authentication: None,
                assertion_method: Some(vec!["did-vm-id".to_string()]),
                key_agreement: None,
                capability_invocation: None,
                capability_delegation: None,
                rest: json!({}),
            })
        });

    let service = TransportProtocolProviderImpl::new(
        Default::default(),
        Arc::new(formatter_provider),
        Arc::new(credential_repository),
        Arc::new(revocation_method_provider),
        Arc::new(key_provider),
        Arc::new(history_repository),
        Arc::new(did_method_provider),
        Some("base_url".to_string()),
    );

    service
        .issue_credential(&credential_id, dummy_did())
        .await
        .unwrap();
}

fn dummy_config() -> CoreConfig {
    CoreConfig::default()
}

fn dummy_credential() -> Credential {
    let claim_schema_id = Uuid::new_v4().into();
    let credential_id = Uuid::new_v4().into();
    Credential {
        id: credential_id,
        created_date: OffsetDateTime::now_utc(),
        issuance_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        deleted_at: None,
        credential: b"credential".to_vec(),
        transport: "protocol".to_string(),
        redirect_uri: None,
        role: CredentialRole::Holder,
        state: Some(vec![CredentialState {
            created_date: OffsetDateTime::now_utc(),
            state: CredentialStateEnum::Pending,
            suspend_end_date: None,
        }]),
        claims: Some(vec![Claim {
            id: Uuid::new_v4(),
            credential_id,
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            value: "claim value".to_string(),
            schema: Some(ClaimSchema {
                id: claim_schema_id,
                key: "key".to_string(),
                data_type: "STRING".to_string(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
            }),
        }]),
        issuer_did: None,
        holder_did: None,
        schema: Some(CredentialSchema {
            id: Uuid::new_v4().into(),
            deleted_at: None,
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            name: "schema".to_string(),
            format: "JWT".to_string(),
            revocation_method: "revocation method".to_string(),
            claim_schemas: Some(vec![CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: claim_schema_id,
                    key: "key".to_string(),
                    data_type: "STRING".to_string(),
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                },
                required: true,
            }]),
            organisation: Some(Organisation {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
            }),
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_type: CredentialSchemaType::ProcivisOneSchema2024,
            schema_id: "CredentialSchemaId".to_owned(),
        }),
        interaction: Some(Interaction {
            id: Uuid::new_v4(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            host: Some("https://core.dev.one-trust-solution.com".parse().unwrap()),
            data: Some(b"interaction data".to_vec()),
        }),
        revocation_list: None,
        key: None,
    }
}

fn dummy_did() -> Did {
    Did {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        name: "John".to_string(),
        did: "did".parse().unwrap(),
        did_type: DidType::Local,
        did_method: "John".to_string(),
        keys: None,
        organisation: None,
        deactivated: false,
    }
}

#[tokio::test]
async fn test_get_relevant_credentials_to_credential_schemas_success_jwt() {
    let mut credential_repository = MockCredentialRepository::new();
    let mut credential = dummy_credential();
    credential
        .state
        .as_mut()
        .unwrap()
        .first_mut()
        .unwrap()
        .state = CredentialStateEnum::Accepted;

    let credential_copy = credential.to_owned();
    credential_repository
        .expect_get_credentials_by_credential_schema_id()
        .return_once(|_, _| Ok(vec![credential_copy]));

    let repository: Arc<dyn CredentialRepository> = Arc::new(credential_repository);
    let (result_credentials, _result_group) = get_relevant_credentials_to_credential_schemas(
        &repository,
        vec![CredentialGroup {
            id: "input_0".to_string(),
            claims: vec![CredentialGroupItem {
                id: "2ec8b9c0-ccbf-4000-a6a2-63491992291d".to_string(),
                key: "key".to_string(),
                required: true,
            }],
            applicable_credentials: vec![],
            validity_credential_nbf: None,
        }],
        HashMap::from([("input_0".to_string(), "schema_id".to_string())]),
        &HashSet::from(["JWT"]),
        &generic_config().core.format,
    )
    .await
    .unwrap();

    assert_eq!(1, result_credentials.len());
    assert_eq!(credential.id, result_credentials[0].id);
}

#[tokio::test]
async fn test_get_relevant_credentials_to_credential_schemas_failed_wrong_state() {
    let mut credential_repository = MockCredentialRepository::new();
    let credential = dummy_credential();

    let credential_copy = credential.to_owned();
    credential_repository
        .expect_get_credentials_by_credential_schema_id()
        .return_once(|_, _| Ok(vec![credential_copy]));

    let repository: Arc<dyn CredentialRepository> = Arc::new(credential_repository);
    let (result_credentials, _result_group) = get_relevant_credentials_to_credential_schemas(
        &repository,
        vec![CredentialGroup {
            id: "input_0".to_string(),
            claims: vec![CredentialGroupItem {
                id: "2ec8b9c0-ccbf-4000-a6a2-63491992291d".to_string(),
                key: "key".to_string(),
                required: true,
            }],
            applicable_credentials: vec![],
            validity_credential_nbf: None,
        }],
        HashMap::from([("input_0".to_string(), "schema_id".to_string())]),
        &HashSet::from(["JWT"]),
        &generic_config().core.format,
    )
    .await
    .unwrap();

    assert_eq!(0, result_credentials.len());
}

#[tokio::test]
async fn test_get_relevant_credentials_to_credential_schemas_failed_format_not_allowed() {
    let mut credential_repository = MockCredentialRepository::new();
    let mut credential = dummy_credential();
    credential
        .state
        .as_mut()
        .unwrap()
        .first_mut()
        .unwrap()
        .state = CredentialStateEnum::Accepted;

    let credential_copy = credential.to_owned();
    credential_repository
        .expect_get_credentials_by_credential_schema_id()
        .return_once(|_, _| Ok(vec![credential_copy]));

    let repository: Arc<dyn CredentialRepository> = Arc::new(credential_repository);
    let (result_credentials, _result_group) = get_relevant_credentials_to_credential_schemas(
        &repository,
        vec![CredentialGroup {
            id: "input_0".to_string(),
            claims: vec![CredentialGroupItem {
                id: "2ec8b9c0-ccbf-4000-a6a2-63491992291d".to_string(),
                key: "key".to_string(),
                required: true,
            }],
            applicable_credentials: vec![],
            validity_credential_nbf: None,
        }],
        HashMap::from([("input_0".to_string(), "schema_id".to_string())]),
        &HashSet::from(["SDJWT"]),
        &generic_config().core.format,
    )
    .await
    .unwrap();

    assert_eq!(0, result_credentials.len());
}

fn mdoc_credential() -> Credential {
    let mut credential = dummy_credential();

    let new_claim_schemas = [
        ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "namespace".to_string(),
            data_type: "OBJECT".to_string(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
        },
        ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "namespace/name".to_string(),
            data_type: "STRING".to_string(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
        },
    ];

    credential
        .state
        .as_mut()
        .unwrap()
        .first_mut()
        .unwrap()
        .state = CredentialStateEnum::Accepted;
    let schema = credential.schema.as_mut().unwrap();
    schema.format = "MDOC".to_string();
    *schema.claim_schemas.as_mut().unwrap() = vec![
        CredentialSchemaClaim {
            schema: new_claim_schemas[0].to_owned(),
            required: true,
        },
        CredentialSchemaClaim {
            schema: new_claim_schemas[1].to_owned(),
            required: true,
        },
    ];
    *credential.claims.as_mut().unwrap() = vec![Claim {
        id: Uuid::new_v4(),
        credential_id: credential.id.to_owned(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        value: "john".to_string(),
        schema: Some(new_claim_schemas[1].to_owned()),
    }];

    credential
}

#[tokio::test]
async fn test_get_relevant_credentials_to_credential_schemas_success_mdoc() {
    let mut credential_repository = MockCredentialRepository::new();
    let credential = mdoc_credential();

    let credential_copy = credential.to_owned();
    credential_repository
        .expect_get_credentials_by_credential_schema_id()
        .return_once(|_, _| Ok(vec![credential_copy]));

    let repository: Arc<dyn CredentialRepository> = Arc::new(credential_repository);
    let (result_credentials, _result_group) = get_relevant_credentials_to_credential_schemas(
        &repository,
        vec![CredentialGroup {
            id: "input_0".to_string(),
            claims: vec![CredentialGroupItem {
                id: "2ec8b9c0-ccbf-4000-a6a2-63491992291d".to_string(),
                key: "namespace/name".to_string(),
                required: true,
            }],
            applicable_credentials: vec![],
            validity_credential_nbf: None,
        }],
        HashMap::from([("input_0".to_string(), "schema_id".to_string())]),
        &HashSet::from(["MDOC"]),
        &generic_config().core.format,
    )
    .await
    .unwrap();

    assert_eq!(1, result_credentials.len());
}

#[tokio::test]
async fn test_get_relevant_credentials_to_credential_schemas_failed_first_level_selected() {
    let mut credential_repository = MockCredentialRepository::new();
    let credential = mdoc_credential();

    let credential_copy = credential.to_owned();
    credential_repository
        .expect_get_credentials_by_credential_schema_id()
        .return_once(|_, _| Ok(vec![credential_copy]));

    let repository: Arc<dyn CredentialRepository> = Arc::new(credential_repository);
    let (result_credentials, _result_group) = get_relevant_credentials_to_credential_schemas(
        &repository,
        vec![CredentialGroup {
            id: "input_0".to_string(),
            claims: vec![CredentialGroupItem {
                id: "2ec8b9c0-ccbf-4000-a6a2-63491992291d".to_string(),
                key: "namespace".to_string(),
                required: true,
            }],
            applicable_credentials: vec![],
            validity_credential_nbf: None,
        }],
        HashMap::from([("input_0".to_string(), "schema_id".to_string())]),
        &HashSet::from(["MDOC"]),
        &generic_config().core.format,
    )
    .await
    .unwrap();

    assert_eq!(0, result_credentials.len());
}
