use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use mockall::predicate::{always, eq};
use serde_json::{json, Value};
use shared_types::CredentialId;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::config::core_config::{CoreConfig, DatatypeType, Fields, Params};
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{Credential, CredentialRole, CredentialState, CredentialStateEnum};
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaClaim, CredentialSchemaType, LayoutType,
    WalletStorageTypeEnum,
};
use crate::model::did::{Did, DidType, KeyRole, RelatedKey};
use crate::model::interaction::Interaction;
use crate::model::key::{Key, PublicKeyJwk, PublicKeyJwkEllipticData};
use crate::model::organisation::Organisation;
use crate::model::revocation_list::{RevocationList, RevocationListPurpose};
use crate::model::validity_credential::{ValidityCredential, ValidityCredentialType};
use crate::provider::credential_formatter::model::{CredentialStatus, MockSignatureProvider};
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::credential_formatter::MockCredentialFormatter;
use crate::provider::did_method::model::{DidDocument, DidVerificationMethod};
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::exchange_protocol::dto::{CredentialGroup, CredentialGroupItem};
use crate::provider::exchange_protocol::mapper::get_relevant_credentials_to_credential_schemas;
use crate::provider::exchange_protocol::openid4vc::error::OpenID4VCIError;
use crate::provider::exchange_protocol::provider::{
    ExchangeProtocolProviderCoreImpl, ExchangeProtocolProviderExtra,
    MockExchangeProtocolProviderExtra,
};
use crate::provider::exchange_protocol::MockStorageProxy;
use crate::provider::key_storage::provider::MockKeyProvider;
use crate::provider::revocation::model::{CredentialRevocationInfo, JsonLdContext};
use crate::provider::revocation::none::NoneRevocation;
use crate::provider::revocation::provider::MockRevocationMethodProvider;
use crate::provider::revocation::MockRevocationMethod;
use crate::repository::credential_repository::MockCredentialRepository;
use crate::repository::history_repository::MockHistoryRepository;
use crate::repository::revocation_list_repository::MockRevocationListRepository;
use crate::repository::validity_credential_repository::MockValidityCredentialRepository;
use crate::service::error::ServiceError;
use crate::service::test_utilities::{dummy_organisation, generic_config, get_dummy_date};

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
        key_reference: b"private_key".to_vec(),
        storage_type: key_storage_type.to_string(),
        key_type: key_type.to_string(),
        organisation: Some(Organisation {
            id: Uuid::new_v4().into(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
        }),
    };

    let credential = Credential {
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
                organisation: Some(dummy_organisation()),
                ..credential.schema.unwrap()
            });
            Ok(Some(credential))
        });

    credential_repository
        .expect_get_credentials_by_issuer_did_id()
        .return_once(move |_, _| Ok(vec![credential]));

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
        .return_once(|_, _| {
            Ok((
                None,
                vec![CredentialRevocationInfo {
                    credential_status: CredentialStatus {
                        id: Some(Uuid::new_v4().urn().to_string().parse().unwrap()),
                        r#type: "type".to_string(),
                        status_purpose: Some("type".to_string()),
                        additional_fields: HashMap::new(),
                    },
                }],
            ))
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
            Ok(DidDocument {
                context: json!({}),
                id: dummy_did().did,
                verification_method: vec![DidVerificationMethod {
                    id: "did-vm-id".to_string(),
                    r#type: "did-vm-type".to_string(),
                    controller: "did-vm-controller".to_string(),
                    public_key_jwk: PublicKeyJwk::Ec(PublicKeyJwkEllipticData {
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
                rest: Default::default(),
            })
        });

    let mut revocation_list_repository = MockRevocationListRepository::default();
    revocation_list_repository
        .expect_get_revocation_by_issuer_did_id()
        .with(always(), eq(RevocationListPurpose::Revocation), always())
        .return_once(move |_, _, _| {
            Ok(Some(RevocationList {
                id: Default::default(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                credentials: vec![],
                purpose: RevocationListPurpose::Revocation,
                issuer_did: None,
            }))
        });
    revocation_list_repository
        .expect_get_revocation_by_issuer_did_id()
        .with(always(), eq(RevocationListPurpose::Suspension), always())
        .return_once(move |_, _, _| {
            Ok(Some(RevocationList {
                id: Default::default(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                credentials: vec![],
                purpose: RevocationListPurpose::Suspension,
                issuer_did: None,
            }))
        });

    let service = ExchangeProtocolProviderCoreImpl::new(
        Arc::new(MockExchangeProtocolProviderExtra::default()),
        Arc::new(formatter_provider),
        Arc::new(credential_repository),
        Arc::new(revocation_method_provider),
        Arc::new(key_provider),
        Arc::new(history_repository),
        Arc::new(did_method_provider),
        Arc::new(revocation_list_repository),
        Arc::new(MockValidityCredentialRepository::new()),
        Arc::new(generic_config().core),
        Some("base_url".to_string()),
    );

    let result = service.issue_credential(&credential_id, dummy_did()).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_get_relevant_credentials_to_credential_schemas_success_jwt() {
    let mut storage = MockStorageProxy::new();
    let mut credential = dummy_credential();
    credential
        .state
        .as_mut()
        .unwrap()
        .first_mut()
        .unwrap()
        .state = CredentialStateEnum::Accepted;

    let credential_copy = credential.to_owned();
    storage
        .expect_get_credentials_by_credential_schema_id()
        .return_once(|_| Ok(vec![credential_copy]));

    let (result_credentials, _result_group) = get_relevant_credentials_to_credential_schemas(
        &storage,
        vec![CredentialGroup {
            id: "input_0".to_string(),
            name: None,
            purpose: None,
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
    )
    .await
    .unwrap();

    assert_eq!(1, result_credentials.len());
    assert_eq!(credential.id, result_credentials[0].id);
}

#[tokio::test]
async fn test_get_relevant_credentials_to_credential_schemas_failed_wrong_state() {
    let mut storage = MockStorageProxy::new();
    let credential = dummy_credential();

    let credential_copy = credential.to_owned();
    storage
        .expect_get_credentials_by_credential_schema_id()
        .return_once(|_| Ok(vec![credential_copy]));

    let (result_credentials, _result_group) = get_relevant_credentials_to_credential_schemas(
        &storage,
        vec![CredentialGroup {
            id: "input_0".to_string(),
            name: None,
            purpose: None,
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
    )
    .await
    .unwrap();

    assert_eq!(0, result_credentials.len());
}

#[tokio::test]
async fn test_get_relevant_credentials_to_credential_schemas_failed_format_not_allowed() {
    let mut storage = MockStorageProxy::new();
    let mut credential = dummy_credential();
    credential
        .state
        .as_mut()
        .unwrap()
        .first_mut()
        .unwrap()
        .state = CredentialStateEnum::Accepted;

    let credential_copy = credential.to_owned();
    storage
        .expect_get_credentials_by_credential_schema_id()
        .return_once(|_| Ok(vec![credential_copy]));

    let (result_credentials, _result_group) = get_relevant_credentials_to_credential_schemas(
        &storage,
        vec![CredentialGroup {
            id: "input_0".to_string(),
            name: None,
            purpose: None,
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
            array: false,
        },
        ClaimSchema {
            id: Uuid::new_v4().into(),
            key: "namespace/name".to_string(),
            data_type: "STRING".to_string(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            array: false,
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
        path: new_claim_schemas[1].key.clone(),
        schema: Some(new_claim_schemas[1].to_owned()),
    }];

    credential
}

fn generic_mdoc_credential(format: &str, state: CredentialStateEnum) -> Credential {
    let key = dummy_key();

    Credential {
        state: Some(vec![CredentialState {
            created_date: OffsetDateTime::now_utc(),
            state,
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
        schema: Some(CredentialSchema {
            format: format.to_string(),
            ..dummy_credential().schema.unwrap()
        }),
        ..dummy_credential()
    }
}

#[tokio::test]
async fn test_get_relevant_credentials_to_credential_schemas_success_mdoc() {
    let mut storage = MockStorageProxy::new();
    let credential = mdoc_credential();

    let credential_copy = credential.to_owned();
    storage
        .expect_get_credentials_by_credential_schema_id()
        .return_once(|_| Ok(vec![credential_copy]));

    let (result_credentials, _result_group) = get_relevant_credentials_to_credential_schemas(
        &storage,
        vec![CredentialGroup {
            id: "input_0".to_string(),
            name: None,
            purpose: None,
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
    )
    .await
    .unwrap();

    assert_eq!(1, result_credentials.len());
}

#[tokio::test]
async fn test_get_relevant_credentials_to_credential_schemas_when_first_level_selected() {
    let mut storage = MockStorageProxy::new();
    let credential = mdoc_credential();

    let credential_copy = credential.to_owned();
    storage
        .expect_get_credentials_by_credential_schema_id()
        .return_once(|_| Ok(vec![credential_copy]));

    let (result_credentials, _result_group) = get_relevant_credentials_to_credential_schemas(
        &storage,
        vec![CredentialGroup {
            id: "input_0".to_string(),
            name: None,
            purpose: None,
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
    )
    .await
    .unwrap();

    assert_eq!(1, result_credentials.len());
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
            credential.schema = Some(crate::model::credential_schema::CredentialSchema {
                organisation: Some(dummy_organisation()),
                ..credential.schema.unwrap()
            });
            Ok(Some(credential))
        });

    credential_repository
        .expect_get_credentials_by_issuer_did_id()
        .return_once(move |_, _| Ok(vec![credential]));

    credential_repository
        .expect_update_credential()
        .once()
        .return_once(|_| Ok(()));

    let mut revocation_method_provider = MockRevocationMethodProvider::new();
    revocation_method_provider
        .expect_get_revocation_method()
        .once()
        .return_once(move |_| Some(Arc::new(NoneRevocation {})));

    let mut formatter = MockCredentialFormatter::new();
    formatter
        .expect_format_credentials()
        .once()
        .returning(|_, _, _, _, _, _, _, _| Ok("token".to_string()));

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_formatter()
        .with(eq(format))
        .once()
        .return_once(move |_| Some(Arc::new(formatter)));

    let mut key_provider = MockKeyProvider::new();
    key_provider
        .expect_get_signature_provider()
        .once()
        .returning(|_, _| Ok(Box::<MockSignatureProvider>::default()));

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .once()
        .returning(|_| Ok(Uuid::new_v4().into()));

    let mut did_method_provider = MockDidMethodProvider::new();
    did_method_provider
        .expect_resolve()
        .once()
        .returning(move |_| Ok(dummy_did_document()));

    let mut revocation_list_repository = MockRevocationListRepository::default();
    revocation_list_repository
        .expect_get_revocation_by_issuer_did_id()
        .with(always(), eq(RevocationListPurpose::Revocation), always())
        .return_once(move |_, _, _| {
            Ok(Some(RevocationList {
                id: Default::default(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                credentials: vec![],
                purpose: RevocationListPurpose::Revocation,
                issuer_did: None,
            }))
        });
    revocation_list_repository
        .expect_get_revocation_by_issuer_did_id()
        .with(always(), eq(RevocationListPurpose::Suspension), always())
        .return_once(move |_, _, _| {
            Ok(Some(RevocationList {
                id: Default::default(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                credentials: vec![],
                purpose: RevocationListPurpose::Suspension,
                issuer_did: None,
            }))
        });

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

    let service = ExchangeProtocolProviderCoreImpl::new(
        Arc::new(MockExchangeProtocolProviderExtra::default()),
        Arc::new(formatter_provider),
        Arc::new(credential_repository),
        Arc::new(revocation_method_provider),
        Arc::new(key_provider),
        Arc::new(history_repository),
        Arc::new(did_method_provider),
        Arc::new(revocation_list_repository),
        Arc::new(validity_credential_repository),
        Arc::new(dummy_config()),
        Some("base_url".to_string()),
    );

    service
        .issue_credential(&credential_id, dummy_did())
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
                organisation: Some(dummy_organisation()),
                ..credential.schema.unwrap()
            });
            Ok(Some(credential))
        });

    credential_repository
        .expect_get_credentials_by_issuer_did_id()
        .return_once(move |_, _| Ok(vec![credential]));

    let mut revocation_method_provider = MockRevocationMethodProvider::new();
    revocation_method_provider
        .expect_get_revocation_method()
        .once()
        .return_once(move |_| Some(Arc::new(NoneRevocation {})));

    let mut formatter = MockCredentialFormatter::new();
    formatter
        .expect_format_credentials()
        .once()
        .returning(|_, _, _, _, _, _, _, _| Ok("token".to_string()));

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_formatter()
        .with(eq(format))
        .once()
        .return_once(move |_| Some(Arc::new(formatter)));

    let mut key_provider = MockKeyProvider::new();
    key_provider
        .expect_get_signature_provider()
        .once()
        .returning(|_, _| Ok(Box::<MockSignatureProvider>::default()));

    let mut did_method_provider = MockDidMethodProvider::new();
    did_method_provider
        .expect_resolve()
        .once()
        .returning(move |_| Ok(dummy_did_document()));

    let mut revocation_list_repository = MockRevocationListRepository::default();
    revocation_list_repository
        .expect_get_revocation_by_issuer_did_id()
        .with(always(), eq(RevocationListPurpose::Revocation), always())
        .return_once(move |_, _, _| {
            Ok(Some(RevocationList {
                id: Default::default(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                credentials: vec![],
                purpose: RevocationListPurpose::Revocation,
                issuer_did: None,
            }))
        });
    revocation_list_repository
        .expect_get_revocation_by_issuer_did_id()
        .with(always(), eq(RevocationListPurpose::Suspension), always())
        .return_once(move |_, _, _| {
            Ok(Some(RevocationList {
                id: Default::default(),
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                credentials: vec![],
                purpose: RevocationListPurpose::Suspension,
                issuer_did: None,
            }))
        });

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
            r#type: "MDOC".to_string(),
            display: Value::String("display".to_string()),
            order: None,
            disabled: None,
            capabilities: None,
            params: Some(Params {
                public: Some(json!({
                    "msoExpectedUpdateIn": Duration::days(3).whole_seconds(),
                    "msoExpiresIn": 10,
                    "leeway": 5,
                })),
                private: None,
            }),
        },
    );

    let service = ExchangeProtocolProviderCoreImpl::new(
        Arc::new(MockExchangeProtocolProviderExtra::default()),
        Arc::new(formatter_provider),
        Arc::new(credential_repository),
        Arc::new(revocation_method_provider),
        Arc::new(key_provider),
        Arc::new(MockHistoryRepository::new()),
        Arc::new(did_method_provider),
        Arc::new(revocation_list_repository),
        Arc::new(validity_credential_repository),
        Arc::new(config),
        Some("base_url".to_string()),
    );

    service
        .issue_credential(&credential_id, dummy_did())
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

    credential_repository
        .expect_get_credentials_by_issuer_did_id()
        .return_once(move |_, _| Ok(vec![credential]));

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
            r#type: format.to_owned(),
            display: Value::String("display".to_string()),
            order: None,
            disabled: None,
            capabilities: None,
            params: Some(Params {
                public: Some(json!({
                    "msoExpectedUpdateIn": Duration::days(3).whole_seconds(),
                    "msoExpiresIn": 10,
                    "leeway": 5,
                })),
                private: None,
            }),
        },
    );

    let service = ExchangeProtocolProviderCoreImpl::new(
        Arc::new(MockExchangeProtocolProviderExtra::default()),
        Arc::new(MockCredentialFormatterProvider::new()),
        Arc::new(credential_repository),
        Arc::new(MockRevocationMethodProvider::new()),
        Arc::new(MockKeyProvider::new()),
        Arc::new(MockHistoryRepository::new()),
        Arc::new(MockDidMethodProvider::new()),
        Arc::new(MockRevocationListRepository::new()),
        Arc::new(validity_credential_repository),
        Arc::new(config),
        Some("base_url".to_string()),
    );

    assert2::assert!(
        let ServiceError::OpenID4VCIError(OpenID4VCIError::InvalidRequest) =
        service
        .issue_credential(&credential_id, dummy_did())
        .await
        .err()
        .unwrap()
    );
}

fn dummy_config() -> CoreConfig {
    let mut config = CoreConfig::default();

    config.datatype.insert(
        "STRING".to_string(),
        Fields {
            r#type: DatatypeType::String,
            display: Value::String("display".to_string()),
            order: None,
            disabled: None,
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
        issuance_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        deleted_at: None,
        credential: b"credential".to_vec(),
        exchange: "protocol".to_string(),
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
            path: "key".to_string(),
            schema: Some(ClaimSchema {
                id: claim_schema_id,
                key: "key".to_string(),
                data_type: "STRING".to_string(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                array: false,
            }),
        }]),
        issuer_did: None,
        holder_did: None,
        schema: Some(CredentialSchema {
            id: Uuid::new_v4().into(),
            imported_source_url: "CORE_URL".to_string(),
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
                    array: false,
                },
                required: true,
            }]),
            layout_type: LayoutType::Card,
            layout_properties: None,
            schema_type: CredentialSchemaType::ProcivisOneSchema2024,
            schema_id: "CredentialSchemaId".to_owned(),
            organisation: Some(Organisation {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
            }),
        }),
        interaction: Some(Interaction {
            id: Uuid::new_v4(),
            created_date: OffsetDateTime::now_utc(),
            host: Some("https://core.dev.one-trust-solution.com".parse().unwrap()),
            data: Some(b"interaction data".to_vec()),
            last_modified: OffsetDateTime::now_utc(),
        }),
        key: None,
        revocation_list: None,
    }
}

fn dummy_did() -> Did {
    Did {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        name: "John".to_string(),
        did: "did:test".parse().unwrap(),
        did_type: DidType::Local,
        did_method: "John".to_string(),
        keys: None,
        organisation: None,
        deactivated: false,
    }
}

fn dummy_did_document() -> DidDocument {
    DidDocument {
        context: json!({}),
        id: dummy_did().did,
        verification_method: vec![DidVerificationMethod {
            id: "did-vm-id".to_string(),
            r#type: "did-vm-type".to_string(),
            controller: "did-vm-controller".to_string(),
            public_key_jwk: PublicKeyJwk::Ec(PublicKeyJwkEllipticData {
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
        rest: Default::default(),
    }
}

fn dummy_key() -> Key {
    Key {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        public_key: b"public_key".to_vec(),
        name: "key name".to_string(),
        key_reference: b"private_key".to_vec(),
        storage_type: "SOFTWARE".to_string(),
        key_type: "EDDSA".to_string(),
        organisation: Some(Organisation {
            id: Uuid::new_v4().into(),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
        }),
    }
}
