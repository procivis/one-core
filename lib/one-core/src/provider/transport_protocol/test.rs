use std::{collections::HashMap, sync::Arc};

use serde_json::{json, Value};
use shared_types::CredentialId;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    config::core_config::{CoreConfig, Fields, KeyAlgorithmType, Params},
    model::{
        claim::Claim,
        claim_schema::ClaimSchema,
        credential::{Credential, CredentialRole, CredentialState, CredentialStateEnum},
        credential_schema::{
            CredentialSchema, CredentialSchemaClaim, LayoutType, WalletStorageTypeEnum,
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
        .returning(|_| Ok(Box::<MockSignatureProvider>::default()));

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

    let service = TransportProtocolProviderImpl::new(
        Default::default(),
        Arc::new(formatter_provider),
        Arc::new(credential_repository),
        Arc::new(revocation_method_provider),
        Arc::new(key_provider),
        Arc::new(history_repository),
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
                data_type: "data type".to_string(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
            }),
        }]),
        issuer_did: None,
        holder_did: None,
        schema: Some(CredentialSchema {
            id: Uuid::new_v4(),
            deleted_at: None,
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            wallet_storage_type: Some(WalletStorageTypeEnum::Software),
            name: "schema".to_string(),
            format: "format".to_string(),
            revocation_method: "revocation method".to_string(),
            claim_schemas: Some(vec![CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: claim_schema_id,
                    key: "key".to_string(),
                    data_type: "data type".to_string(),
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
