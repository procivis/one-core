use std::{collections::HashMap, sync::Arc};

use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::config::core_config::{CoreConfig, Fields, KeyAlgorithmType, Params};
use crate::provider::credential_formatter::MockSignatureProvider;
use crate::provider::transport_protocol::provider::{
    TransportProtocolProvider, TransportProtocolProviderImpl,
};
use crate::{
    model::{
        claim::Claim,
        claim_schema::ClaimSchema,
        credential::{Credential, CredentialId, CredentialState, CredentialStateEnum},
        credential_schema::{CredentialSchema, CredentialSchemaClaim},
        did::{Did, DidType, KeyRole, RelatedKey},
        interaction::Interaction,
        key::Key,
        organisation::Organisation,
    },
    provider::{
        credential_formatter::{
            model::CredentialStatus, provider::MockCredentialFormatterProvider,
            MockCredentialFormatter,
        },
        key_storage::provider::MockKeyProvider,
        revocation::{
            provider::MockRevocationMethodProvider, CredentialRevocationInfo, MockRevocationMethod,
        },
    },
    repository::mock::credential_repository::MockCredentialRepository,
};

#[tokio::test]
async fn test_issuer_submit_succeeds() {
    let credential_id: CredentialId = Uuid::new_v4();
    let key_storage_type = "storage type";
    let key_type = "EDDSA";
    let algorithm = "algorithm";

    let key_id = Uuid::new_v4();
    let mut credential_repository = MockCredentialRepository::new();
    credential_repository
        .expect_get_credential()
        .withf(move |_credential_id, _| {
            assert_eq!(_credential_id, &credential_id);
            true
        })
        .once()
        .return_once(move |_, _| {
            Ok(Credential {
                state: Some(vec![CredentialState {
                    created_date: OffsetDateTime::now_utc(),
                    state: CredentialStateEnum::Offered,
                }]),
                holder_did: Some(dummy_did()),
                issuer_did: Some(Did {
                    keys: Some(vec![RelatedKey {
                        role: KeyRole::AssertionMethod,
                        key: Key {
                            id: key_id,
                            created_date: OffsetDateTime::now_utc(),
                            last_modified: OffsetDateTime::now_utc(),
                            public_key: b"public_key".to_vec(),
                            name: "key name".to_string(),
                            key_reference: b"private_key".to_vec(),
                            storage_type: key_storage_type.to_string(),
                            key_type: key_type.to_string(),
                            organisation: Some(Organisation {
                                id: Uuid::new_v4(),
                                created_date: OffsetDateTime::now_utc(),
                                last_modified: OffsetDateTime::now_utc(),
                            }),
                        },
                    }]),
                    ..dummy_did()
                }),
                ..dummy_credential()
            })
        });

    credential_repository
        .expect_update_credential()
        .once()
        .withf(move |update_request| update_request.key == Some(key_id))
        .return_once(|_| Ok(()));

    let mut revocation_method = MockRevocationMethod::new();
    revocation_method
        .expect_add_issued_credential()
        .once()
        .return_once(|_| {
            Ok(Some(CredentialRevocationInfo {
                additional_vc_contexts: vec![],
                credential_status: CredentialStatus {
                    id: Uuid::new_v4().to_string(),
                    r#type: "type".to_string(),
                    status_purpose: "type".to_string(),
                    additional_fields: HashMap::new(),
                },
            }))
        });

    let mut revocation_method_provider = MockRevocationMethodProvider::new();
    revocation_method_provider
        .expect_get_revocation_method()
        .once()
        .return_once(move |_| Ok(Arc::new(revocation_method)));

    let mut formatter = MockCredentialFormatter::new();
    formatter
        .expect_format_credentials()
        .once()
        .returning(|_, _, _, _, _, _, _| Ok("token".to_string()));

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_formatter()
        .once()
        .return_once(move |_| Ok(Arc::new(formatter)));

    let mut key_provider = MockKeyProvider::new();
    key_provider
        .expect_get_signature_provider()
        .once()
        .returning(|_| Ok(Box::<MockSignatureProvider>::default()));

    let mut config = dummy_config();
    config.key_algorithm.insert(
        KeyAlgorithmType::Eddsa,
        Fields {
            r#type: "EDDSA".to_string(),
            display: "display".to_string(),
            order: None,
            disabled: None,
            params: Some(Params {
                public: Some(json!({
                    "algorithm": algorithm
                })),
                private: None,
            }),
        },
    );

    let service = TransportProtocolProviderImpl::new(
        Default::default(),
        Arc::new(formatter_provider),
        Arc::new(credential_repository),
        Arc::new(revocation_method_provider),
        Arc::new(key_provider),
        Arc::new(config),
    );

    service.issue_credential(&credential_id).await.unwrap();
}

fn dummy_config() -> CoreConfig {
    CoreConfig::default()
}

fn dummy_credential() -> Credential {
    let claim_schema_id = Uuid::new_v4();

    Credential {
        id: Uuid::new_v4(),
        created_date: OffsetDateTime::now_utc(),
        issuance_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        credential: b"credential".to_vec(),
        transport: "protocol".to_string(),
        redirect_uri: None,
        state: Some(vec![CredentialState {
            created_date: OffsetDateTime::now_utc(),
            state: CredentialStateEnum::Pending,
        }]),
        claims: Some(vec![Claim {
            id: Uuid::new_v4(),
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
                id: Uuid::new_v4(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
            }),
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
