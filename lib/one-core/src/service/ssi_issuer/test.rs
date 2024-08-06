use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use shared_types::{CredentialId, DidValue};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::config::ConfigValidationError;
use crate::model::credential::{Credential, CredentialState, CredentialStateEnum};
use crate::provider::exchange_protocol::provider::MockExchangeProtocolProviderExtra;
use crate::repository::credential_repository::MockCredentialRepository;
use crate::repository::credential_schema_repository::MockCredentialSchemaRepository;
use crate::repository::did_repository::MockDidRepository;
use crate::repository::history_repository::MockHistoryRepository;
use crate::service::error::ServiceError;
use crate::service::ssi_issuer::dto::{
    JsonLDContextDTO, JsonLDContextResponseDTO, JsonLDEntityDTO, JsonLDInlineEntityDTO,
};
use crate::service::ssi_issuer::SSIIssuerService;
use crate::service::test_utilities::{dummy_credential_with_exchange, dummy_did, generic_config};

#[tokio::test]
async fn test_issuer_connect_succeeds() {
    let credential_id: CredentialId = Uuid::new_v4().into();

    let mut credential_repository = MockCredentialRepository::new();
    credential_repository
        .expect_get_credential()
        .withf(move |_credential_id, _| {
            assert_eq!(_credential_id, &credential_id);
            true
        })
        .once()
        .return_once(move |_, _| {
            Ok(Some(Credential {
                issuer_did: Some(dummy_did()),
                ..dummy_credential_with_exchange("PROCIVIS_TEMPORARY")
            }))
        });

    credential_repository
        .expect_update_credential()
        .once()
        .return_once(|_| Ok(()));

    let service = SSIIssuerService {
        credential_repository: Arc::new(credential_repository),
        ..mock_ssi_issuer_service()
    };

    service
        .issuer_connect("PROCIVIS_TEMPORARY", &credential_id)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_issuer_connect_incorrect_protocol() {
    let credential_id: CredentialId = Uuid::new_v4().into();

    let mut credential_repository = MockCredentialRepository::new();
    credential_repository
        .expect_get_credential()
        .withf(move |_credential_id, _| {
            assert_eq!(_credential_id, &credential_id);
            true
        })
        .once()
        .return_once(move |_, _| {
            Ok(Some(Credential {
                ..dummy_credential_with_exchange("OPENID4VC")
            }))
        });

    let service = SSIIssuerService {
        credential_repository: Arc::new(credential_repository),
        ..mock_ssi_issuer_service()
    };

    assert!(service
        .issuer_connect("OPENID4VC", &credential_id)
        .await
        .is_err_and(|x| matches!(
            x,
            ServiceError::ConfigValidationError(ConfigValidationError::InvalidType(_, _))
        )));
}

#[tokio::test]
async fn test_issuer_reject_succeeds() {
    let credential_id: CredentialId = Uuid::new_v4().into();

    let mut credential_repository = MockCredentialRepository::new();
    credential_repository
        .expect_get_credential()
        .withf(move |_credential_id, _| {
            assert_eq!(_credential_id, &credential_id);
            true
        })
        .once()
        .return_once(move |_, _| {
            Ok(Some(Credential {
                state: Some(vec![CredentialState {
                    created_date: OffsetDateTime::now_utc(),
                    state: CredentialStateEnum::Offered,
                    suspend_end_date: None,
                }]),
                ..dummy_credential_with_exchange("PROCIVIS_TEMPORARY")
            }))
        });

    credential_repository
        .expect_update_credential()
        .once()
        .return_once(|_| Ok(()));

    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_create_history()
        .once()
        .returning(|_| Ok(Uuid::new_v4().into()));

    let service = SSIIssuerService {
        credential_repository: Arc::new(credential_repository),
        history_repository: Arc::new(history_repository),
        ..mock_ssi_issuer_service()
    };

    service.issuer_reject(&credential_id).await.unwrap();
}

#[tokio::test]
async fn test_issuer_submit_incorrect_protocol() {
    let credential_id: CredentialId = Uuid::new_v4().into();

    let mut credential_repository = MockCredentialRepository::new();
    credential_repository
        .expect_get_credential()
        .withf(move |_credential_id, _| {
            assert_eq!(_credential_id, &credential_id);
            true
        })
        .once()
        .return_once(move |_, _| Ok(Some(dummy_credential_with_exchange("OPENID4VC"))));

    let service = SSIIssuerService {
        credential_repository: Arc::new(credential_repository),
        ..mock_ssi_issuer_service()
    };

    assert!(service
        .issuer_submit(&credential_id, DidValue::from_str("did:key:123").unwrap())
        .await
        .is_err_and(|x| matches!(
            x,
            ServiceError::ConfigValidationError(ConfigValidationError::InvalidType(_, _))
        )));
}

#[tokio::test]
async fn test_issuer_reject_incorrect_protocol() {
    let credential_id: CredentialId = Uuid::new_v4().into();

    let mut credential_repository = MockCredentialRepository::new();
    credential_repository
        .expect_get_credential()
        .withf(move |_credential_id, _| {
            assert_eq!(_credential_id, &credential_id);
            true
        })
        .once()
        .return_once(move |_, _| {
            Ok(Some(Credential {
                state: Some(vec![CredentialState {
                    created_date: OffsetDateTime::now_utc(),
                    state: CredentialStateEnum::Offered,
                    suspend_end_date: None,
                }]),
                ..dummy_credential_with_exchange("OPENID4VC")
            }))
        });

    let service = SSIIssuerService {
        credential_repository: Arc::new(credential_repository),
        ..mock_ssi_issuer_service()
    };

    assert!(service
        .issuer_reject(&credential_id)
        .await
        .is_err_and(|x| matches!(
            x,
            ServiceError::ConfigValidationError(ConfigValidationError::InvalidType(_, _))
        )));
}

fn mock_ssi_issuer_service() -> SSIIssuerService {
    SSIIssuerService {
        credential_schema_repository: Arc::new(MockCredentialSchemaRepository::new()),
        credential_repository: Arc::new(MockCredentialRepository::new()),
        did_repository: Arc::new(MockDidRepository::new()),
        protocol_provider: Arc::new(MockExchangeProtocolProviderExtra::new()),
        config: Arc::new(generic_config().core),
        core_base_url: Some("http://127.0.0.1".to_string()),
        history_repository: Arc::new(MockHistoryRepository::new()),
    }
}

#[tokio::test]
async fn test_get_json_ld_context_lvvc_success() {
    let service = SSIIssuerService {
        ..mock_ssi_issuer_service()
    };

    let expected = JsonLDContextResponseDTO {
        context: JsonLDContextDTO {
            version: 1.1,
            protected: true,
            id: "@id".to_string(),
            r#type: "@type".to_string(),
            entities: HashMap::from([
                (
                    "LvvcCredential".to_string(),
                    JsonLDEntityDTO::Inline(JsonLDInlineEntityDTO {
                        id: "http://127.0.0.1/ssi/context/v1/lvvc.json#LvvcCredential".to_string(),
                        context: JsonLDContextDTO {
                            version: 1.1,
                            protected: true,
                            id: "@id".to_string(),
                            r#type: "@type".to_string(),
                            entities: Default::default(),
                        },
                    }),
                ),
                (
                    "LvvcSubject".to_string(),
                    JsonLDEntityDTO::Inline(JsonLDInlineEntityDTO {
                        id: "http://127.0.0.1/ssi/context/v1/lvvc.json#LvvcSubject".to_string(),
                        context: JsonLDContextDTO {
                            version: 1.1,
                            protected: true,
                            id: "@id".to_string(),
                            r#type: "@type".to_string(),
                            entities: HashMap::from([
                                (
                                    "status".to_string(),
                                    JsonLDEntityDTO::Reference(
                                        "http://127.0.0.1/ssi/context/v1/lvvc.json#status"
                                            .to_string(),
                                    ),
                                ),
                                (
                                    "suspendEndDate".to_string(),
                                    JsonLDEntityDTO::Reference(
                                        "http://127.0.0.1/ssi/context/v1/lvvc.json#suspendEndDate"
                                            .to_string(),
                                    ),
                                ),
                            ]),
                        },
                    }),
                ),
            ]),
        },
    };

    assert_eq!(
        expected,
        service.get_json_ld_context("lvvc.json").await.unwrap()
    );
}
