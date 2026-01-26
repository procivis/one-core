use std::ops::Add;
use std::sync::Arc;

use assert2::let_assert;
use mockall::Sequence;
use similar_asserts::assert_eq;
use standardized_types::jwk::{PublicJwk, PublicJwkEc};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::creator::IdentifierCreatorProto;
use super::{
    CreateLocalIdentifierRequest, IdentifierCreator, IdentifierRole, RemoteIdentifierRelation,
};
use crate::config::core_config::{CoreConfig, KeyAlgorithmType};
use crate::model::certificate::{Certificate, CertificateState, GetCertificateList};
use crate::model::identifier::{GetIdentifierList, Identifier};
use crate::model::key::{GetKeyList, Key};
use crate::proto::certificate_validator::{MockCertificateValidator, ParsedCertificate};
use crate::proto::csr_creator::MockCsrCreator;
use crate::proto::transaction_manager::NoTransactionManager;
use crate::provider::credential_formatter::model::{CertificateDetails, IdentifierDetails};
use crate::provider::did_method::model::{DidCapabilities, Operation};
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::did_method::{DidCreated, MockDidMethod};
use crate::provider::key_algorithm::MockKeyAlgorithm;
use crate::provider::key_algorithm::key::{
    KeyHandle, MockSignaturePublicKeyHandle, SignatureKeyHandle,
};
use crate::provider::key_algorithm::provider::{MockKeyAlgorithmProvider, ParsedKey};
use crate::provider::key_storage::provider::MockKeyProvider;
use crate::provider::signer::provider::MockSignerProvider;
use crate::repository::certificate_repository::MockCertificateRepository;
use crate::repository::did_repository::MockDidRepository;
use crate::repository::error::DataLayerError;
use crate::repository::identifier_repository::MockIdentifierRepository;
use crate::repository::key_repository::MockKeyRepository;
use crate::service::certificate::dto::CertificateX509AttributesDTO;
use crate::service::did::dto::{CreateDidRequestDTO, CreateDidRequestKeysDTO};
use crate::service::error::{BusinessLogicError, ServiceError, ValidationError};
use crate::service::test_utilities::{
    dummy_identifier, dummy_key, dummy_organisation, generic_config,
};

#[derive(Default)]
struct Mocks {
    did_method_provider: MockDidMethodProvider,
    did_repository: MockDidRepository,
    certificate_repository: MockCertificateRepository,
    certificate_validator: MockCertificateValidator,
    key_repository: MockKeyRepository,
    key_provider: MockKeyProvider,
    key_algorithm_provider: MockKeyAlgorithmProvider,
    identifier_repository: MockIdentifierRepository,
    csr_creator: MockCsrCreator,
    signer_provider: MockSignerProvider,
    config: CoreConfig,
}

fn setup_creator(mocks: Mocks) -> Box<dyn IdentifierCreator> {
    Box::new(IdentifierCreatorProto::new(
        Arc::new(mocks.did_method_provider),
        Arc::new(mocks.did_repository),
        Arc::new(mocks.certificate_repository),
        Arc::new(mocks.certificate_validator),
        Arc::new(mocks.key_repository),
        Arc::new(mocks.key_provider),
        Arc::new(mocks.key_algorithm_provider),
        Arc::new(mocks.identifier_repository),
        Arc::new(mocks.csr_creator),
        Arc::new(mocks.signer_provider),
        Arc::new(mocks.config),
        Arc::new(NoTransactionManager),
    ))
}

#[tokio::test]
async fn test_get_or_create_remote_identifier_certificate_new() {
    let mut certificate_repository = MockCertificateRepository::new();
    certificate_repository.expect_list().once().returning(|_| {
        Ok(GetCertificateList {
            values: vec![],
            total_pages: 0,
            total_items: 0,
        })
    });
    certificate_repository
        .expect_create()
        .once()
        .returning(move |_| Ok(Uuid::new_v4().into()));

    let now = OffsetDateTime::now_utc();

    let mut certificate_validator = MockCertificateValidator::new();
    certificate_validator
        .expect_parse_pem_chain()
        .once()
        .returning(move |_, _| {
            Ok(ParsedCertificate {
                attributes: CertificateX509AttributesDTO {
                    serial_number: "test".to_string(),
                    not_before: now,
                    not_after: now,
                    issuer: "Test Issuer".to_string(),
                    subject: "Test Subject".to_string(),
                    fingerprint: "fingerprint".to_string(),
                    extensions: vec![],
                },
                subject_common_name: Some("Test".to_string()),
                subject_key_identifier: None,
                public_key: KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(Arc::new(
                    MockSignaturePublicKeyHandle::default(),
                ))),
            })
        });

    let mut identifier_repository = MockIdentifierRepository::new();
    identifier_repository
        .expect_create()
        .once()
        .returning(move |_| Ok(Uuid::new_v4().into()));

    let creator = setup_creator(Mocks {
        certificate_repository,
        certificate_validator,
        identifier_repository,
        ..Default::default()
    });

    let (_identifier, relation) = creator
        .get_or_create_remote_identifier(
            &Some(dummy_organisation(None)),
            &IdentifierDetails::Certificate(CertificateDetails {
                chain: "chain".to_string(),
                fingerprint: "fingerprint".to_string(),
                expiry: now,
                subject_common_name: Some("subject_common_name".to_string()),
            }),
            IdentifierRole::Issuer,
        )
        .await
        .unwrap();

    let_assert!(RemoteIdentifierRelation::Certificate(_) = relation);
}

#[tokio::test]
async fn test_get_or_create_remote_identifier_certificate_existing() {
    let mut certificate_repository = MockCertificateRepository::new();

    let organisation = dummy_organisation(None);
    let certificate_id = Uuid::new_v4().into();
    let identifier_id = Uuid::new_v4().into();
    let now = OffsetDateTime::now_utc();
    let certificate = Certificate {
        id: certificate_id,
        identifier_id,
        organisation_id: Some(organisation.id),
        created_date: now,
        last_modified: now,
        expiry_date: now.add(Duration::minutes(10)),
        name: "test cert".to_string(),
        chain: "chain".to_string(),
        fingerprint: "fingerprint".to_string(),
        state: CertificateState::Active,
        key: None,
    };
    certificate_repository.expect_list().once().return_once({
        let certificate = certificate.clone();
        move |_| {
            Ok(GetCertificateList {
                values: vec![certificate],
                total_pages: 1,
                total_items: 1,
            })
        }
    });

    let now = OffsetDateTime::now_utc();

    let mut identifier_repository = MockIdentifierRepository::new();
    identifier_repository
        .expect_get()
        .once()
        .return_once(move |_, _| {
            Ok(Some(Identifier {
                id: identifier_id,
                ..dummy_identifier()
            }))
        });

    let creator = setup_creator(Mocks {
        certificate_repository,
        identifier_repository,
        ..Default::default()
    });

    let (identifier, relation) = creator
        .get_or_create_remote_identifier(
            &Some(organisation),
            &IdentifierDetails::Certificate(CertificateDetails {
                chain: "chain".to_string(),
                fingerprint: "fingerprint".to_string(),
                expiry: now,
                subject_common_name: Some("subject_common_name".to_string()),
            }),
            IdentifierRole::Issuer,
        )
        .await
        .unwrap();

    assert_eq!(identifier.id, identifier_id);
    let_assert!(RemoteIdentifierRelation::Certificate(certificate) = relation);
    assert_eq!(certificate.id, certificate_id);
}

#[tokio::test]
async fn test_get_or_create_remote_identifier_key_existing() {
    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_parse_jwk()
        .once()
        .return_once(|_| {
            let mut public_key = MockSignaturePublicKeyHandle::new();
            public_key
                .expect_as_raw()
                .once()
                .return_once(|| vec![0x0, 0x1]);

            Ok(ParsedKey {
                algorithm_type: KeyAlgorithmType::Eddsa,
                key: KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(Arc::new(
                    public_key,
                ))),
            })
        });

    let key = dummy_key();
    let key_id = key.id;
    let mut key_repository = MockKeyRepository::new();
    key_repository.expect_get_key_list().once().return_once({
        move |_| {
            Ok(GetKeyList {
                values: vec![key],
                total_pages: 1,
                total_items: 1,
            })
        }
    });

    let identifier = dummy_identifier();
    let identifier_id = identifier.id;
    let mut identifier_repository = MockIdentifierRepository::new();
    identifier_repository
        .expect_get_identifier_list()
        .once()
        .return_once({
            move |_| {
                Ok(GetIdentifierList {
                    values: vec![identifier],
                    total_pages: 1,
                    total_items: 1,
                })
            }
        });

    let creator = setup_creator(Mocks {
        key_algorithm_provider,
        identifier_repository,
        key_repository,
        ..Default::default()
    });

    let (identifier, relation) = creator
        .get_or_create_remote_identifier(
            &Some(dummy_organisation(None)),
            &IdentifierDetails::Key(PublicJwk::Okp(PublicJwkEc {
                alg: None,
                r#use: None,
                kid: None,
                crv: "Ed25519".to_string(),
                x: "test".to_string(),
                y: None,
            })),
            IdentifierRole::Issuer,
        )
        .await
        .unwrap();

    assert_eq!(identifier.id, identifier_id);
    let_assert!(RemoteIdentifierRelation::Key(key) = relation);
    assert_eq!(key.id, key_id);
}

#[tokio::test]
async fn test_get_or_create_remote_identifier_key_created_in_parallel() {
    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider.expect_parse_jwk().returning(|_| {
        let mut public_key = MockSignaturePublicKeyHandle::new();
        public_key.expect_as_raw().returning(|| vec![0x0, 0x1]);

        Ok(ParsedKey {
            algorithm_type: KeyAlgorithmType::Eddsa,
            key: KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(Arc::new(public_key))),
        })
    });

    let mut key_repository = MockKeyRepository::new();
    let mut seq = Sequence::new();
    key_repository
        .expect_get_key_list()
        .in_sequence(&mut seq)
        .once()
        .return_once({
            move |_| {
                Ok(GetKeyList {
                    values: vec![],
                    total_pages: 0,
                    total_items: 0,
                })
            }
        });
    let key = dummy_key();
    let key_id = key.id;
    key_repository
        .expect_get_key_list()
        .in_sequence(&mut seq)
        .once()
        .return_once({
            move |_| {
                Ok(GetKeyList {
                    values: vec![key],
                    total_pages: 1,
                    total_items: 1,
                })
            }
        });
    key_repository
        .expect_create_key()
        .once()
        .return_once(|_| Err(DataLayerError::AlreadyExists));

    let identifier = dummy_identifier();
    let identifier_id = identifier.id;
    let mut identifier_repository = MockIdentifierRepository::new();
    identifier_repository
        .expect_get_identifier_list()
        .once()
        .return_once({
            move |_| {
                Ok(GetIdentifierList {
                    values: vec![identifier],
                    total_pages: 1,
                    total_items: 1,
                })
            }
        });

    let creator = setup_creator(Mocks {
        key_algorithm_provider,
        identifier_repository,
        key_repository,
        ..Default::default()
    });

    let (identifier, relation) = creator
        .get_or_create_remote_identifier(
            &Some(dummy_organisation(None)),
            &IdentifierDetails::Key(PublicJwk::Okp(PublicJwkEc {
                alg: None,
                r#use: None,
                kid: None,
                crv: "Ed25519".to_string(),
                x: "test".to_string(),
                y: None,
            })),
            IdentifierRole::Issuer,
        )
        .await
        .unwrap();

    assert_eq!(identifier.id, identifier_id);
    let_assert!(RemoteIdentifierRelation::Key(key) = relation);
    assert_eq!(key.id, key_id);
}

#[tokio::test]
async fn test_create_local_identifier_did() {
    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .once()
        .return_once(|_| {
            let mut key_algorithm = MockKeyAlgorithm::new();
            key_algorithm
                .expect_algorithm_type()
                .once()
                .returning(|| KeyAlgorithmType::Eddsa);
            Some(Arc::new(key_algorithm))
        });

    let key = Key {
        key_reference: Some(vec![]),
        ..dummy_key()
    };
    let key_id = key.id;
    let mut key_repository = MockKeyRepository::new();
    key_repository
        .expect_get_keys()
        .once()
        .return_once(move |_| Ok(vec![key]));

    let mut identifier_repository = MockIdentifierRepository::new();
    identifier_repository
        .expect_create()
        .once()
        .return_once(move |_| Ok(Uuid::new_v4().into()));

    let mut did_method_provider = MockDidMethodProvider::new();
    did_method_provider
        .expect_get_did_method()
        .once()
        .return_once({
            let mut did_method = MockDidMethod::new();
            did_method.expect_validate_keys().once().returning(|_| true);
            did_method
                .expect_get_capabilities()
                .once()
                .returning(|| DidCapabilities {
                    operations: vec![Operation::CREATE],
                    key_algorithms: vec![KeyAlgorithmType::Eddsa],
                    method_names: vec![],
                    features: vec![],
                    supported_update_key_types: vec![],
                });
            did_method.expect_create().once().returning(|_, _, _| {
                Ok(DidCreated {
                    did: "did:example:123".parse().unwrap(),
                    log: None,
                })
            });
            did_method
                .expect_get_reference_for_key()
                .once()
                .returning(|_| Ok("ref".to_string()));
            move |_| Some(Arc::new(did_method))
        });

    let mut did_repository = MockDidRepository::new();
    did_repository
        .expect_create_did()
        .once()
        .returning(|_| Ok(Uuid::new_v4().into()));

    let creator = setup_creator(Mocks {
        key_algorithm_provider,
        identifier_repository,
        key_repository,
        did_method_provider,
        did_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let organisation = dummy_organisation(None);
    creator
        .create_local_identifier(
            "name".to_string(),
            CreateLocalIdentifierRequest::Did(CreateDidRequestDTO {
                name: "did-name".to_string(),
                organisation_id: organisation.id,
                did_method: "KEY".to_string(),
                keys: CreateDidRequestKeysDTO {
                    authentication: vec![key_id],
                    assertion_method: vec![key_id],
                    key_agreement: vec![key_id],
                    capability_invocation: vec![key_id],
                    capability_delegation: vec![key_id],
                },
                params: None,
            }),
            organisation,
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn test_create_local_identifier_did_did_value_already_exists() {
    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_type()
        .once()
        .return_once(|_| {
            let mut key_algorithm = MockKeyAlgorithm::new();
            key_algorithm
                .expect_algorithm_type()
                .once()
                .returning(|| KeyAlgorithmType::Eddsa);
            Some(Arc::new(key_algorithm))
        });

    let key = Key {
        key_reference: Some(vec![]),
        ..dummy_key()
    };
    let key_id = key.id;
    let mut key_repository = MockKeyRepository::new();
    key_repository
        .expect_get_keys()
        .once()
        .return_once(move |_| Ok(vec![key]));

    let mut did_method_provider = MockDidMethodProvider::new();
    did_method_provider
        .expect_get_did_method()
        .once()
        .return_once({
            let mut did_method = MockDidMethod::new();
            did_method.expect_validate_keys().once().returning(|_| true);
            did_method
                .expect_get_capabilities()
                .once()
                .returning(|| DidCapabilities {
                    operations: vec![Operation::CREATE],
                    key_algorithms: vec![KeyAlgorithmType::Eddsa],
                    method_names: vec![],
                    features: vec![],
                    supported_update_key_types: vec![],
                });
            did_method.expect_create().once().returning(|_, _, _| {
                Ok(DidCreated {
                    did: "did:example:123".parse().unwrap(),
                    log: None,
                })
            });
            did_method
                .expect_get_reference_for_key()
                .once()
                .returning(|_| Ok("ref".to_string()));
            move |_| Some(Arc::new(did_method))
        });

    let mut did_repository = MockDidRepository::new();
    did_repository
        .expect_create_did()
        .once()
        .returning(|_| Err(DataLayerError::AlreadyExists));

    let creator = setup_creator(Mocks {
        key_algorithm_provider,
        key_repository,
        did_method_provider,
        did_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let organisation = dummy_organisation(None);
    let result = creator
        .create_local_identifier(
            "name".to_string(),
            CreateLocalIdentifierRequest::Did(CreateDidRequestDTO {
                name: "did-name".to_string(),
                organisation_id: organisation.id,
                did_method: "KEY".to_string(),
                keys: CreateDidRequestKeysDTO {
                    authentication: vec![key_id],
                    assertion_method: vec![key_id],
                    key_agreement: vec![key_id],
                    capability_invocation: vec![key_id],
                    capability_delegation: vec![key_id],
                },
                params: None,
            }),
            organisation,
        )
        .await;

    assert!(matches!(
        result,
        Err(ServiceError::BusinessLogic(
            BusinessLogicError::DidValueAlreadyExists(_)
        ))
    ));
}

#[tokio::test]
async fn test_create_local_identifier_did_invalid_num_keys() {
    let key = Key {
        key_reference: Some(vec![]),
        ..dummy_key()
    };
    let key_id = key.id;

    let mut did_method_provider = MockDidMethodProvider::new();
    did_method_provider
        .expect_get_did_method()
        .once()
        .return_once({
            let mut did_method = MockDidMethod::new();
            did_method
                .expect_validate_keys()
                .once()
                .returning(|_| false);
            move |_| Some(Arc::new(did_method))
        });

    let creator = setup_creator(Mocks {
        did_method_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let organisation = dummy_organisation(None);
    let result = creator
        .create_local_identifier(
            "name".to_string(),
            CreateLocalIdentifierRequest::Did(CreateDidRequestDTO {
                name: "did-name".to_string(),
                organisation_id: organisation.id,
                did_method: "KEY".to_string(),
                keys: CreateDidRequestKeysDTO {
                    authentication: vec![key_id],
                    assertion_method: vec![key_id],
                    key_agreement: vec![key_id],
                    capability_invocation: vec![key_id],
                    capability_delegation: vec![key_id],
                },
                params: None,
            }),
            organisation,
        )
        .await;

    assert!(matches!(
        result,
        Err(ServiceError::Validation(
            ValidationError::DidInvalidKeyNumber
        ))
    ));
}
