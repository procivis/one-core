use std::ops::Add;
use std::sync::Arc;

use assert2::let_assert;
use similar_asserts::assert_eq;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::creator::{
    IdentifierCreator, IdentifierCreatorProto, IdentifierRole, RemoteIdentifierRelation,
};
use crate::config::core_config::KeyAlgorithmType;
use crate::model::certificate::{Certificate, CertificateState, GetCertificateList};
use crate::model::identifier::{GetIdentifierList, Identifier};
use crate::model::key::{GetKeyList, PublicKeyJwk, PublicKeyJwkEllipticData};
use crate::proto::certificate_validator::{MockCertificateValidator, ParsedCertificate};
use crate::proto::transaction_manager::NoTransactionManager;
use crate::provider::credential_formatter::model::{CertificateDetails, IdentifierDetails};
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::key_algorithm::key::{
    KeyHandle, MockSignaturePublicKeyHandle, SignatureKeyHandle,
};
use crate::provider::key_algorithm::provider::{MockKeyAlgorithmProvider, ParsedKey};
use crate::repository::certificate_repository::MockCertificateRepository;
use crate::repository::did_repository::MockDidRepository;
use crate::repository::identifier_repository::MockIdentifierRepository;
use crate::repository::key_repository::MockKeyRepository;
use crate::service::certificate::dto::CertificateX509AttributesDTO;
use crate::service::test_utilities::{dummy_identifier, dummy_key, dummy_organisation};

#[derive(Default)]
struct Mocks {
    did_method_provider: MockDidMethodProvider,
    did_repository: MockDidRepository,
    certificate_repository: MockCertificateRepository,
    certificate_validator: MockCertificateValidator,
    key_repository: MockKeyRepository,
    key_algorithm_provider: MockKeyAlgorithmProvider,
    identifier_repository: MockIdentifierRepository,
}

fn setup_creator(mocks: Mocks) -> IdentifierCreatorProto {
    IdentifierCreatorProto::new(
        Arc::new(mocks.did_method_provider),
        Arc::new(mocks.did_repository),
        Arc::new(mocks.certificate_repository),
        Arc::new(mocks.certificate_validator),
        Arc::new(mocks.key_repository),
        Arc::new(mocks.key_algorithm_provider),
        Arc::new(mocks.identifier_repository),
        Arc::new(NoTransactionManager),
    )
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
            &IdentifierDetails::Key(PublicKeyJwk::Okp(PublicKeyJwkEllipticData {
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
