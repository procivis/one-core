use std::ops::Add;
use std::sync::Arc;

use assert2::let_assert;
use mockall::Sequence;
use shared_types::IdentifierId;
use shared_types::i18n::I18nString;
use similar_asserts::assert_eq;
use standardized_types::jwk::{PublicJwk, PublicJwkEc};
use time::Duration;
use uuid::Uuid;

use super::creator::IdentifierCreatorProto;
use super::{
    CreateLocalIdentifierRequestParams, CreateLocalIdentifierRequestType, IdentifierCreator,
    IdentifierName, IdentifierRole, IdentifierTranslations, RemoteIdentifierRelation,
};
use crate::config::core_config::{CoreConfig, DidType, KeyAlgorithmType};
use crate::error::{ErrorCode, ErrorCodeMixin};
use crate::model::certificate::{Certificate, CertificateState, GetCertificateList};
use crate::model::identifier::{
    GetIdentifierList, Identifier, IdentifierData, UpdateIdentifierRequest,
};
use crate::model::key::{GetKeyList, Key};
use crate::model::localized_text::{LocalizedText, LocalizedTextEntityType, LocalizedTextField};
use crate::model::relation::RelatedVec;
use crate::proto::certificate_validator::{MockCertificateValidator, ParsedCertificate};
use crate::proto::csr_creator::MockCsrCreator;
use crate::proto::transaction_manager::NoTransactionManager;
use crate::provider::blob_storage::MockBlobStorage;
use crate::provider::blob_storage::provider::MockBlobStorageProvider;
use crate::provider::credential_formatter::model::{CertificateDetails, IdentifierDetails};
use crate::provider::did_method::error::DidMethodError;
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
    signer_provider: MockSignerProvider,
    blob_storage_provider: MockBlobStorageProvider,
    csr_creator: MockCsrCreator,
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
        Arc::new(mocks.signer_provider),
        Arc::new(mocks.blob_storage_provider),
        Arc::new(mocks.csr_creator),
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
            total_pages: Some(0),
            total_items: Some(0),
        })
    });
    certificate_repository
        .expect_create()
        .once()
        .returning(move |_| Ok(Uuid::new_v4().into()));

    let now = crate::clock::now_utc();

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

    let (identifier, relation) = creator
        .get_or_create_remote_identifier(
            &dummy_organisation(None),
            &IdentifierDetails::Certificate(CertificateDetails {
                chain: "chain".to_string(),
                fingerprint: "fingerprint".to_string(),
                expiry: now,
                subject_common_name: Some("subject_common_name".to_string()),
                x5_references: Default::default(),
            }),
            IdentifierName::PrefixForId(IdentifierRole::Issuer.to_string()),
            true,
            None,
            None,
        )
        .await
        .unwrap();

    // The returned identifier carries its certificates relation (consistent with did/key).
    let_assert!(IdentifierData::Certificate(certificates) = &identifier.data);
    let certificates = certificates.as_ref().await.unwrap();
    assert_eq!(certificates.len(), 1);
    assert_eq!(certificates[0].fingerprint, "fingerprint");
    let_assert!(RemoteIdentifierRelation::Certificate(_) = relation);
}

#[tokio::test]
async fn test_get_or_create_remote_identifier_certificate_existing() {
    let mut certificate_repository = MockCertificateRepository::new();

    let organisation = dummy_organisation(None);
    let certificate_id = Uuid::new_v4().into();
    let identifier_id = Uuid::new_v4().into();
    let now = crate::clock::now_utc();
    let certificate = Certificate {
        id: certificate_id,
        identifier_id,
        organisation: organisation.clone().into(),
        created_date: now,
        last_modified: now,
        deleted_at: None,
        expiry_date: now.add(Duration::minutes(10)),
        name: "test cert".to_string(),
        chain: "chain".to_string(),
        fingerprint: "fingerprint".to_string(),
        state: CertificateState::Active,
        roles: vec![],
        key: None,
    };
    certificate_repository.expect_list().once().return_once({
        let certificate = certificate.clone();
        move |_| {
            Ok(GetCertificateList {
                values: vec![certificate],
                total_pages: Some(1),
                total_items: Some(1),
            })
        }
    });

    let now = crate::clock::now_utc();

    let mut identifier_repository = MockIdentifierRepository::new();
    identifier_repository.expect_get().once().return_once({
        let certificate = certificate.clone();
        move |_| {
            Ok(Identifier {
                id: identifier_id,
                data: IdentifierData::Certificate(RelatedVec::from(vec![certificate])),
                ..dummy_identifier()
            })
        }
    });

    let creator = setup_creator(Mocks {
        certificate_repository,
        identifier_repository,
        ..Default::default()
    });

    let (identifier, relation) = creator
        .get_or_create_remote_identifier(
            &organisation,
            &IdentifierDetails::Certificate(CertificateDetails {
                chain: "chain".to_string(),
                fingerprint: "fingerprint".to_string(),
                expiry: now,
                subject_common_name: Some("subject_common_name".to_string()),
                x5_references: Default::default(),
            }),
            IdentifierName::PrefixForId(IdentifierRole::Issuer.to_string()),
            true,
            None,
            None,
        )
        .await
        .unwrap();

    assert_eq!(identifier.id, identifier_id);
    // The existing identifier is returned as loaded, carrying its certificates relation.
    let_assert!(IdentifierData::Certificate(certificates) = &identifier.data);
    let certificates = certificates.as_ref().await.unwrap();
    assert_eq!(certificates.len(), 1);
    assert_eq!(certificates[0].id, certificate_id);
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
    let key_clone = key.clone();
    let key_id = key.id;
    let mut key_repository = MockKeyRepository::new();
    key_repository.expect_get_key_list().once().return_once({
        move |_| {
            Ok(GetKeyList {
                values: vec![key_clone],
                total_pages: Some(1),
                total_items: Some(1),
            })
        }
    });

    let mut identifier = dummy_identifier();
    identifier.data = IdentifierData::Key(key.clone().into());
    let identifier_id = identifier.id;
    let mut identifier_repository = MockIdentifierRepository::new();
    identifier_repository
        .expect_get_identifier_list()
        .once()
        .return_once({
            move |_| {
                Ok(GetIdentifierList {
                    values: vec![identifier],
                    total_pages: Some(1),
                    total_items: Some(1),
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
            &dummy_organisation(None),
            &IdentifierDetails::Key(PublicJwk::Okp(PublicJwkEc {
                alg: None,
                r#use: None,
                kid: None,
                crv: "Ed25519".to_string(),
                x: "test".to_string(),
                y: None,
            })),
            IdentifierName::PrefixForId(IdentifierRole::Issuer.to_string()),
            true,
            None,
            None,
        )
        .await
        .unwrap();

    assert_eq!(identifier.id, identifier_id);
    let_assert!(IdentifierData::Key(identifier_key) = &identifier.data);
    assert_eq!(identifier_key.id(), key.id);
    let_assert!(RemoteIdentifierRelation::Key(key) = relation);
    assert_eq!(key.id, key_id);
}

fn expect_existing_key_identifier(
    key_algorithm_provider: &mut MockKeyAlgorithmProvider,
    key_repository: &mut MockKeyRepository,
    identifier_repository: &mut MockIdentifierRepository,
    identifier: Identifier,
) {
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
    key_repository
        .expect_get_key_list()
        .once()
        .return_once(|_| {
            Ok(GetKeyList {
                values: vec![dummy_key()],
                total_pages: Some(1),
                total_items: Some(1),
            })
        });
    identifier_repository
        .expect_get_identifier_list()
        .once()
        .return_once(move |_| {
            Ok(GetIdentifierList {
                values: vec![identifier],
                total_pages: Some(1),
                total_items: Some(1),
            })
        });
}

fn key_jwk() -> IdentifierDetails {
    IdentifierDetails::Key(PublicJwk::Okp(PublicJwkEc {
        alg: None,
        r#use: None,
        kid: None,
        crv: "Ed25519".to_string(),
        x: "test".to_string(),
        y: None,
    }))
}

fn name_text(id: IdentifierId, lang: &str, value: &str) -> LocalizedText {
    let now = crate::clock::now_utc();
    LocalizedText {
        entity_id: id.into(),
        field: LocalizedTextField::Name,
        created_date: now,
        last_modified: now,
        lang: lang.to_string(),
        value: value.to_string(),
        entity_type: LocalizedTextEntityType::Identifier,
    }
}

#[tokio::test]
async fn test_get_or_create_remote_identifier_does_not_update_when_translations_unchanged() {
    let mut identifier = dummy_identifier();
    identifier.data = IdentifierData::Key(dummy_key().into());
    // the identifier already has exactly the translation the issuer display would produce
    identifier.translations = vec![name_text(identifier.id, "en", "English issuer")].into();

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    let mut key_repository = MockKeyRepository::new();
    let mut identifier_repository = MockIdentifierRepository::new();
    // no `expect_update` / `expect_get`: the creator must not touch the identifier
    expect_existing_key_identifier(
        &mut key_algorithm_provider,
        &mut key_repository,
        &mut identifier_repository,
        identifier,
    );

    let creator = setup_creator(Mocks {
        key_algorithm_provider,
        key_repository,
        identifier_repository,
        config: generic_config().core,
        ..Default::default()
    });

    creator
        .get_or_create_remote_identifier(
            &dummy_organisation(None),
            &key_jwk(),
            IdentifierName::PrefixForId(IdentifierRole::Issuer.to_string()),
            true,
            Some(IdentifierTranslations {
                name: I18nString([("en".to_string(), "English issuer".to_string())].into()),
                logo_alt_text: None,
            }),
            None,
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn test_get_or_create_remote_identifier_updates_when_translations_differ() {
    let mut identifier = dummy_identifier();
    identifier.data = IdentifierData::Key(dummy_key().into());
    let identifier_id = identifier.id;
    identifier.translations = vec![name_text(identifier_id, "en", "identifier")].into();

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    let mut key_repository = MockKeyRepository::new();
    let mut identifier_repository = MockIdentifierRepository::new();
    expect_existing_key_identifier(
        &mut key_algorithm_provider,
        &mut key_repository,
        &mut identifier_repository,
        identifier,
    );
    identifier_repository
        .expect_update()
        .once()
        .withf(move |id, request: &UpdateIdentifierRequest| {
            *id == identifier_id
                && request.logo.is_none()
                && request.translations.as_ref().is_some_and(|texts| {
                    texts.iter().any(|t| {
                        t.field == LocalizedTextField::Name
                            && t.lang == "de"
                            && t.value == "Deutscher Aussteller"
                    })
                })
        })
        .return_once(|_, _| Ok(()));
    let reloaded = {
        let mut i = dummy_identifier();
        i.id = identifier_id;
        i.data = IdentifierData::Key(dummy_key().into());
        i
    };
    identifier_repository
        .expect_get()
        .once()
        .return_once(move |_| Ok(reloaded));

    let creator = setup_creator(Mocks {
        key_algorithm_provider,
        key_repository,
        identifier_repository,
        config: generic_config().core,
        ..Default::default()
    });

    creator
        .get_or_create_remote_identifier(
            &dummy_organisation(None),
            &key_jwk(),
            IdentifierName::PrefixForId(IdentifierRole::Issuer.to_string()),
            true,
            Some(IdentifierTranslations {
                name: I18nString(
                    [
                        ("en".to_string(), "identifier".to_string()),
                        ("de".to_string(), "Deutscher Aussteller".to_string()),
                    ]
                    .into(),
                ),
                logo_alt_text: None,
            }),
            None,
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn test_get_or_create_remote_identifier_sets_logo_when_identifier_has_none() {
    let mut identifier = dummy_identifier();
    identifier.data = IdentifierData::Key(dummy_key().into());
    let identifier_id = identifier.id;
    identifier.logo = None;
    // translations already match -> only the logo triggers the update
    identifier.translations = vec![name_text(identifier_id, "en", "English issuer")].into();

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    let mut key_repository = MockKeyRepository::new();
    let mut identifier_repository = MockIdentifierRepository::new();
    expect_existing_key_identifier(
        &mut key_algorithm_provider,
        &mut key_repository,
        &mut identifier_repository,
        identifier,
    );
    identifier_repository
        .expect_update()
        .once()
        .withf(move |id, request: &UpdateIdentifierRequest| {
            *id == identifier_id
                && request.translations.is_none()
                && matches!(request.logo, Some(Some(_)))
        })
        .return_once(|_, _| Ok(()));
    identifier_repository
        .expect_get()
        .once()
        .return_once(move |_| {
            let mut i = dummy_identifier();
            i.id = identifier_id;
            i.data = IdentifierData::Key(dummy_key().into());
            Ok(i)
        });

    let mut blob_storage = MockBlobStorage::default();
    blob_storage.expect_create().once().returning(|_| Ok(()));
    let blob_storage = Arc::new(blob_storage);
    let mut blob_storage_provider = MockBlobStorageProvider::default();
    blob_storage_provider
        .expect_get_blob_storage()
        .once()
        .returning(move |_| Ok(blob_storage.clone()));

    let creator = setup_creator(Mocks {
        key_algorithm_provider,
        key_repository,
        identifier_repository,
        blob_storage_provider,
        config: generic_config().core,
        ..Default::default()
    });

    creator
        .get_or_create_remote_identifier(
            &dummy_organisation(None),
            &key_jwk(),
            IdentifierName::PrefixForId(IdentifierRole::Issuer.to_string()),
            true,
            Some(IdentifierTranslations {
                name: I18nString([("en".to_string(), "English issuer".to_string())].into()),
                logo_alt_text: None,
            }),
            Some("data:image/png;base64,AAAA".to_string()),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn test_get_or_create_remote_identifier_does_not_refresh_existing_logo() {
    let mut identifier = dummy_identifier();
    identifier.data = IdentifierData::Key(dummy_key().into());
    let identifier_id = identifier.id;
    // the identifier already has a logo and matching translations -> nothing to write
    identifier.logo = Some(Uuid::new_v4().into());
    identifier.translations = vec![name_text(identifier_id, "en", "English issuer")].into();

    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    let mut key_repository = MockKeyRepository::new();
    let mut identifier_repository = MockIdentifierRepository::new();
    // no `expect_update` / `expect_get`: the existing logo must not be refreshed
    expect_existing_key_identifier(
        &mut key_algorithm_provider,
        &mut key_repository,
        &mut identifier_repository,
        identifier,
    );

    let creator = setup_creator(Mocks {
        key_algorithm_provider,
        key_repository,
        identifier_repository,
        config: generic_config().core,
        ..Default::default()
    });

    creator
        .get_or_create_remote_identifier(
            &dummy_organisation(None),
            &key_jwk(),
            IdentifierName::PrefixForId(IdentifierRole::Issuer.to_string()),
            true,
            Some(IdentifierTranslations {
                name: I18nString([("en".to_string(), "English issuer".to_string())].into()),
                logo_alt_text: None,
            }),
            Some("data:image/png;base64,BBBB".to_string()),
        )
        .await
        .unwrap();
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
                    total_pages: Some(0),
                    total_items: Some(0),
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
                    total_pages: Some(1),
                    total_items: Some(1),
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
                    total_pages: Some(1),
                    total_items: Some(1),
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
            &dummy_organisation(None),
            &IdentifierDetails::Key(PublicJwk::Okp(PublicJwkEc {
                alg: None,
                r#use: None,
                kid: None,
                crv: "Ed25519".to_string(),
                x: "test".to_string(),
                y: None,
            })),
            IdentifierName::PrefixForId(IdentifierRole::Issuer.to_string()),
            true,
            None,
            None,
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
        .expect_key_algorithm_from_key()
        .once()
        .return_once(|_| {
            let mut key_algorithm = MockKeyAlgorithm::new();
            key_algorithm
                .expect_algorithm_type()
                .once()
                .returning(|| KeyAlgorithmType::Eddsa);
            Ok(Arc::new(key_algorithm))
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
            move |_| Ok((Arc::new(did_method), DidType::Key))
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
            CreateLocalIdentifierRequestParams {
                name: "name".to_string(),
                organisation: organisation.clone(),
                now: crate::clock::now_utc(),
                autogenerated: false,
                logo: None,
                translations: None,
            },
            CreateLocalIdentifierRequestType::Did(CreateDidRequestDTO {
                name: "did-name".to_string(),
                organisation_id: organisation.id,
                did_method: "KEY".into(),
                keys: CreateDidRequestKeysDTO {
                    authentication: vec![key_id],
                    assertion_method: vec![key_id],
                    key_agreement: vec![key_id],
                    capability_invocation: vec![key_id],
                    capability_delegation: vec![key_id],
                },
                params: None,
            }),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn test_create_local_identifier_did_did_value_already_exists() {
    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_key()
        .once()
        .return_once(|_| {
            let mut key_algorithm = MockKeyAlgorithm::new();
            key_algorithm
                .expect_algorithm_type()
                .once()
                .returning(|| KeyAlgorithmType::Eddsa);
            Ok(Arc::new(key_algorithm))
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
            move |_| Ok((Arc::new(did_method), DidType::Key))
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
            CreateLocalIdentifierRequestParams {
                name: "name".to_string(),
                organisation: organisation.clone(),
                now: crate::clock::now_utc(),
                autogenerated: false,
                logo: None,
                translations: None,
            },
            CreateLocalIdentifierRequestType::Did(CreateDidRequestDTO {
                name: "did-name".to_string(),
                organisation_id: organisation.id,
                did_method: "KEY".into(),
                keys: CreateDidRequestKeysDTO {
                    authentication: vec![key_id],
                    assertion_method: vec![key_id],
                    key_agreement: vec![key_id],
                    capability_invocation: vec![key_id],
                    capability_delegation: vec![key_id],
                },
                params: None,
            }),
        )
        .await;

    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0028);
}

#[tokio::test]
async fn test_create_local_identifier_did_create_failure() {
    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_key_algorithm_from_key()
        .once()
        .return_once(|_| {
            let mut key_algorithm = MockKeyAlgorithm::new();
            key_algorithm
                .expect_algorithm_type()
                .once()
                .returning(|| KeyAlgorithmType::Eddsa);
            Ok(Arc::new(key_algorithm))
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
            did_method
                .expect_create()
                .once()
                .returning(|_, _, _| Err(DidMethodError::CreationError("test".to_string())));
            move |_| Ok((Arc::new(did_method), DidType::Key))
        });

    let creator = setup_creator(Mocks {
        key_algorithm_provider,
        did_method_provider,
        key_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let organisation = dummy_organisation(None);
    let result = creator
        .create_local_identifier(
            CreateLocalIdentifierRequestParams {
                name: "name".to_string(),
                organisation: organisation.clone(),
                now: crate::clock::now_utc(),
                autogenerated: false,
                logo: None,
                translations: None,
            },
            CreateLocalIdentifierRequestType::Did(CreateDidRequestDTO {
                name: "did-name".to_string(),
                organisation_id: organisation.id,
                did_method: "KEY".into(),
                keys: CreateDidRequestKeysDTO {
                    authentication: vec![key_id],
                    assertion_method: vec![key_id],
                    key_agreement: vec![key_id],
                    capability_invocation: vec![key_id],
                    capability_delegation: vec![key_id],
                },
                params: None,
            }),
        )
        .await;

    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0064);
}

#[tokio::test]
async fn test_create_local_identifier_key_threads_autogenerated_true() {
    let organisation = dummy_organisation(None);
    let key = Key {
        key_reference: Some(vec![]),
        organisation: organisation.clone().into(),
        ..dummy_key()
    };

    let mut identifier_repository = MockIdentifierRepository::new();
    identifier_repository
        .expect_create()
        .once()
        .returning(move |identifier| {
            assert!(identifier.autogenerated, "expected autogenerated = true");
            Ok(Uuid::new_v4().into())
        });

    let creator = setup_creator(Mocks {
        identifier_repository,
        ..Default::default()
    });

    creator
        .create_local_identifier(
            CreateLocalIdentifierRequestParams {
                name: "name".to_string(),
                organisation: organisation.clone(),
                now: crate::clock::now_utc(),
                autogenerated: true,
                logo: None,
                translations: None,
            },
            CreateLocalIdentifierRequestType::Key(key),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn test_create_local_identifier_key_threads_autogenerated_false() {
    let organisation = dummy_organisation(None);
    let key = Key {
        key_reference: Some(vec![]),
        organisation: organisation.clone().into(),
        ..dummy_key()
    };

    let mut identifier_repository = MockIdentifierRepository::new();
    identifier_repository
        .expect_create()
        .once()
        .returning(move |identifier| {
            assert!(!identifier.autogenerated, "expected autogenerated = false");
            Ok(Uuid::new_v4().into())
        });

    let creator = setup_creator(Mocks {
        identifier_repository,
        ..Default::default()
    });

    creator
        .create_local_identifier(
            CreateLocalIdentifierRequestParams {
                name: "name".to_string(),
                organisation: organisation.clone(),
                now: crate::clock::now_utc(),
                autogenerated: false,
                logo: None,
                translations: None,
            },
            CreateLocalIdentifierRequestType::Key(key),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn test_get_or_create_remote_identifier_key_new_is_autogenerated() {
    let mut key_algorithm_provider = MockKeyAlgorithmProvider::new();
    key_algorithm_provider
        .expect_parse_jwk()
        .once()
        .return_once(|_| {
            let mut public_key = MockSignaturePublicKeyHandle::new();
            public_key
                .expect_as_raw()
                .times(2)
                .returning(|| vec![0x0, 0x1]);

            Ok(ParsedKey {
                algorithm_type: KeyAlgorithmType::Eddsa,
                key: KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(Arc::new(
                    public_key,
                ))),
            })
        });

    let mut key_repository = MockKeyRepository::new();
    key_repository.expect_get_key_list().once().returning(|_| {
        Ok(GetKeyList {
            values: vec![],
            total_pages: Some(0),
            total_items: Some(0),
        })
    });
    key_repository
        .expect_create_key()
        .once()
        .returning(|key| Ok(key.id));

    let mut identifier_repository = MockIdentifierRepository::new();
    identifier_repository
        .expect_create()
        .once()
        .returning(move |_| Ok(Uuid::new_v4().into()));

    let creator = setup_creator(Mocks {
        key_algorithm_provider,
        identifier_repository,
        key_repository,
        ..Default::default()
    });

    let (identifier, _relation) = creator
        .get_or_create_remote_identifier(
            &dummy_organisation(None),
            &IdentifierDetails::Key(PublicJwk::Okp(PublicJwkEc {
                alg: None,
                r#use: None,
                kid: None,
                crv: "Ed25519".to_string(),
                x: "test".to_string(),
                y: None,
            })),
            IdentifierName::PrefixForId(IdentifierRole::Verifier.to_string()),
            true,
            None,
            None,
        )
        .await
        .unwrap();

    assert!(
        identifier.autogenerated,
        "remote verifier identifiers should be marked autogenerated"
    );
}
