use std::str::FromStr;
use std::sync::Arc;

use mockall::predicate::{always, eq};
use shared_types::{DidId, DidValue, TrustAnchorId, TrustEntityId, TrustEntityKey};
use similar_asserts::assert_eq;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::config::core_config::KeyAlgorithmType;
use crate::model::did::{Did, DidType};
use crate::model::identifier::IdentifierType;
use crate::model::organisation::Organisation;
use crate::model::trust_anchor::TrustAnchor;
use crate::model::trust_entity::{TrustEntity, TrustEntityRole, TrustEntityState, TrustEntityType};
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::http_client::MockHttpClient;
use crate::provider::key_algorithm::MockKeyAlgorithm;
use crate::provider::key_algorithm::key::{
    KeyHandle, MockSignaturePublicKeyHandle, SignatureKeyHandle,
};
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::key_storage::provider::MockKeyProvider;
use crate::provider::trust_management::provider::MockTrustManagementProvider;
use crate::provider::trust_management::{MockTrustManagement, TrustCapabilities, TrustOperation};
use crate::repository::did_repository::MockDidRepository;
use crate::repository::error::DataLayerError;
use crate::repository::identifier_repository::MockIdentifierRepository;
use crate::repository::organisation_repository::MockOrganisationRepository;
use crate::repository::trust_anchor_repository::MockTrustAnchorRepository;
use crate::repository::trust_entity_repository::MockTrustEntityRepository;
use crate::service::certificate::validator::MockCertificateValidator;
use crate::service::error::{BusinessLogicError, ServiceError};
use crate::service::test_utilities::{dummy_did, dummy_did_document, get_dummy_date};
use crate::service::trust_entity::TrustEntityService;
use crate::service::trust_entity::dto::{
    CreateTrustEntityFromDidPublisherRequestDTO, CreateTrustEntityRequestDTO,
};

#[derive(Default)]
struct TestData {
    pub trust_anchor_repository: MockTrustAnchorRepository,
    pub trust_entity_repository: MockTrustEntityRepository,
    pub did_repository: MockDidRepository,
    pub identifier_repository: MockIdentifierRepository,
    pub organisation_repository: MockOrganisationRepository,
    pub did_method_provider: MockDidMethodProvider,
    pub key_algorithm_provider: MockKeyAlgorithmProvider,
    pub trust_provider: MockTrustManagementProvider,
    pub key_provider: MockKeyProvider,
    pub client: MockHttpClient,
    pub certificate_validator: MockCertificateValidator,
}

fn setup_service(test_data: TestData) -> TrustEntityService {
    TrustEntityService::new(
        Arc::new(test_data.trust_anchor_repository),
        Arc::new(test_data.trust_entity_repository),
        Arc::new(test_data.did_repository),
        Arc::new(test_data.identifier_repository),
        Arc::new(test_data.organisation_repository),
        Arc::new(test_data.did_method_provider),
        Arc::new(test_data.key_algorithm_provider),
        Arc::new(test_data.trust_provider),
        Arc::new(test_data.key_provider),
        Arc::new(test_data.client),
        Arc::new(test_data.certificate_validator),
    )
}

fn generic_trust_anchor(id: TrustAnchorId) -> TrustAnchor {
    TrustAnchor {
        id,
        name: "test".to_string(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        r#type: "SIMPLE_TRUST_LIST".to_string(),
        publisher_reference: "".to_string(),
        is_publisher: true,
    }
}

fn generic_did(id: DidId) -> Did {
    Did {
        id,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        name: "did".to_string(),
        did: DidValue::from_str("did:key:123").unwrap(),
        did_type: DidType::Local,
        did_method: "KEY".to_string(),
        deactivated: false,
        keys: None,
        organisation: None,
        log: None,
    }
}

fn generic_trust_entity(id: TrustEntityId) -> TrustEntity {
    TrustEntity {
        id,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        deactivated_at: None,
        name: "generic trust entity".to_string(),
        logo: None,
        website: None,
        terms_url: None,
        privacy_url: None,
        role: TrustEntityRole::Issuer,
        state: TrustEntityState::Active,
        r#type: TrustEntityType::Did,
        entity_key: (&dummy_did().did).into(),
        content: None,
        trust_anchor: None,
        organisation: None,
    }
}

#[tokio::test]
async fn test_create_trust_entity_success() {
    let did_id = Uuid::new_v4().into();
    let trust_anchor_id = Uuid::new_v4().into();

    let mut trust_anchor_repository = MockTrustAnchorRepository::default();
    trust_anchor_repository
        .expect_get()
        .with(eq(trust_anchor_id))
        .returning(move |id| Ok(Some(generic_trust_anchor(id))));

    let mut did_repository = MockDidRepository::default();
    did_repository
        .expect_get_did()
        .with(eq(did_id), always())
        .returning(move |id, _| Ok(Some(generic_did(*id))));

    let mut trust_entity_repository = MockTrustEntityRepository::default();
    trust_entity_repository
        .expect_create()
        .returning(move |request| Ok(request.id));

    let organisation_id = Uuid::new_v4().into();
    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation()
        .returning(move |_, _| {
            Ok(Some(Organisation {
                id: organisation_id,
                name: "test".to_string(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                deactivated_at: None,
            }))
        });

    let service = setup_service(TestData {
        did_repository,
        trust_anchor_repository,
        trust_entity_repository,
        organisation_repository,
        ..Default::default()
    });

    service
        .create_trust_entity(CreateTrustEntityRequestDTO {
            name: "".to_string(),
            logo: None,
            website: None,
            terms_url: None,
            privacy_url: None,
            role: TrustEntityRole::Issuer,
            trust_anchor_id,
            r#type: None,
            did_id: Some(did_id),
            identifier_id: None,
            content: None,
            organisation_id,
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn test_create_trust_entity_failed_only_one_entity_can_be_created_for_one_did() {
    let did_id = Uuid::new_v4().into();
    let trust_anchor_id = Uuid::new_v4().into();

    let mut trust_anchor_repository = MockTrustAnchorRepository::default();
    trust_anchor_repository
        .expect_get()
        .with(eq(trust_anchor_id))
        .times(2)
        .returning(move |id| Ok(Some(generic_trust_anchor(id))));

    let mut did_repository = MockDidRepository::default();
    did_repository
        .expect_get_did()
        .with(eq(did_id), always())
        .times(2)
        .returning(move |id, _| Ok(Some(generic_did(*id))));

    let mut trust_entity_repository = MockTrustEntityRepository::default();
    trust_entity_repository
        .expect_create()
        .times(1)
        .return_once(move |request| Ok(request.id));

    trust_entity_repository
        .expect_create()
        .times(1)
        .return_once(|_| Err(DataLayerError::AlreadyExists));

    let organisation_id = Uuid::new_v4().into();
    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation()
        .returning(move |_, _| {
            Ok(Some(Organisation {
                id: organisation_id,
                name: "test".to_string(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                deactivated_at: None,
            }))
        });

    let service = setup_service(TestData {
        did_repository,
        trust_anchor_repository,
        trust_entity_repository,
        organisation_repository,
        ..Default::default()
    });

    service
        .create_trust_entity(CreateTrustEntityRequestDTO {
            name: "".to_string(),
            logo: None,
            website: None,
            terms_url: None,
            privacy_url: None,
            role: TrustEntityRole::Issuer,
            trust_anchor_id,
            did_id: Some(did_id),
            identifier_id: None,
            r#type: None,
            content: None,
            organisation_id,
        })
        .await
        .unwrap();

    assert!(matches!(
        service
            .create_trust_entity(CreateTrustEntityRequestDTO {
                name: "".to_string(),
                logo: None,
                website: None,
                terms_url: None,
                privacy_url: None,
                role: TrustEntityRole::Issuer,
                trust_anchor_id,
                r#type: None,
                did_id: Some(did_id),
                identifier_id: None,
                content: None,
                organisation_id,
            })
            .await
            .unwrap_err(),
        ServiceError::BusinessLogic(BusinessLogicError::TrustEntityAlreadyPresent)
    ));
}

#[tokio::test]
async fn test_publisher_create_remote_trust_entity_success() {
    let trust_anchor_id = Uuid::new_v4().into();
    let did_value =
        DidValue::from_str("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").unwrap();
    let did_id = Uuid::new_v4().into();
    let trust_entity_id = Uuid::new_v4().into();

    let bearer_token = format!(
        "{}.{}",
        "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRpZDprZXk6ejZNa2hhWGdCWkR2b3REa0w1MjU3ZmFpenRpR2lDMlF0S0xHcGJubkVHdGEyZG9LIn0.eyJpc3MiOiJkaWQ6a2V5Ono2TWtoYVhnQlpEdm90RGtMNTI1N2ZhaXp0aUdpQzJRdEtMR3Bibm5FR3RhMmRvSyIsInRpbWVzdGFtcCI6MjIyMzc0NDExM30",
        "ZHVtbXlfc2lnbmF0dXJlX2Zvcl90ZXN0aW5n"
    );

    // Setup mocks
    let mut test_data = TestData::default();

    // Trust anchor, entity repositories
    test_data
        .trust_anchor_repository
        .expect_get()
        .with(eq(trust_anchor_id))
        .once()
        .return_once(move |id| Ok(Some(generic_trust_anchor(id))));

    test_data
        .trust_entity_repository
        .expect_get_by_entity_key()
        .with(eq::<TrustEntityKey>((&did_value).into()))
        .once()
        .return_once(|_| Ok(None));

    let did_value_for_trust_entity = did_value.clone();
    test_data
        .trust_entity_repository
        .expect_create()
        .withf(move |trust_entity| {
            trust_entity.name == "Test Remote Trust Entity"
                && trust_entity.role == TrustEntityRole::Issuer
                && trust_entity.r#type == TrustEntityType::Did
                && trust_entity.entity_key == TrustEntityKey::from(&did_value_for_trust_entity)
                && trust_entity.state == TrustEntityState::Active
        })
        .once()
        .return_once(move |_| Ok(trust_entity_id));

    // DID method provider for bearer token validation
    test_data
        .did_method_provider
        .expect_get_did_method_id()
        .with(eq(did_value.clone()))
        .once()
        .return_once(|_| Some("KEY".to_string()));

    // DID method provider for bearer token validation
    let mut did_document = dummy_did_document(&did_value);
    did_document.verification_method[0].id = did_value.to_string();
    did_document.authentication = Some(vec![did_value.to_string()]);
    did_document.assertion_method = Some(vec![did_value.to_string()]);
    test_data
        .did_method_provider
        .expect_resolve()
        .with(eq(did_value.clone()))
        .once()
        .return_once(move |_| Ok(did_document));

    // DID, Identifier creation
    test_data
        .did_repository
        .expect_get_did_by_value()
        .with(eq(did_value.clone()), eq(None), always())
        .once()
        .return_once(|_, _, _| Ok(None));

    let did_value_for_create = did_value.clone();
    test_data
        .did_repository
        .expect_create_did()
        .withf(move |did| {
            did.did == did_value_for_create
                && did.did_method == "KEY"
                && did.did_type == DidType::Remote
        })
        .once()
        .return_once(move |_| Ok(did_id));

    test_data
        .identifier_repository
        .expect_get_from_did_id()
        .once()
        .return_once(|_, _| Ok(None));

    let did_value_for_identifier = did_value.clone();
    test_data
        .identifier_repository
        .expect_create()
        .withf(move |identifier| {
            identifier.did.as_ref().unwrap().did == did_value_for_identifier
                && identifier.r#type == IdentifierType::Did
        })
        .once()
        .return_once(|_| Ok(Uuid::new_v4().into()));

    // Trust management setup
    let mut trust_management = MockTrustManagement::default();
    trust_management
        .expect_get_capabilities()
        .once()
        .return_once(|| TrustCapabilities {
            operations: vec![TrustOperation::Publish],
            supported_types: vec![TrustEntityType::Did],
        });

    trust_management
        .expect_publish_entity()
        .once()
        .return_once(|_, _| {});

    let trust_management = Arc::new(trust_management);
    test_data
        .trust_provider
        .expect_get()
        .with(eq("SIMPLE_TRUST_LIST"))
        .once()
        .return_once(move |_| Some(trust_management));

    // Key algorithm provider for bearer token validation
    setup_key_algorithm_mocks(&mut test_data.key_algorithm_provider);

    let service = setup_service(test_data);

    let create_request = CreateTrustEntityFromDidPublisherRequestDTO {
        trust_anchor_id: Some(trust_anchor_id),
        did: did_value,
        name: "Test Remote Trust Entity".to_string(),
        logo: None,
        terms_url: None,
        privacy_url: None,
        website: None,
        role: TrustEntityRole::Issuer,
    };

    let created_id = service
        .publisher_create_trust_entity_for_did(create_request, &bearer_token)
        .await
        .unwrap();

    assert_eq!(created_id, trust_entity_id);
}

#[tokio::test]
async fn test_publisher_get_remote_trust_entity_success() {
    let did_value =
        DidValue::from_str("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").unwrap();
    let did_id = Uuid::new_v4().into();
    let trust_entity_id = Uuid::new_v4().into();
    let trust_anchor_id = Uuid::new_v4().into();

    let bearer_token = format!(
        "{}.{}",
        "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRpZDprZXk6ejZNa2hhWGdCWkR2b3REa0w1MjU3ZmFpenRpR2lDMlF0S0xHcGJubkVHdGEyZG9LIn0.eyJpc3MiOiJkaWQ6a2V5Ono2TWtoYVhnQlpEdm90RGtMNTI1N2ZhaXp0aUdpQzJRdEtMR3Bibm5FR3RhMmRvSyIsInRpbWVzdGFtcCI6MjIyMzc0NDExM30",
        "ZHVtbXlfc2lnbmF0dXJlX2Zvcl90ZXN0aW5n"
    );

    let mut test_data = TestData::default();

    // Key algorithm provider for bearer token validation
    setup_key_algorithm_mocks(&mut test_data.key_algorithm_provider);

    // DID method provider for bearer token validation
    let mut did_document = dummy_did_document(&did_value);
    did_document.verification_method[0].id = did_value.to_string();
    did_document.authentication = Some(vec![did_value.to_string()]);
    did_document.assertion_method = Some(vec![did_value.to_string()]);
    test_data
        .did_method_provider
        .expect_resolve()
        .with(eq(did_value.clone()))
        .once()
        .return_once(move |_| Ok(did_document));

    // DID repository - get DID by value
    let mut did = generic_did(did_id);
    did.did = did_value.clone();
    did.organisation = Some(Organisation {
        id: Uuid::new_v4().into(),
        name: "test organisation".to_string(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        deactivated_at: None,
    });

    test_data
        .did_repository
        .expect_get_did_by_value()
        .with(eq(did_value.clone()), eq(Some(None)), always())
        .once()
        .return_once(move |_, _, _| Ok(Some(did)));

    // Trust entity repository - get by entity key
    let mut trust_entity = generic_trust_entity(trust_entity_id);
    trust_entity.entity_key = (&did_value).into();
    trust_entity.trust_anchor = Some(generic_trust_anchor(trust_anchor_id));
    trust_entity.organisation = Some(Organisation {
        id: Uuid::new_v4().into(),
        name: "test organisation".to_string(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        deactivated_at: None,
    });

    test_data
        .trust_entity_repository
        .expect_get_by_entity_key()
        .with(eq::<TrustEntityKey>((&did_value).into()))
        .once()
        .return_once(move |_| Ok(Some(trust_entity)));

    let service = setup_service(test_data);

    let result = service
        .publisher_get_trust_entity_for_did(did_value, &bearer_token)
        .await
        .unwrap();

    assert_eq!(result.id, trust_entity_id);
    assert_eq!(result.name, "generic trust entity");
    assert_eq!(result.role, TrustEntityRole::Issuer);
    assert!(result.did.is_some());
}

// Mocks for parsing / verifying the bearer token
fn setup_key_algorithm_mocks(provider: &mut MockKeyAlgorithmProvider) {
    provider
        .expect_key_algorithm_from_jose_alg()
        .with(eq("ES256"))
        .once()
        .returning(|_| {
            let mut algorithm = MockKeyAlgorithm::default();
            algorithm
                .expect_algorithm_type()
                .once()
                .returning(|| KeyAlgorithmType::Ecdsa);
            Some((KeyAlgorithmType::Ecdsa, Arc::new(algorithm)))
        });

    provider
        .expect_key_algorithm_from_type()
        .with(eq(KeyAlgorithmType::Ecdsa))
        .once()
        .returning(|_| {
            let mut algorithm = MockKeyAlgorithm::default();
            algorithm.expect_parse_jwk().once().returning(|_| {
                let mut public_key_handle = MockSignaturePublicKeyHandle::default();
                public_key_handle
                    .expect_verify()
                    .once()
                    .returning(|_, _| Ok(()));

                Ok(KeyHandle::SignatureOnly(SignatureKeyHandle::PublicKeyOnly(
                    Arc::new(public_key_handle),
                )))
            });
            Some(Arc::new(algorithm))
        });
}
