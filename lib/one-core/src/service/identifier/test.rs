use std::collections::HashMap;
use std::sync::Arc;

use shared_types::i18n::I18nString;
use shared_types::{EcosystemId, EntityId, TrustCollectionId};
use similar_asserts::assert_eq;
use standardized_types::jwk::{JwkUse, PublicJwk, PublicJwkEc};
use uuid::Uuid;

use crate::error::{ErrorCode, ErrorCodeMixin};
use crate::model::blob::BlobType;
use crate::model::certificate::Certificate;
use crate::model::identifier::{
    GetIdentifierList, Identifier, IdentifierData, IdentifierState, IdentifierType,
};
use crate::model::relation::RelatedVec;
use crate::model::trust_collection::{GetTrustCollectionList, TrustCollection};
use crate::model::trust_list_role::TrustListRoleEnum;
use crate::model::trust_list_subscription::{
    GetTrustListSubscriptionList, TrustListSubscription, TrustListSubscriptionState,
};
use crate::proto::identifier_creator::{
    IdentifierName, MockIdentifierCreator, RemoteIdentifierOutcome, RemoteIdentifierRelation,
};
use crate::proto::session_provider::test::StaticSessionProvider;
use crate::proto::transaction_manager::NoTransactionManager;
use crate::proto::trust_list_regenerator::MockTrustListRegenerator;
use crate::provider::blob_storage::MockBlobStorage;
use crate::provider::blob_storage::provider::MockBlobStorageProvider;
use crate::provider::credential_formatter::model::IdentifierDetails;
use crate::provider::ecosystem::directory::MockEcosystemDirectory;
use crate::provider::ecosystem::error::EcosystemError;
use crate::provider::ecosystem::model::ParsedTrustInformation;
use crate::provider::ecosystem::{Ecosystem, MockEcosystem};
use crate::provider::trust_list_subscriber::provider::MockTrustListSubscriberProvider;
use crate::provider::trust_list_subscriber::{
    Feature, MockTrustListSubscriber, TrustEntityMetadata, TrustEntityResponse,
    TrustListSubscriberCapabilities,
};
use crate::repository::certificate_repository::MockCertificateRepository;
use crate::repository::credential_schema_repository::MockCredentialSchemaRepository;
use crate::repository::did_repository::MockDidRepository;
use crate::repository::error::{DataLayerError, EntityKind};
use crate::repository::identifier_repository::MockIdentifierRepository;
use crate::repository::identifier_trust_information_repository::MockIdentifierTrustInformationRepository;
use crate::repository::key_repository::MockKeyRepository;
use crate::repository::localized_text_repository::MockLocalizedTextRepository;
use crate::repository::organisation_repository::MockOrganisationRepository;
use crate::repository::proof_schema_repository::MockProofSchemaRepository;
use crate::repository::trust_collection_repository::MockTrustCollectionRepository;
use crate::repository::trust_list_subscription_repository::MockTrustListSubscriptionRepository;
use crate::service::common_dto::ListQueryDTO;
use crate::service::did::dto::CreateDidRequestKeysDTO;
use crate::service::identifier::IdentifierService;
use crate::service::identifier::dto::{
    CertificateRolesMatchMode, CreateIdentifierKeyRequestDTO, CreateIdentifierRequestDTO,
    CreateIdentifierTrustInformationRequestDTO, CreateRemoteCertificateChainDTO,
    CreateRemoteIdentifierRequestDTO, IdentifierFilterParamsDTO, IdentifierTrustInformationType,
    PatchIdentifierDidRequestDTO, PatchIdentifierRequestDTO, ResolveTrustEntriesRequestDTO,
};
use crate::service::identifier::error::IdentifierServiceError;
use crate::service::test_utilities::{
    dummy_certificate, dummy_did, dummy_identifier, dummy_key, dummy_organisation, generic_config,
    get_dummy_date,
};

#[derive(Default)]
struct Mocks {
    identifier_repository: MockIdentifierRepository,
    certificate_repository: MockCertificateRepository,
    did_repository: MockDidRepository,
    key_repository: MockKeyRepository,
    organisation_repository: MockOrganisationRepository,
    credential_schema_repository: MockCredentialSchemaRepository,
    proof_schema_repository: MockProofSchemaRepository,
    trust_collection_repository: MockTrustCollectionRepository,
    trust_list_subscription_repository: MockTrustListSubscriptionRepository,
    identifier_creator: MockIdentifierCreator,
    session_provider: StaticSessionProvider,
    trust_list_subscriber_provider: MockTrustListSubscriberProvider,
    identifier_trust_information_repository: MockIdentifierTrustInformationRepository,
    localized_text_repository: MockLocalizedTextRepository,
    blob_storage_provider: MockBlobStorageProvider,
    ecosystem_provider: MockEcosystemDirectory,
    trust_list_regenerator: Option<MockTrustListRegenerator>,
}

fn setup_service(mocks: Mocks) -> IdentifierService {
    let trust_list_regenerator = mocks.trust_list_regenerator.unwrap_or_else(|| {
        let mut regenerator = MockTrustListRegenerator::new();
        regenerator
            .expect_regenerate_for_identifier()
            .returning(|_| Ok(()));
        regenerator
    });
    IdentifierService {
        identifier_repository: Arc::new(mocks.identifier_repository),
        certificate_repository: Arc::new(mocks.certificate_repository),
        did_repository: Arc::new(mocks.did_repository),
        key_repository: Arc::new(mocks.key_repository),
        organisation_repository: Arc::new(mocks.organisation_repository),
        credential_schema_repository: Arc::new(mocks.credential_schema_repository),
        proof_schema_repository: Arc::new(mocks.proof_schema_repository),
        trust_collection_repository: Arc::new(mocks.trust_collection_repository),
        trust_list_subscription_repository: Arc::new(mocks.trust_list_subscription_repository),
        identifier_trust_information_repository: Arc::new(
            mocks.identifier_trust_information_repository,
        ),
        localized_text_repository: Arc::new(mocks.localized_text_repository),
        blob_storage_provider: Arc::new(mocks.blob_storage_provider),
        config: Arc::new(generic_config().core),
        identifier_creator: Arc::new(mocks.identifier_creator),
        session_provider: Arc::new(mocks.session_provider),
        trust_list_subscriber_provider: Arc::new(mocks.trust_list_subscriber_provider),
        transaction_manager: Arc::new(NoTransactionManager),
        ecosystem_provider: Arc::new(mocks.ecosystem_provider),
        trust_list_regenerator: Arc::new(trust_list_regenerator),
    }
}

fn setup_service_simple(identifier: Option<Identifier>) -> IdentifierService {
    let mut identifier_repository = MockIdentifierRepository::default();
    identifier_repository.expect_get().returning(move |id| {
        identifier.clone().ok_or(DataLayerError::EntityNotFound {
            kind: EntityKind::Identifier,
            id: id.into(),
        })
    });

    setup_service(Mocks {
        identifier_repository,
        ..Default::default()
    })
}

fn dummy_trust_list_subscription(
    trust_collection_id: TrustCollectionId,
) -> (TrustListSubscription, TrustCollection) {
    let now = get_dummy_date();
    let trust_collection = TrustCollection {
        ecosystem: "EUDI".into(),
        id: trust_collection_id,
        name: "test trust collection".to_string(),
        created_date: now,
        last_modified: now,
        deactivated_at: None,
        remote_trust_collection_url: None,
        organisation: dummy_organisation(None).into(),
    };
    (
        TrustListSubscription {
            id: Uuid::new_v4().into(),
            name: "test trust list subscription".to_string(),
            created_date: now,
            last_modified: now,
            deactivated_at: None,
            r#type: "test type".to_string().into(),
            reference: "http://test.com".to_string(),
            role: Some(TrustListRoleEnum::Issuer),
            state: TrustListSubscriptionState::Active,
            trust_collection: trust_collection.clone().into(),
        },
        trust_collection,
    )
}

#[tokio::test]
async fn test_get_identifier_list_session_org_mismatch() {
    let service = setup_service_simple(None);

    let result = service
        .get_identifier_list(ListQueryDTO {
            page: 0,
            page_size: 0,
            sort: None,
            sort_direction: None,
            filter: IdentifierFilterParamsDTO {
                ids: None,
                name: None,
                types: None,
                states: None,
                did_methods: None,
                is_remote: None,
                autogenerated: None,
                key_algorithms: None,
                key_roles: None,
                key_storages: None,
                certificate_roles: None,
                certificate_roles_match_mode: CertificateRolesMatchMode::default(),
                trust_issuance_schema_id: None,
                trust_verification_schema_id: None,
                ecosystem: None,
                ecosystem_roles: None,
                ecosystem_credential_schema_id: None,
                ecosystem_proof_schema_id: None,
                exact: None,
                organisation_id: Uuid::new_v4().into(),
                created_date_after: None,
                created_date_before: None,
                last_modified_after: None,
                last_modified_before: None,
            },
            include: None,
        })
        .await;

    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);
}

#[tokio::test]
async fn test_create_identifier_session_org_mismatch() {
    let service = setup_service_simple(None);

    let result = service
        .create_identifier(CreateIdentifierRequestDTO {
            name: "".to_string(),
            did: None,
            key: None,
            key_id: None,
            certificates: None,
            certificate_authorities: None,
            translations: None,
            logo: None,
            organisation_id: Uuid::new_v4().into(),
            trust_information: vec![],
        })
        .await;

    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);
}

#[tokio::test]
async fn test_identifier_ops_session_org_mismatch() {
    let mut identifier = dummy_identifier();
    identifier.organisation = dummy_organisation(None).into();
    let service = setup_service_simple(Some(identifier));

    let result = service.get_identifier(&Uuid::new_v4().into()).await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);

    let result = service.delete_identifier(&Uuid::new_v4().into()).await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);
}

#[tokio::test]
async fn test_resolve_trust_entries_success() {
    // given
    let mut identifier_repository = MockIdentifierRepository::default();
    let mut trust_list_subscription_repository = MockTrustListSubscriptionRepository::default();
    let mut trust_collection_repository = MockTrustCollectionRepository::default();
    let mut trust_list_subscriber_provider = MockTrustListSubscriberProvider::default();

    let identifier_id = Uuid::new_v4().into();
    let mut identifier = dummy_identifier();
    let organisation_id = identifier.organisation.id();
    identifier.id = identifier_id;
    identifier.is_remote = true;
    identifier.data = IdentifierData::Certificate(RelatedVec::from(vec![]));

    identifier_repository
        .expect_get_identifier_list()
        .returning(move |_| {
            Ok(GetIdentifierList {
                values: vec![identifier.clone()],
                total_items: Some(1),
                total_pages: Some(1),
            })
        });

    let trust_collection_id = Uuid::new_v4().into();
    let (subscription, trust_collection) = dummy_trust_list_subscription(trust_collection_id);

    trust_list_subscription_repository
        .expect_list()
        .returning(move |_| {
            Ok(GetTrustListSubscriptionList {
                values: vec![subscription.clone()],
                total_items: Some(1),
                total_pages: Some(1),
            })
        });

    trust_collection_repository
        .expect_list()
        .returning(move |_| {
            Ok(GetTrustCollectionList {
                values: vec![trust_collection.clone()],
                total_items: Some(1),
                total_pages: Some(1),
            })
        });

    let mut trust_list_subscriber = MockTrustListSubscriber::default();
    trust_list_subscriber
        .expect_get_capabilities()
        .returning(|| TrustListSubscriberCapabilities {
            roles: vec![],
            resolvable_identifier_types: vec![
                IdentifierType::Certificate,
                IdentifierType::CertificateAuthority,
            ],
            features: vec![Feature::SupportsRemoteIdentifiers],
        });
    trust_list_subscriber
        .expect_resolve_entries()
        .returning(move |_, _| {
            let mut map = HashMap::new();
            map.insert(
                identifier_id,
                vec![TrustEntityResponse {
                    derived_role: None,
                    metadata: TrustEntityMetadata::Lote(Default::default()),
                }],
            );
            Ok(map)
        });

    let subscriber_arc: Arc<dyn crate::provider::trust_list_subscriber::TrustListSubscriber> =
        Arc::new(trust_list_subscriber);
    trust_list_subscriber_provider
        .expect_get()
        .returning(move |_| Ok(subscriber_arc.clone()));

    let service = setup_service(Mocks {
        session_provider: StaticSessionProvider::new_with_org(organisation_id),
        identifier_repository,
        trust_list_subscription_repository,
        trust_collection_repository,
        trust_list_subscriber_provider,
        ..Default::default()
    });

    // when
    let result = service
        .resolve_trust_entries(ResolveTrustEntriesRequestDTO {
            identifiers: vec![identifier_id],
            roles: None,
            trust_collection_ids: None,
        })
        .await
        .unwrap();

    // then
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].identifier.id, identifier_id);
    assert_eq!(result[0].trust_entries.len(), 1);
}

#[tokio::test]
async fn test_resolve_trust_entries_session_org_mismatch() {
    let mut identifier_repository = MockIdentifierRepository::default();
    let mut identifier = dummy_identifier();
    identifier.organisation = dummy_organisation(None).into();
    identifier_repository
        .expect_get_identifier_list()
        .returning(move |_| {
            Ok(GetIdentifierList {
                values: vec![identifier.clone()],
                total_items: Some(1),
                total_pages: Some(1),
            })
        });

    let service = setup_service(Mocks {
        identifier_repository,
        ..Default::default()
    });

    let result = service
        .resolve_trust_entries(ResolveTrustEntriesRequestDTO {
            identifiers: vec![Uuid::new_v4().into()],
            roles: None,
            trust_collection_ids: None,
        })
        .await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);
}

#[tokio::test]
async fn test_resolve_trust_entries_identifiers_of_different_organisations() {
    let mut identifier_repository = MockIdentifierRepository::default();
    let identifier = dummy_identifier();
    let organisation_id = identifier.organisation.id();
    let other_identifier = dummy_identifier();
    identifier_repository
        .expect_get_identifier_list()
        .returning(move |_| {
            Ok(GetIdentifierList {
                values: vec![identifier.clone(), other_identifier.clone()],
                total_items: Some(2),
                total_pages: Some(1),
            })
        });

    let service = setup_service(Mocks {
        identifier_repository,
        session_provider: StaticSessionProvider::new_with_org(organisation_id),
        ..Default::default()
    });

    let result = service
        .resolve_trust_entries(ResolveTrustEntriesRequestDTO {
            identifiers: vec![Uuid::new_v4().into(), Uuid::new_v4().into()],
            roles: None,
            trust_collection_ids: None,
        })
        .await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);
}

#[tokio::test]
async fn test_resolve_trust_entries_filters_local() {
    // given
    let mut identifier_repository = MockIdentifierRepository::default();
    let mut trust_list_subscription_repository = MockTrustListSubscriptionRepository::default();
    let mut trust_collection_repository = MockTrustCollectionRepository::default();
    let mut trust_list_subscriber_provider = MockTrustListSubscriberProvider::default();

    let identifier_id = Uuid::new_v4().into();
    let mut identifier = dummy_identifier();
    let organisation_id = identifier.organisation.id();
    identifier.id = identifier_id;
    identifier.is_remote = false; // Local
    identifier.data = IdentifierData::Certificate(RelatedVec::from(vec![]));

    identifier_repository
        .expect_get_identifier_list()
        .returning(move |_| {
            Ok(GetIdentifierList {
                values: vec![identifier.clone()],
                total_items: Some(1),
                total_pages: Some(1),
            })
        });

    trust_list_subscription_repository
        .expect_list()
        .returning(move |_| {
            Ok(GetTrustListSubscriptionList {
                values: vec![dummy_trust_list_subscription(Uuid::new_v4().into()).0],
                total_items: Some(1),
                total_pages: Some(1),
            })
        });

    trust_collection_repository
        .expect_list()
        .returning(move |_| {
            Ok(GetTrustCollectionList {
                values: vec![],
                total_items: Some(0),
                total_pages: Some(0),
            })
        });

    let mut trust_list_subscriber = MockTrustListSubscriber::default();
    trust_list_subscriber
        .expect_get_capabilities()
        .returning(|| TrustListSubscriberCapabilities {
            roles: vec![],
            resolvable_identifier_types: vec![
                IdentifierType::Certificate,
                IdentifierType::CertificateAuthority,
            ],
            features: vec![Feature::SupportsRemoteIdentifiers],
        });
    // Should be called with empty identifiers list
    trust_list_subscriber
        .expect_resolve_entries()
        .withf(|_, identifiers| identifiers.is_empty())
        .returning(move |_, _| Ok(HashMap::new()));

    let subscriber_arc: Arc<dyn crate::provider::trust_list_subscriber::TrustListSubscriber> =
        Arc::new(trust_list_subscriber);
    trust_list_subscriber_provider
        .expect_get()
        .returning(move |_| Ok(subscriber_arc.clone()));

    let service = setup_service(Mocks {
        session_provider: StaticSessionProvider::new_with_org(organisation_id),
        identifier_repository,
        trust_list_subscription_repository,
        trust_collection_repository,
        trust_list_subscriber_provider,
        ..Default::default()
    });

    // when
    let result = service
        .resolve_trust_entries(ResolveTrustEntriesRequestDTO {
            identifiers: vec![identifier_id],
            roles: None,
            trust_collection_ids: None,
        })
        .await
        .unwrap();

    // then
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].identifier.id, identifier_id);
    assert_eq!(result[0].trust_entries.len(), 0);
}

#[tokio::test]
async fn test_resolve_trust_entries_ignores_missing_identifiers() {
    // given
    let mut identifier_repository = MockIdentifierRepository::default();
    let mut trust_list_subscription_repository = MockTrustListSubscriptionRepository::default();
    let mut trust_collection_repository = MockTrustCollectionRepository::default();

    let identifier_id = Uuid::new_v4().into();
    identifier_repository
        .expect_get_identifier_list()
        .returning(move |_| {
            Ok(GetIdentifierList {
                values: vec![],
                total_items: Some(0),
                total_pages: Some(0),
            })
        });

    trust_list_subscription_repository
        .expect_list()
        .returning(move |_| {
            Ok(GetTrustListSubscriptionList {
                values: vec![],
                total_items: Some(0),
                total_pages: Some(0),
            })
        });

    trust_collection_repository
        .expect_list()
        .returning(move |_| {
            Ok(GetTrustCollectionList {
                values: vec![],
                total_items: Some(0),
                total_pages: Some(0),
            })
        });

    let service = setup_service(Mocks {
        identifier_repository,
        trust_list_subscription_repository,
        trust_collection_repository,
        ..Default::default()
    });

    // when
    let result = service
        .resolve_trust_entries(ResolveTrustEntriesRequestDTO {
            identifiers: vec![identifier_id],
            roles: None,
            trust_collection_ids: None,
        })
        .await
        .unwrap();

    // then
    // Result should be empty because the identifier was not found in repo
    assert_eq!(result.len(), 0);
}

#[tokio::test]
async fn test_resolve_trust_entries_subscriber_error() {
    // given
    let mut identifier_repository = MockIdentifierRepository::default();
    let mut trust_list_subscription_repository = MockTrustListSubscriptionRepository::default();
    let mut trust_collection_repository = MockTrustCollectionRepository::default();
    let mut trust_list_subscriber_provider = MockTrustListSubscriberProvider::default();

    let identifier_id = Uuid::new_v4().into();
    let mut identifier = dummy_identifier();
    let organisation_id = identifier.organisation.id();
    identifier.id = identifier_id;
    identifier.is_remote = true;
    identifier.data = IdentifierData::Certificate(RelatedVec::from(vec![]));

    identifier_repository
        .expect_get_identifier_list()
        .returning(move |_| {
            Ok(GetIdentifierList {
                values: vec![identifier.clone()],
                total_items: Some(1),
                total_pages: Some(1),
            })
        });

    trust_list_subscription_repository
        .expect_list()
        .returning(move |_| {
            Ok(GetTrustListSubscriptionList {
                values: vec![dummy_trust_list_subscription(Uuid::new_v4().into()).0],
                total_items: Some(1),
                total_pages: Some(1),
            })
        });

    trust_collection_repository
        .expect_list()
        .returning(move |_| {
            Ok(GetTrustCollectionList {
                values: vec![],
                total_items: Some(0),
                total_pages: Some(0),
            })
        });

    let mut trust_list_subscriber = MockTrustListSubscriber::default();
    trust_list_subscriber
        .expect_get_capabilities()
        .returning(|| TrustListSubscriberCapabilities {
            roles: vec![],
            resolvable_identifier_types: vec![
                IdentifierType::Certificate,
                IdentifierType::CertificateAuthority,
            ],
            features: vec![Feature::SupportsRemoteIdentifiers],
        });
    trust_list_subscriber
        .expect_resolve_entries()
        .returning(move |_, _| Err(crate::provider::trust_list_subscriber::error::TrustListSubscriberError::MappingError("error".to_string())));

    let subscriber_arc: Arc<dyn crate::provider::trust_list_subscriber::TrustListSubscriber> =
        Arc::new(trust_list_subscriber);
    trust_list_subscriber_provider
        .expect_get()
        .returning(move |_| Ok(subscriber_arc.clone()));

    let service = setup_service(Mocks {
        session_provider: StaticSessionProvider::new_with_org(organisation_id),
        identifier_repository,
        trust_list_subscription_repository,
        trust_collection_repository,
        trust_list_subscriber_provider,
        ..Default::default()
    });

    // when
    let result = service
        .resolve_trust_entries(ResolveTrustEntriesRequestDTO {
            identifiers: vec![identifier_id],
            roles: None,
            trust_collection_ids: None,
        })
        .await
        .unwrap();

    // then
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].identifier.id, identifier_id);
    assert_eq!(result[0].trust_entries.len(), 0);
}

#[tokio::test]
async fn test_resolve_trust_entries_filters_key_type() {
    // given
    let mut identifier_repository = MockIdentifierRepository::default();
    let mut trust_list_subscription_repository = MockTrustListSubscriptionRepository::default();
    let mut trust_collection_repository = MockTrustCollectionRepository::default();
    let mut trust_list_subscriber_provider = MockTrustListSubscriberProvider::default();

    let identifier_id = Uuid::new_v4().into();
    let mut identifier = dummy_identifier();
    let organisation_id = identifier.organisation.id();
    identifier.id = identifier_id;
    identifier.is_remote = true;
    identifier.data = IdentifierData::Key(dummy_key().into());

    identifier_repository
        .expect_get_identifier_list()
        .returning(move |_| {
            Ok(GetIdentifierList {
                values: vec![identifier.clone()],
                total_items: Some(1),
                total_pages: Some(1),
            })
        });

    trust_list_subscription_repository
        .expect_list()
        .returning(move |_| {
            Ok(GetTrustListSubscriptionList {
                values: vec![dummy_trust_list_subscription(Uuid::new_v4().into()).0],
                total_items: Some(1),
                total_pages: Some(1),
            })
        });

    trust_collection_repository
        .expect_list()
        .returning(move |_| {
            Ok(GetTrustCollectionList {
                values: vec![],
                total_items: Some(0),
                total_pages: Some(0),
            })
        });

    let mut trust_list_subscriber = MockTrustListSubscriber::default();
    trust_list_subscriber
        .expect_get_capabilities()
        .returning(|| TrustListSubscriberCapabilities {
            roles: vec![],
            resolvable_identifier_types: vec![
                IdentifierType::Certificate,
                IdentifierType::CertificateAuthority,
            ],
            features: vec![Feature::SupportsRemoteIdentifiers],
        });

    // Should be called with empty identifiers list because Key type is filtered out
    trust_list_subscriber
        .expect_resolve_entries()
        .withf(|_, identifiers| identifiers.is_empty())
        .returning(move |_, _| Ok(HashMap::new()));

    let subscriber_arc: Arc<dyn crate::provider::trust_list_subscriber::TrustListSubscriber> =
        Arc::new(trust_list_subscriber);
    trust_list_subscriber_provider
        .expect_get()
        .returning(move |_| Ok(subscriber_arc.clone()));

    let service = setup_service(Mocks {
        session_provider: StaticSessionProvider::new_with_org(organisation_id),
        identifier_repository,
        trust_list_subscription_repository,
        trust_collection_repository,
        trust_list_subscriber_provider,
        ..Default::default()
    });

    // when
    let result = service
        .resolve_trust_entries(ResolveTrustEntriesRequestDTO {
            identifiers: vec![identifier_id],
            roles: None,
            trust_collection_ids: None,
        })
        .await
        .unwrap();

    // then
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].identifier.id, identifier_id);
    assert_eq!(result[0].trust_entries.len(), 0);
}

fn setup_for_trust_information() -> (
    StaticSessionProvider,
    MockOrganisationRepository,
    MockKeyRepository,
    MockIdentifierCreator,
    shared_types::OrganisationId,
    shared_types::KeyId,
) {
    let session_provider = StaticSessionProvider::new_random();
    let organisation_id = session_provider.0.organisation_id.unwrap();

    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation()
        .returning(move |_| Ok(dummy_organisation(Some(organisation_id))));

    let mut key_repository = MockKeyRepository::default();
    let dummy_key = dummy_key();
    let key_id = dummy_key.id;
    key_repository
        .expect_get_key()
        .returning(move |_| Ok(dummy_key.clone()));

    let mut identifier = dummy_identifier();
    identifier.id = Uuid::new_v4().into();
    identifier.organisation = dummy_organisation(Some(organisation_id)).into();

    let mut identifier_creator = MockIdentifierCreator::default();
    identifier_creator
        .expect_create_local_identifier()
        .returning(move |_, _| Ok(identifier.clone()));

    (
        session_provider,
        organisation_repository,
        key_repository,
        identifier_creator,
        organisation_id,
        key_id,
    )
}

fn create_identifier_with_trust_information_request(
    organisation_id: shared_types::OrganisationId,
    key_id: shared_types::KeyId,
) -> CreateIdentifierRequestDTO {
    CreateIdentifierRequestDTO {
        name: "test identifier".to_string(),
        did: None,
        key: Some(CreateIdentifierKeyRequestDTO { key_id }),
        key_id: None,
        certificates: None,
        certificate_authorities: None,
        translations: None,
        logo: None,
        organisation_id,
        trust_information: vec![CreateIdentifierTrustInformationRequestDTO {
            data: "dummy reg cert".to_string(),
            r#type: IdentifierTrustInformationType::RegistrationCertificate,
        }],
    }
}

fn ecosystem_accepting_trust_information(config_name: &'static str) -> MockEcosystem {
    let mut ecosystem = MockEcosystem::new();
    ecosystem
        .expect_config_name()
        .return_const(EcosystemId::from(config_name));
    ecosystem
        .expect_parse_identifier_trust_information()
        .once()
        .returning(|_, inputs| {
            Ok(inputs
                .iter()
                .map(|_| ParsedTrustInformation {
                    valid_from: None,
                    valid_to: None,
                    intended_use: None,
                    allowed_issuance_types: vec![],
                    allowed_verification_types: vec![],
                    blob_type: BlobType::RegistrationCertificate,
                })
                .collect())
        });
    ecosystem
}

#[tokio::test]
async fn test_create_identifier_with_trust_information() {
    let (
        session_provider,
        organisation_repository,
        key_repository,
        identifier_creator,
        organisation_id,
        key_id,
    ) = setup_for_trust_information();

    let mut identifier_trust_information_repository =
        MockIdentifierTrustInformationRepository::default();
    identifier_trust_information_repository
        .expect_create()
        .once()
        .returning(|_| Ok(Uuid::new_v4().into()));
    let mut blob_storage = MockBlobStorage::default();
    blob_storage.expect_create().once().returning(|_| Ok(()));
    let blob_storage = Arc::new(blob_storage);
    let mut blob_storage_provider = MockBlobStorageProvider::default();
    blob_storage_provider
        .expect_get_blob_storage()
        .once()
        .returning(move |_| Ok(blob_storage.clone()));

    let mut ecosystem_provider = MockEcosystemDirectory::new();
    ecosystem_provider
        .expect_enabled_ecosystems()
        .returning(|| {
            vec![Arc::new(ecosystem_accepting_trust_information("EUDI")) as Arc<dyn Ecosystem>]
        });

    let service = setup_service(Mocks {
        organisation_repository,
        key_repository,
        identifier_creator,
        identifier_trust_information_repository,
        blob_storage_provider,
        session_provider,
        ecosystem_provider,
        ..Default::default()
    });

    let result = service
        .create_identifier(create_identifier_with_trust_information_request(
            organisation_id,
            key_id,
        ))
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_create_identifier_trust_information_fails_when_no_ecosystem_enabled() {
    // given: no ecosystem is enabled
    let (
        session_provider,
        organisation_repository,
        key_repository,
        identifier_creator,
        organisation_id,
        key_id,
    ) = setup_for_trust_information();

    let mut ecosystem_provider = MockEcosystemDirectory::new();
    ecosystem_provider
        .expect_enabled_ecosystems()
        .returning(Vec::new);

    let service = setup_service(Mocks {
        organisation_repository,
        key_repository,
        identifier_creator,
        session_provider,
        ecosystem_provider,
        ..Default::default()
    });

    // when
    let result = service
        .create_identifier(create_identifier_with_trust_information_request(
            organisation_id,
            key_id,
        ))
        .await;

    // then
    let error = result.unwrap_err();
    assert_eq!(error.error_code(), ErrorCode::BR_0416);
    assert!(matches!(
        error,
        IdentifierServiceError::NoEcosystemEnabledForTrustInformation
    ));
}

#[tokio::test]
async fn test_create_identifier_trust_information_fails_when_not_applicable() {
    // given: EUDI is enabled, but reports it does not handle this trust
    // information type
    let (
        session_provider,
        organisation_repository,
        key_repository,
        identifier_creator,
        organisation_id,
        key_id,
    ) = setup_for_trust_information();

    let mut ecosystem_provider = MockEcosystemDirectory::new();
    ecosystem_provider
        .expect_enabled_ecosystems()
        .returning(|| {
            let mut ecosystem = MockEcosystem::new();
            ecosystem
                .expect_config_name()
                .return_const(EcosystemId::from("EUDI"));
            ecosystem
                .expect_parse_identifier_trust_information()
                .once()
                .returning(|_, _| Err(EcosystemError::NotApplicable));
            vec![Arc::new(ecosystem) as Arc<dyn Ecosystem>]
        });

    let service = setup_service(Mocks {
        organisation_repository,
        key_repository,
        identifier_creator,
        session_provider,
        ecosystem_provider,
        ..Default::default()
    });

    // when
    let result = service
        .create_identifier(create_identifier_with_trust_information_request(
            organisation_id,
            key_id,
        ))
        .await;

    // then
    let error = result.unwrap_err();
    assert_eq!(error.error_code(), ErrorCode::BR_0416);
    let IdentifierServiceError::TrustInformationRejected(outcomes) = error else {
        panic!("expected TrustInformationRejected, got {error:?}");
    };
    let outcome = outcomes.get(&EcosystemId::from("EUDI")).unwrap();
    assert!(!outcome.is_trusted());
    assert_eq!(
        outcome.error.as_ref().unwrap().error_code,
        ErrorCode::BR_0479
    );
}

#[tokio::test]
async fn test_create_identifier_trust_information_tries_next_ecosystem_after_rejection() {
    let (
        session_provider,
        organisation_repository,
        key_repository,
        identifier_creator,
        organisation_id,
        key_id,
    ) = setup_for_trust_information();

    let mut identifier_trust_information_repository =
        MockIdentifierTrustInformationRepository::default();
    identifier_trust_information_repository
        .expect_create()
        .once()
        .returning(|_| Ok(Uuid::new_v4().into()));
    let mut blob_storage = MockBlobStorage::default();
    blob_storage.expect_create().once().returning(|_| Ok(()));
    let blob_storage = Arc::new(blob_storage);
    let mut blob_storage_provider = MockBlobStorageProvider::default();
    blob_storage_provider
        .expect_get_blob_storage()
        .once()
        .returning(move |_| Ok(blob_storage.clone()));

    let mut ecosystem_provider = MockEcosystemDirectory::new();
    ecosystem_provider
        .expect_enabled_ecosystems()
        .returning(|| {
            let mut rejecting = MockEcosystem::new();
            rejecting
                .expect_config_name()
                .return_const(EcosystemId::from("FIRST"));
            rejecting
                .expect_parse_identifier_trust_information()
                .once()
                .returning(|_, _| {
                    Err(EcosystemError::InvalidTrustInformation(
                        "invalid".to_string(),
                    ))
                });
            vec![
                Arc::new(rejecting) as Arc<dyn Ecosystem>,
                Arc::new(ecosystem_accepting_trust_information("EUDI")) as Arc<dyn Ecosystem>,
            ]
        });

    let service = setup_service(Mocks {
        organisation_repository,
        key_repository,
        identifier_creator,
        identifier_trust_information_repository,
        blob_storage_provider,
        session_provider,
        ecosystem_provider,
        ..Default::default()
    });

    let result = service
        .create_identifier(create_identifier_with_trust_information_request(
            organisation_id,
            key_id,
        ))
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_delete_identifier_cascades_to_certificates() {
    let identifier_id = Uuid::new_v4().into();
    let organisation = dummy_organisation(None);
    let cert_a: Certificate = dummy_certificate(identifier_id);
    let cert_b: Certificate = dummy_certificate(identifier_id);

    let mut identifier = dummy_identifier();
    identifier.id = identifier_id;
    identifier.organisation = organisation.clone().into();
    identifier.data =
        IdentifierData::Certificate(RelatedVec::from(vec![cert_a.clone(), cert_b.clone()]));

    let mut identifier_repository = MockIdentifierRepository::default();
    let returned_identifier = identifier.clone();
    identifier_repository
        .expect_get()
        .returning(move |_| Ok(returned_identifier.clone()));
    identifier_repository
        .expect_delete()
        .times(1)
        .returning(|_| Ok(()));

    let mut certificate_repository = MockCertificateRepository::default();
    certificate_repository
        .expect_delete()
        .times(2)
        .returning(|_| Ok(()));

    let service = setup_service(Mocks {
        identifier_repository,
        certificate_repository,
        session_provider: StaticSessionProvider::new_with_org(organisation.id),
        ..Default::default()
    });

    service.delete_identifier(&identifier_id).await.unwrap();
}

#[tokio::test]
async fn test_delete_identifier_removes_logo_blob() {
    let logo_id: shared_types::BlobId = Uuid::new_v4().into();
    let mut identifier = dummy_identifier();
    identifier.logo = Some(logo_id);
    identifier.data = IdentifierData::Key(dummy_key().into());
    let identifier_id = identifier.id;
    let organisation_id = identifier.organisation.id();

    let mut identifier_repository = MockIdentifierRepository::default();
    identifier_repository
        .expect_get()
        .once()
        .returning(move |_| Ok(identifier.clone()));
    identifier_repository
        .expect_delete()
        .once()
        .returning(|_| Ok(()));

    let mut blob_storage = MockBlobStorage::default();
    blob_storage
        .expect_delete()
        .once()
        .withf(move |id| *id == logo_id)
        .returning(|_| Ok(()));
    let blob_storage: Arc<dyn crate::provider::blob_storage::BlobStorage> = Arc::new(blob_storage);
    let mut blob_storage_provider = MockBlobStorageProvider::default();
    blob_storage_provider
        .expect_get_blob_storage()
        .once()
        .returning(move |_| Ok(blob_storage.clone()));

    let service = setup_service(Mocks {
        identifier_repository,
        blob_storage_provider,
        session_provider: StaticSessionProvider::new_with_org(organisation_id),
        ..Default::default()
    });

    service.delete_identifier(&identifier_id).await.unwrap();
}

fn dummy_public_jwk() -> PublicJwk {
    PublicJwk::Okp(PublicJwkEc {
        alg: None,
        r#use: None,
        kid: None,
        crv: "Ed25519".to_string(),
        x: "test".to_string(),
        y: None,
    })
}

fn remote_dto(
    organisation_id: shared_types::OrganisationId,
    name: &str,
) -> CreateRemoteIdentifierRequestDTO {
    CreateRemoteIdentifierRequestDTO {
        name: name.to_string(),
        did: None,
        key: None,
        certificates: None,
        certificate_authorities: None,
        organisation_id,
    }
}

#[tokio::test]
async fn test_create_remote_identifier_session_org_mismatch() {
    let service = setup_service_simple(None);

    let result = service
        .create_remote_identifier(CreateRemoteIdentifierRequestDTO {
            did: Some("did:example:123".parse().unwrap()),
            ..remote_dto(Uuid::new_v4().into(), "remote")
        })
        .await;

    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);
}

#[tokio::test]
async fn test_create_remote_identifier_missing_organisation() {
    let session_provider = StaticSessionProvider::new_random();
    let organisation_id = session_provider.0.organisation_id.unwrap();

    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation()
        .returning(|_| {
            Err(DataLayerError::EntityNotFound {
                kind: EntityKind::Organisation,
                id: Uuid::nil(),
            })
        });

    let service = setup_service(Mocks {
        organisation_repository,
        session_provider,
        ..Default::default()
    });

    let result = service
        .create_remote_identifier(CreateRemoteIdentifierRequestDTO {
            did: Some("did:example:123".parse().unwrap()),
            ..remote_dto(organisation_id, "remote")
        })
        .await;

    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0022);
}

#[tokio::test]
async fn test_create_remote_identifier_deactivated_organisation() {
    let session_provider = StaticSessionProvider::new_random();
    let organisation_id = session_provider.0.organisation_id.unwrap();

    let mut deactivated_organisation = dummy_organisation(Some(organisation_id));
    deactivated_organisation.deactivated_at = Some(get_dummy_date());

    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation()
        .returning(move |_| Ok(deactivated_organisation.clone()));

    let service = setup_service(Mocks {
        organisation_repository,
        session_provider,
        ..Default::default()
    });

    let result = service
        .create_remote_identifier(CreateRemoteIdentifierRequestDTO {
            did: Some("did:example:123".parse().unwrap()),
            ..remote_dto(organisation_id, "remote")
        })
        .await;

    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0241);
}

#[tokio::test]
async fn test_create_remote_identifier_empty_request_returns_error() {
    let session_provider = StaticSessionProvider::new_random();
    let organisation_id = session_provider.0.organisation_id.unwrap();

    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation()
        .returning(move |_| Ok(dummy_organisation(Some(organisation_id))));

    let service = setup_service(Mocks {
        organisation_repository,
        identifier_repository: identifier_repo_with_no_name_match(),
        session_provider,
        ..Default::default()
    });

    let result = service
        .create_remote_identifier(remote_dto(organisation_id, "remote"))
        .await;

    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0206);
}

#[tokio::test]
async fn test_create_remote_identifier_multiple_inputs_returns_error() {
    let session_provider = StaticSessionProvider::new_random();
    let organisation_id = session_provider.0.organisation_id.unwrap();

    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation()
        .returning(move |_| Ok(dummy_organisation(Some(organisation_id))));

    let service = setup_service(Mocks {
        organisation_repository,
        identifier_repository: identifier_repo_with_no_name_match(),
        session_provider,
        ..Default::default()
    });

    let result = service
        .create_remote_identifier(CreateRemoteIdentifierRequestDTO {
            did: Some("did:example:123".parse().unwrap()),
            key: Some(dummy_public_jwk()),
            ..remote_dto(organisation_id, "remote")
        })
        .await;

    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0206);
}

fn full_field_jwk() -> PublicJwk {
    PublicJwk::Okp(PublicJwkEc {
        alg: Some("EdDSA".to_string()),
        r#use: Some(JwkUse::Signature),
        kid: Some("test-kid".to_string()),
        crv: "Ed25519".to_string(),
        x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo".to_string(),
        y: None,
    })
}

fn org_repo_returning_org(
    organisation_id: shared_types::OrganisationId,
) -> MockOrganisationRepository {
    let mut repo = MockOrganisationRepository::default();
    repo.expect_get_organisation()
        .returning(move |_| Ok(dummy_organisation(Some(organisation_id))));
    repo
}

fn identifier_repo_with_no_name_match() -> MockIdentifierRepository {
    let mut repo = MockIdentifierRepository::default();
    repo.expect_get_identifier_list().returning(|_| {
        Ok(GetIdentifierList {
            values: vec![],
            total_pages: Some(0),
            total_items: Some(0),
        })
    });
    repo
}

#[tokio::test]
async fn test_create_remote_did_identifier_success() {
    let session_provider = StaticSessionProvider::new_random();
    let organisation_id = session_provider.0.organisation_id.unwrap();
    let did_value: shared_types::DidValue = "did:example:abc".parse().unwrap();
    let identifier_id: shared_types::IdentifierId = Uuid::new_v4().into();

    let mut returned = dummy_identifier();
    returned.id = identifier_id;
    returned.name = "my-did".to_string();
    let returned_clone = returned.clone();

    let expected_did = did_value.clone();
    let mut identifier_creator = MockIdentifierCreator::default();
    identifier_creator
        .expect_get_or_create_remote_identifier()
        .withf(
            move |org_id, details, name, autogenerated, _translations, _logo| {
                org_id == &organisation_id
                    && matches!(details, IdentifierDetails::Did(d) if *d == expected_did)
                    && matches!(name, IdentifierName::Name(n) if n == "my-did")
                    && !autogenerated
            },
        )
        .once()
        .returning(move |_, _, _, _, _, _| {
            Ok((
                returned_clone.clone(),
                RemoteIdentifierRelation::Did(dummy_did()),
            ))
        });

    let service = setup_service(Mocks {
        organisation_repository: org_repo_returning_org(organisation_id),
        identifier_repository: identifier_repo_with_no_name_match(),
        identifier_creator,
        session_provider,
        ..Default::default()
    });

    let result = service
        .create_remote_identifier(CreateRemoteIdentifierRequestDTO {
            did: Some(did_value),
            ..remote_dto(organisation_id, "my-did")
        })
        .await
        .unwrap();

    assert_eq!(result, identifier_id);
}

#[tokio::test]
async fn test_create_remote_did_identifier_duplicate_returns_colliding_id() {
    let session_provider = StaticSessionProvider::new_random();
    let organisation_id = session_provider.0.organisation_id.unwrap();
    let existing_id: shared_types::IdentifierId = Uuid::new_v4().into();

    let mut existing = dummy_identifier();
    existing.id = existing_id;
    existing.name = "name-set-by-other-request".to_string();
    let existing_clone = existing.clone();

    let mut identifier_creator = MockIdentifierCreator::default();
    identifier_creator
        .expect_get_or_create_remote_identifier()
        .once()
        .returning(move |_, _, _, _, _, _| {
            Ok((
                existing_clone.clone(),
                RemoteIdentifierRelation::Did(dummy_did()),
            ))
        });

    let service = setup_service(Mocks {
        organisation_repository: org_repo_returning_org(organisation_id),
        identifier_repository: identifier_repo_with_no_name_match(),
        identifier_creator,
        session_provider,
        ..Default::default()
    });

    let err = service
        .create_remote_identifier(CreateRemoteIdentifierRequestDTO {
            did: Some("did:example:abc".parse().unwrap()),
            ..remote_dto(organisation_id, "my-did")
        })
        .await
        .unwrap_err();

    assert_eq!(err.error_code(), ErrorCode::BR_0240);
    assert!(matches!(
        err,
        IdentifierServiceError::RemoteIdentifierAlreadyExists(id) if id == existing_id
    ));
}

#[tokio::test]
async fn test_create_remote_key_identifier_success_forwards_jwk_and_name() {
    let session_provider = StaticSessionProvider::new_random();
    let organisation_id = session_provider.0.organisation_id.unwrap();
    let jwk = full_field_jwk();
    let identifier_id: shared_types::IdentifierId = Uuid::new_v4().into();

    let mut returned = dummy_identifier();
    returned.id = identifier_id;
    returned.name = "my-key".to_string();
    let returned_clone = returned.clone();

    let expected_jwk = jwk.clone();
    let mut identifier_creator = MockIdentifierCreator::default();
    identifier_creator
        .expect_get_or_create_remote_identifier()
        .withf(
            move |org_id, details, name, autogenerated, _translations, _logo| {
                org_id == &organisation_id
                    && matches!(details, IdentifierDetails::Key(k) if *k == expected_jwk)
                    && matches!(name, IdentifierName::Name(n) if n == "my-key")
                    && !autogenerated
            },
        )
        .once()
        .returning(move |_, _, _, _, _, _| {
            Ok((
                returned_clone.clone(),
                RemoteIdentifierRelation::Key(dummy_key()),
            ))
        });

    let service = setup_service(Mocks {
        organisation_repository: org_repo_returning_org(organisation_id),
        identifier_repository: identifier_repo_with_no_name_match(),
        identifier_creator,
        session_provider,
        ..Default::default()
    });

    let result = service
        .create_remote_identifier(CreateRemoteIdentifierRequestDTO {
            key: Some(jwk),
            ..remote_dto(organisation_id, "my-key")
        })
        .await
        .unwrap();

    assert_eq!(result, identifier_id);
}

#[tokio::test]
async fn test_create_remote_key_identifier_duplicate_returns_colliding_id() {
    let session_provider = StaticSessionProvider::new_random();
    let organisation_id = session_provider.0.organisation_id.unwrap();
    let existing_id: shared_types::IdentifierId = Uuid::new_v4().into();
    let jwk = full_field_jwk();

    let mut existing = dummy_identifier();
    existing.id = existing_id;
    existing.name = "name-set-by-other-request".to_string();
    let existing_clone = existing.clone();

    let mut identifier_creator = MockIdentifierCreator::default();
    identifier_creator
        .expect_get_or_create_remote_identifier()
        .once()
        .returning(move |_, _, _, _, _, _| {
            Ok((
                existing_clone.clone(),
                RemoteIdentifierRelation::Key(dummy_key()),
            ))
        });

    let service = setup_service(Mocks {
        organisation_repository: org_repo_returning_org(organisation_id),
        identifier_repository: identifier_repo_with_no_name_match(),
        identifier_creator,
        session_provider,
        ..Default::default()
    });

    let err = service
        .create_remote_identifier(CreateRemoteIdentifierRequestDTO {
            key: Some(jwk),
            ..remote_dto(organisation_id, "my-key")
        })
        .await
        .unwrap_err();

    assert_eq!(err.error_code(), ErrorCode::BR_0240);
    assert!(matches!(
        err,
        IdentifierServiceError::RemoteIdentifierAlreadyExists(id) if id == existing_id
    ));
}

#[tokio::test]
async fn test_create_remote_certificate_identifier_single_chain_success() {
    let session_provider = StaticSessionProvider::new_random();
    let organisation_id = session_provider.0.organisation_id.unwrap();
    let identifier_id: shared_types::IdentifierId = Uuid::new_v4().into();

    let chain = "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n".to_string();
    let expected_chain = chain.clone();

    let mut identifier_creator = MockIdentifierCreator::default();
    identifier_creator
        .expect_create_remote_certificate_identifier()
        .withf(move |org_id, name, chains, identifier_type| {
            org_id == &organisation_id
                && name == "my-cert"
                && chains.as_slice() == [expected_chain.clone()]
                && *identifier_type == IdentifierType::Certificate
        })
        .once()
        .returning(move |_, _, _, _| Ok(RemoteIdentifierOutcome::Created(identifier_id)));

    let service = setup_service(Mocks {
        organisation_repository: org_repo_returning_org(organisation_id),
        identifier_repository: identifier_repo_with_no_name_match(),
        identifier_creator,
        session_provider,
        ..Default::default()
    });

    let result = service
        .create_remote_identifier(CreateRemoteIdentifierRequestDTO {
            certificates: Some(vec![CreateRemoteCertificateChainDTO { chain }]),
            ..remote_dto(organisation_id, "my-cert")
        })
        .await
        .unwrap();

    assert_eq!(result, identifier_id);
}

#[tokio::test]
async fn test_create_remote_certificate_identifier_multiple_chains_success() {
    let session_provider = StaticSessionProvider::new_random();
    let organisation_id = session_provider.0.organisation_id.unwrap();
    let identifier_id: shared_types::IdentifierId = Uuid::new_v4().into();

    let chains = vec![
        "-----BEGIN CERTIFICATE-----\nLEAF-1\n-----END CERTIFICATE-----\n".to_string(),
        "-----BEGIN CERTIFICATE-----\nLEAF-2\n-----END CERTIFICATE-----\n".to_string(),
        "-----BEGIN CERTIFICATE-----\nLEAF-3\n-----END CERTIFICATE-----\n".to_string(),
    ];
    let expected_chains = chains.clone();

    let mut identifier_creator = MockIdentifierCreator::default();
    identifier_creator
        .expect_create_remote_certificate_identifier()
        .withf(move |org_id, name, received_chains, identifier_type| {
            org_id == &organisation_id
                && name == "multi-cert"
                && *received_chains == expected_chains
                && *identifier_type == IdentifierType::Certificate
        })
        .once()
        .returning(move |_, _, _, _| Ok(RemoteIdentifierOutcome::Created(identifier_id)));

    let service = setup_service(Mocks {
        organisation_repository: org_repo_returning_org(organisation_id),
        identifier_repository: identifier_repo_with_no_name_match(),
        identifier_creator,
        session_provider,
        ..Default::default()
    });

    let result = service
        .create_remote_identifier(CreateRemoteIdentifierRequestDTO {
            certificates: Some(
                chains
                    .into_iter()
                    .map(|chain| CreateRemoteCertificateChainDTO { chain })
                    .collect(),
            ),
            ..remote_dto(organisation_id, "multi-cert")
        })
        .await
        .unwrap();

    assert_eq!(result, identifier_id);
}

#[tokio::test]
async fn test_create_remote_certificate_identifier_duplicate_returns_colliding_id() {
    let session_provider = StaticSessionProvider::new_random();
    let organisation_id = session_provider.0.organisation_id.unwrap();
    let colliding_id: shared_types::IdentifierId = Uuid::new_v4().into();

    let mut identifier_creator = MockIdentifierCreator::default();
    identifier_creator
        .expect_create_remote_certificate_identifier()
        .withf(|_, _, _, identifier_type| *identifier_type == IdentifierType::Certificate)
        .once()
        .returning(move |_, _, _, _| Ok(RemoteIdentifierOutcome::AlreadyExists(colliding_id)));

    let service = setup_service(Mocks {
        organisation_repository: org_repo_returning_org(organisation_id),
        identifier_repository: identifier_repo_with_no_name_match(),
        identifier_creator,
        session_provider,
        ..Default::default()
    });

    let err = service
        .create_remote_identifier(CreateRemoteIdentifierRequestDTO {
            certificates: Some(vec![CreateRemoteCertificateChainDTO {
                chain: "chain".to_string(),
            }]),
            ..remote_dto(organisation_id, "my-cert")
        })
        .await
        .unwrap_err();

    assert_eq!(err.error_code(), ErrorCode::BR_0240);
    assert!(matches!(
        err,
        IdentifierServiceError::RemoteIdentifierAlreadyExists(id) if id == colliding_id
    ));
}

#[tokio::test]
async fn test_create_remote_ca_identifier_single_chain_success() {
    let session_provider = StaticSessionProvider::new_random();
    let organisation_id = session_provider.0.organisation_id.unwrap();
    let identifier_id: shared_types::IdentifierId = Uuid::new_v4().into();

    let chain = "-----BEGIN CERTIFICATE-----\nROOT-CA\n-----END CERTIFICATE-----\n".to_string();
    let expected_chain = chain.clone();

    let mut identifier_creator = MockIdentifierCreator::default();
    identifier_creator
        .expect_create_remote_certificate_identifier()
        .withf(move |org_id, name, chains, identifier_type| {
            org_id == &organisation_id
                && name == "my-ca"
                && chains.as_slice() == [expected_chain.clone()]
                && *identifier_type == IdentifierType::CertificateAuthority
        })
        .once()
        .returning(move |_, _, _, _| Ok(RemoteIdentifierOutcome::Created(identifier_id)));

    let service = setup_service(Mocks {
        organisation_repository: org_repo_returning_org(organisation_id),
        identifier_repository: identifier_repo_with_no_name_match(),
        identifier_creator,
        session_provider,
        ..Default::default()
    });

    let result = service
        .create_remote_identifier(CreateRemoteIdentifierRequestDTO {
            certificate_authorities: Some(vec![CreateRemoteCertificateChainDTO { chain }]),
            ..remote_dto(organisation_id, "my-ca")
        })
        .await
        .unwrap();

    assert_eq!(result, identifier_id);
}

#[tokio::test]
async fn test_create_remote_ca_identifier_multiple_chains_success() {
    let session_provider = StaticSessionProvider::new_random();
    let organisation_id = session_provider.0.organisation_id.unwrap();
    let identifier_id: shared_types::IdentifierId = Uuid::new_v4().into();

    let chains = vec![
        "-----BEGIN CERTIFICATE-----\nROOT-CA-A\n-----END CERTIFICATE-----\n".to_string(),
        "-----BEGIN CERTIFICATE-----\nROOT-CA-B\n-----END CERTIFICATE-----\n".to_string(),
    ];
    let expected_chains = chains.clone();

    let mut identifier_creator = MockIdentifierCreator::default();
    identifier_creator
        .expect_create_remote_certificate_identifier()
        .withf(move |org_id, name, received_chains, identifier_type| {
            org_id == &organisation_id
                && name == "multi-ca"
                && *received_chains == expected_chains
                && *identifier_type == IdentifierType::CertificateAuthority
        })
        .once()
        .returning(move |_, _, _, _| Ok(RemoteIdentifierOutcome::Created(identifier_id)));

    let service = setup_service(Mocks {
        organisation_repository: org_repo_returning_org(organisation_id),
        identifier_repository: identifier_repo_with_no_name_match(),
        identifier_creator,
        session_provider,
        ..Default::default()
    });

    let result = service
        .create_remote_identifier(CreateRemoteIdentifierRequestDTO {
            certificate_authorities: Some(
                chains
                    .into_iter()
                    .map(|chain| CreateRemoteCertificateChainDTO { chain })
                    .collect(),
            ),
            ..remote_dto(organisation_id, "multi-ca")
        })
        .await
        .unwrap();

    assert_eq!(result, identifier_id);
}

#[tokio::test]
async fn test_create_remote_ca_identifier_duplicate_returns_colliding_id() {
    let session_provider = StaticSessionProvider::new_random();
    let organisation_id = session_provider.0.organisation_id.unwrap();
    let colliding_id: shared_types::IdentifierId = Uuid::new_v4().into();

    let mut identifier_creator = MockIdentifierCreator::default();
    identifier_creator
        .expect_create_remote_certificate_identifier()
        .withf(|_, _, _, identifier_type| *identifier_type == IdentifierType::CertificateAuthority)
        .once()
        .returning(move |_, _, _, _| Ok(RemoteIdentifierOutcome::AlreadyExists(colliding_id)));

    let service = setup_service(Mocks {
        organisation_repository: org_repo_returning_org(organisation_id),
        identifier_repository: identifier_repo_with_no_name_match(),
        identifier_creator,
        session_provider,
        ..Default::default()
    });

    let err = service
        .create_remote_identifier(CreateRemoteIdentifierRequestDTO {
            certificate_authorities: Some(vec![CreateRemoteCertificateChainDTO {
                chain: "chain".to_string(),
            }]),
            ..remote_dto(organisation_id, "my-ca")
        })
        .await
        .unwrap_err();

    assert_eq!(err.error_code(), ErrorCode::BR_0240);
    assert!(matches!(
        err,
        IdentifierServiceError::RemoteIdentifierAlreadyExists(id) if id == colliding_id
    ));
}

#[tokio::test]
async fn test_create_remote_identifier_name_already_taken_returns_colliding_id() {
    let session_provider = StaticSessionProvider::new_random();
    let organisation_id = session_provider.0.organisation_id.unwrap();
    let colliding_id: shared_types::IdentifierId = Uuid::new_v4().into();

    let mut existing = dummy_identifier();
    existing.id = colliding_id;
    existing.name = "taken".to_string();
    let existing_clone = existing.clone();

    let mut identifier_repository = MockIdentifierRepository::default();
    identifier_repository
        .expect_get_identifier_list()
        .once()
        .returning(move |_| {
            Ok(GetIdentifierList {
                values: vec![existing_clone.clone()],
                total_pages: Some(1),
                total_items: Some(1),
            })
        });

    let service = setup_service(Mocks {
        organisation_repository: org_repo_returning_org(organisation_id),
        identifier_repository,
        session_provider,
        ..Default::default()
    });

    let err = service
        .create_remote_identifier(CreateRemoteIdentifierRequestDTO {
            did: Some("did:example:abc".parse().unwrap()),
            ..remote_dto(organisation_id, "taken")
        })
        .await
        .unwrap_err();

    assert_eq!(err.error_code(), ErrorCode::BR_0240);
    assert!(matches!(
        err,
        IdentifierServiceError::RemoteIdentifierAlreadyExists(id) if id == colliding_id
    ));
}

#[tokio::test]
async fn test_update_identifier_not_found_for_deleted() {
    let mut identifier = dummy_identifier();
    identifier.deleted_at = Some(get_dummy_date());
    let identifier_id = identifier.id;

    let mut identifier_repository = MockIdentifierRepository::default();
    identifier_repository
        .expect_get()
        .once()
        .returning(move |_| Ok(identifier.clone()));

    let service = setup_service(Mocks {
        identifier_repository,
        ..Default::default()
    });

    let err = service
        .update_identifier(&identifier_id, PatchIdentifierRequestDTO::default())
        .await
        .unwrap_err();

    assert!(matches!(err, IdentifierServiceError::NotFound(id) if id == identifier_id));
}

#[tokio::test]
async fn test_update_identifier_remote_identifier_fails() {
    let mut identifier = dummy_identifier();
    identifier.is_remote = true;
    let identifier_id = identifier.id;
    let organisation_id = identifier.organisation.id();

    let mut identifier_repository = MockIdentifierRepository::default();
    identifier_repository
        .expect_get()
        .once()
        .returning(move |_| Ok(identifier.clone()));

    let service = setup_service(Mocks {
        identifier_repository,
        session_provider: StaticSessionProvider::new_with_org(organisation_id),
        ..Default::default()
    });

    let err = service
        .update_identifier(&identifier_id, PatchIdentifierRequestDTO::default())
        .await
        .unwrap_err();

    assert_eq!(err.error_code(), ErrorCode::BR_0513);
}

#[tokio::test]
async fn test_update_identifier_key_on_non_key_identifier_fails() {
    let identifier = dummy_identifier();
    let identifier_id = identifier.id;
    let organisation_id = identifier.organisation.id();

    let mut identifier_repository = MockIdentifierRepository::default();
    identifier_repository
        .expect_get()
        .once()
        .returning(move |_| Ok(identifier.clone()));

    let service = setup_service(Mocks {
        identifier_repository,
        session_provider: StaticSessionProvider::new_with_org(organisation_id),
        ..Default::default()
    });

    let err = service
        .update_identifier(
            &identifier_id,
            PatchIdentifierRequestDTO {
                key: Some(CreateIdentifierKeyRequestDTO {
                    key_id: Uuid::new_v4().into(),
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();

    assert_eq!(err.error_code(), ErrorCode::BR_0513);
    assert!(matches!(
        err,
        IdentifierServiceError::InvalidUpdateForIdentifierType {
            attribute: "key",
            ..
        }
    ));
}

#[tokio::test]
async fn test_update_identifier_remote_key_fails() {
    let mut identifier = dummy_identifier();
    identifier.data = IdentifierData::Key(dummy_key().into());
    let identifier_id = identifier.id;
    let organisation_id = identifier.organisation.id();

    let remote_key = dummy_key(); // key_reference: None => is_remote() == true
    let key_id = remote_key.id;

    let mut identifier_repository = MockIdentifierRepository::default();
    identifier_repository
        .expect_get()
        .once()
        .returning(move |_| Ok(identifier.clone()));

    let mut key_repository = MockKeyRepository::default();
    key_repository
        .expect_get_key()
        .once()
        .returning(move |_| Ok(remote_key.clone()));

    let service = setup_service(Mocks {
        identifier_repository,
        key_repository,
        session_provider: StaticSessionProvider::new_with_org(organisation_id),
        ..Default::default()
    });

    let err = service
        .update_identifier(
            &identifier_id,
            PatchIdentifierRequestDTO {
                key: Some(CreateIdentifierKeyRequestDTO { key_id }),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();

    assert_eq!(err.error_code(), ErrorCode::BR_0076);
    assert!(matches!(err, IdentifierServiceError::KeyMustNotBeRemote(_)));
}

#[tokio::test]
async fn test_update_identifier_logo_updates_existing_blob_in_place() {
    let existing_blob_id = Uuid::new_v4().into();
    let mut identifier = dummy_identifier();
    identifier.logo = Some(existing_blob_id);
    let identifier_id = identifier.id;
    let organisation_id = identifier.organisation.id();

    let mut identifier_repository = MockIdentifierRepository::default();
    identifier_repository
        .expect_get()
        .once()
        .returning(move |_| Ok(identifier.clone()));
    identifier_repository
        .expect_update()
        .once()
        .withf(|_, request| request.logo.is_none() && request.key_id.is_none())
        .returning(|_, _| Ok(()));

    let mut blob_storage = MockBlobStorage::default();
    blob_storage
        .expect_update()
        .once()
        .withf(move |id, update| {
            *id == existing_blob_id && update.value.as_deref() == Some(b"base64logo".as_slice())
        })
        .returning(|_, _| Ok(()));
    let blob_storage: Arc<dyn crate::provider::blob_storage::BlobStorage> = Arc::new(blob_storage);
    let mut blob_storage_provider = MockBlobStorageProvider::default();
    blob_storage_provider
        .expect_get_blob_storage()
        .once()
        .returning(move |_| Ok(blob_storage.clone()));

    let mut trust_list_regenerator = MockTrustListRegenerator::new();
    trust_list_regenerator
        .expect_regenerate_for_identifier()
        .with(mockall::predicate::eq(identifier_id))
        .once()
        .returning(|_| Ok(()));

    let service = setup_service(Mocks {
        trust_list_regenerator: Some(trust_list_regenerator),
        identifier_repository,
        blob_storage_provider,
        session_provider: StaticSessionProvider::new_with_org(organisation_id),
        ..Default::default()
    });

    service
        .update_identifier(
            &identifier_id,
            PatchIdentifierRequestDTO {
                logo: Some(Some(crate::service::common_dto::BoundedB64Image(
                    "base64logo".to_string(),
                ))),
                ..Default::default()
            },
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn test_update_identifier_logo_null_removes_blob() {
    let existing_blob_id = Uuid::new_v4().into();
    let mut identifier = dummy_identifier();
    identifier.logo = Some(existing_blob_id);
    let identifier_id = identifier.id;
    let organisation_id = identifier.organisation.id();

    let mut identifier_repository = MockIdentifierRepository::default();
    identifier_repository
        .expect_get()
        .once()
        .returning(move |_| Ok(identifier.clone()));
    identifier_repository
        .expect_update()
        .once()
        .withf(|_, request| request.logo == Some(None))
        .returning(|_, _| Ok(()));

    let mut blob_storage = MockBlobStorage::default();
    blob_storage
        .expect_delete()
        .once()
        .withf(move |id| *id == existing_blob_id)
        .returning(|_| Ok(()));
    let blob_storage: Arc<dyn crate::provider::blob_storage::BlobStorage> = Arc::new(blob_storage);
    let mut blob_storage_provider = MockBlobStorageProvider::default();
    blob_storage_provider
        .expect_get_blob_storage()
        .once()
        .returning(move |_| Ok(blob_storage.clone()));

    let service = setup_service(Mocks {
        identifier_repository,
        blob_storage_provider,
        session_provider: StaticSessionProvider::new_with_org(organisation_id),
        ..Default::default()
    });

    service
        .update_identifier(
            &identifier_id,
            PatchIdentifierRequestDTO {
                logo: Some(None),
                ..Default::default()
            },
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn test_update_identifier_translations_null_resets_to_default_name() {
    let mut identifier = dummy_identifier();
    identifier.name = "Original Name".to_string();
    let identifier_id = identifier.id;
    let organisation_id = identifier.organisation.id();

    let mut identifier_repository = MockIdentifierRepository::default();
    identifier_repository
        .expect_get()
        .once()
        .returning(move |_| Ok(identifier.clone()));
    identifier_repository
        .expect_update()
        .once()
        .returning(|_, _| Ok(()));

    let mut localized_text_repository = MockLocalizedTextRepository::default();
    localized_text_repository
        .expect_replace()
        .once()
        .returning(move |_, rows| {
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].lang, "en");
            assert_eq!(rows[0].value, "Original Name");
            assert_eq!(
                rows[0].field,
                crate::model::localized_text::LocalizedTextField::Name
            );
            Ok(())
        });

    let service = setup_service(Mocks {
        identifier_repository,
        localized_text_repository,
        session_provider: StaticSessionProvider::new_with_org(organisation_id),
        ..Default::default()
    });

    service
        .update_identifier(
            &identifier_id,
            PatchIdentifierRequestDTO {
                translations: Some(None),
                ..Default::default()
            },
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn test_update_identifier_logo_creates_blob_when_missing() {
    let identifier = dummy_identifier();
    let identifier_id = identifier.id;
    let organisation_id = identifier.organisation.id();

    let mut identifier_repository = MockIdentifierRepository::default();
    identifier_repository
        .expect_get()
        .once()
        .returning(move |_| Ok(identifier.clone()));

    let new_blob_id = Uuid::new_v4().into();
    let mut identifier_creator = MockIdentifierCreator::default();
    identifier_creator
        .expect_persist_identifier_logo()
        .once()
        .returning(move |_, _| Ok(new_blob_id));

    identifier_repository
        .expect_update()
        .once()
        .withf(move |_, request| {
            request.logo == Some(Some(new_blob_id)) && request.key_id.is_none()
        })
        .returning(|_, _| Ok(()));

    let service = setup_service(Mocks {
        identifier_repository,
        identifier_creator,
        session_provider: StaticSessionProvider::new_with_org(organisation_id),
        ..Default::default()
    });

    service
        .update_identifier(
            &identifier_id,
            PatchIdentifierRequestDTO {
                logo: Some(Some(crate::service::common_dto::BoundedB64Image(
                    "base64logo".to_string(),
                ))),
                ..Default::default()
            },
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn test_update_identifier_translations_replace_with_backfill() {
    let mut identifier = dummy_identifier();
    identifier.name = "Original Name".to_string();
    let identifier_id = identifier.id;
    let organisation_id = identifier.organisation.id();

    let mut identifier_repository = MockIdentifierRepository::default();
    identifier_repository
        .expect_get()
        .once()
        .returning(move |_| Ok(identifier.clone()));
    identifier_repository
        .expect_update()
        .once()
        .returning(|_, _| Ok(()));

    let mut localized_text_repository = MockLocalizedTextRepository::default();
    localized_text_repository
        .expect_replace()
        .once()
        .returning(move |entity_id, rows| {
            let expected_entity_id: EntityId = identifier_id.into();
            assert_eq!(*entity_id, expected_entity_id);
            assert_eq!(rows.len(), 2);
            assert!(rows.iter().any(|r| r.lang == "pl"
                && r.value == "Nazwa"
                && r.field == crate::model::localized_text::LocalizedTextField::Name));
            assert!(rows.iter().any(|r| r.lang == "en"
                && r.value == "Original Name"
                && r.field == crate::model::localized_text::LocalizedTextField::Name));
            Ok(())
        });

    let service = setup_service(Mocks {
        identifier_repository,
        localized_text_repository,
        session_provider: StaticSessionProvider::new_with_org(organisation_id),
        ..Default::default()
    });

    service
        .update_identifier(
            &identifier_id,
            PatchIdentifierRequestDTO {
                translations: Some(Some(
                    crate::service::identifier::dto::IdentifierTranslationsDTO {
                        name: I18nString(std::collections::BTreeMap::from([(
                            "pl".to_string(),
                            "Nazwa".to_string(),
                        )])),
                        logo_alt_text: None,
                    },
                )),
                ..Default::default()
            },
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn test_update_identifier_trust_information_replace() {
    let session_provider = StaticSessionProvider::new_random();
    let organisation_id = session_provider.0.organisation_id.unwrap();

    let identifier_id: shared_types::IdentifierId = Uuid::new_v4().into();
    let mut identifier = dummy_identifier();
    identifier.id = identifier_id;
    identifier.organisation = dummy_organisation(Some(organisation_id)).into();
    identifier.data =
        IdentifierData::Certificate(RelatedVec::from(vec![dummy_certificate(identifier_id)]));

    let mut identifier_repository = MockIdentifierRepository::default();
    identifier_repository
        .expect_get()
        .once()
        .returning(move |_| Ok(identifier.clone()));
    identifier_repository
        .expect_update()
        .once()
        .returning(|_, _| Ok(()));

    let old_blob_id: shared_types::BlobId = Uuid::new_v4().into();
    let mut identifier_trust_information_repository =
        MockIdentifierTrustInformationRepository::default();
    identifier_trust_information_repository
        .expect_get_by_identifier_id()
        .once()
        .returning(move |_| {
            Ok(vec![
                crate::model::identifier_trust_information::IdentifierTrustInformation {
                    id: Uuid::new_v4().into(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    valid_from: None,
                    valid_to: None,
                    intended_use: None,
                    allowed_issuance_types: vec![],
                    allowed_verification_types: vec![],
                    identifier_id,
                    blob_id: old_blob_id,
                },
            ])
        });
    identifier_trust_information_repository
        .expect_delete_by_identifier_id()
        .once()
        .returning(|_| Ok(()));
    identifier_trust_information_repository
        .expect_create()
        .once()
        .returning(|_| Ok(Uuid::new_v4().into()));

    let mut blob_storage = MockBlobStorage::default();
    blob_storage
        .expect_delete()
        .once()
        .withf(move |id| *id == old_blob_id)
        .returning(|_| Ok(()));
    blob_storage.expect_create().once().returning(|_| Ok(()));
    let blob_storage: Arc<dyn crate::provider::blob_storage::BlobStorage> = Arc::new(blob_storage);
    let mut blob_storage_provider = MockBlobStorageProvider::default();
    blob_storage_provider
        .expect_get_blob_storage()
        .times(2)
        .returning(move |_| Ok(blob_storage.clone()));

    let mut ecosystem_provider = MockEcosystemDirectory::new();
    ecosystem_provider
        .expect_enabled_ecosystems()
        .returning(|| {
            vec![Arc::new(ecosystem_accepting_trust_information("EUDI")) as Arc<dyn Ecosystem>]
        });

    let service = setup_service(Mocks {
        identifier_repository,
        identifier_trust_information_repository,
        blob_storage_provider,
        session_provider,
        ecosystem_provider,
        ..Default::default()
    });

    service
        .update_identifier(
            &identifier_id,
            PatchIdentifierRequestDTO {
                trust_information: Some(vec![CreateIdentifierTrustInformationRequestDTO {
                    data: "dummy reg cert".to_string(),
                    r#type: IdentifierTrustInformationType::RegistrationCertificate,
                }]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn test_update_identifier_empty_request_only_bumps() {
    let identifier = dummy_identifier();
    let identifier_id = identifier.id;
    let organisation_id = identifier.organisation.id();

    let mut identifier_repository = MockIdentifierRepository::default();
    identifier_repository
        .expect_get()
        .once()
        .returning(move |_| Ok(identifier.clone()));
    identifier_repository
        .expect_update()
        .once()
        .withf(|_, request| {
            *request == crate::model::identifier::UpdateIdentifierRequest::default()
        })
        .returning(|_, _| Ok(()));

    let service = setup_service(Mocks {
        identifier_repository,
        session_provider: StaticSessionProvider::new_with_org(organisation_id),
        ..Default::default()
    });

    service
        .update_identifier(&identifier_id, PatchIdentifierRequestDTO::default())
        .await
        .unwrap();
}

fn certificate_identifier(
    identifier_id: shared_types::IdentifierId,
    organisation: crate::model::organisation::Organisation,
    certificates: Vec<Certificate>,
) -> Identifier {
    let mut identifier = dummy_identifier();
    identifier.id = identifier_id;
    identifier.organisation = organisation.into();
    identifier.data = IdentifierData::Certificate(RelatedVec::from(certificates));
    identifier
}

fn ca_identifier(
    identifier_id: shared_types::IdentifierId,
    organisation: crate::model::organisation::Organisation,
    certificates: Vec<Certificate>,
) -> Identifier {
    let mut identifier = dummy_identifier();
    identifier.id = identifier_id;
    identifier.organisation = organisation.into();
    identifier.data = IdentifierData::CertificateAuthority(RelatedVec::from(certificates));
    identifier
}

#[tokio::test]
async fn test_add_certificates_happy_path() {
    let identifier_id: shared_types::IdentifierId = Uuid::new_v4().into();
    let organisation = dummy_organisation(None);
    let identifier = certificate_identifier(identifier_id, organisation.clone(), vec![]);
    let new_cert = dummy_certificate(identifier_id);
    let new_cert_id = new_cert.id;

    let mut identifier_repository = MockIdentifierRepository::default();
    let returned = identifier.clone();
    identifier_repository
        .expect_get()
        .returning(move |_| Ok(returned.clone()));
    identifier_repository
        .expect_update()
        .once()
        .withf(|_, request| request.state.is_none())
        .returning(|_, _| Ok(()));

    let mut certificate_repository = MockCertificateRepository::default();
    certificate_repository
        .expect_create()
        .once()
        .returning(move |_| Ok(new_cert_id));

    let mut identifier_creator = MockIdentifierCreator::default();
    let cert_clone = new_cert.clone();
    identifier_creator
        .expect_prepare_certificates()
        .once()
        .returning(move |_, _| Ok(vec![cert_clone.clone()]));

    let mut trust_list_regenerator = MockTrustListRegenerator::new();
    trust_list_regenerator
        .expect_regenerate_for_identifier()
        .with(mockall::predicate::eq(identifier_id))
        .once()
        .returning(|_| Ok(()));

    let service = setup_service(Mocks {
        trust_list_regenerator: Some(trust_list_regenerator),
        identifier_repository,
        certificate_repository,
        identifier_creator,
        session_provider: StaticSessionProvider::new_with_org(organisation.id),
        ..Default::default()
    });

    let ids = service
        .add_certificates(&identifier_id, vec![])
        .await
        .unwrap();

    assert_eq!(ids, vec![new_cert_id]);
}

#[tokio::test]
async fn test_add_certificates_reactivates_deactivated_identifier() {
    let identifier_id: shared_types::IdentifierId = Uuid::new_v4().into();
    let organisation = dummy_organisation(None);
    let mut identifier = certificate_identifier(identifier_id, organisation.clone(), vec![]);
    identifier.state = crate::model::identifier::IdentifierState::Deactivated;

    let new_cert = dummy_certificate(identifier_id);
    let new_cert_id = new_cert.id;

    let mut identifier_repository = MockIdentifierRepository::default();
    let returned = identifier.clone();
    identifier_repository
        .expect_get()
        .returning(move |_| Ok(returned.clone()));
    identifier_repository
        .expect_update()
        .once()
        .withf(|_, request| {
            request.state == Some(crate::model::identifier::IdentifierState::Active)
        })
        .returning(|_, _| Ok(()));

    let mut certificate_repository = MockCertificateRepository::default();
    certificate_repository
        .expect_create()
        .once()
        .returning(move |_| Ok(new_cert_id));

    let mut identifier_creator = MockIdentifierCreator::default();
    let cert_clone = new_cert.clone();
    identifier_creator
        .expect_prepare_certificates()
        .once()
        .returning(move |_, _| Ok(vec![cert_clone.clone()]));

    let service = setup_service(Mocks {
        identifier_repository,
        certificate_repository,
        identifier_creator,
        session_provider: StaticSessionProvider::new_with_org(organisation.id),
        ..Default::default()
    });

    service
        .add_certificates(&identifier_id, vec![])
        .await
        .unwrap();
}

#[tokio::test]
async fn test_add_certificates_wrong_identifier_type() {
    let identifier_id: shared_types::IdentifierId = Uuid::new_v4().into();
    let organisation = dummy_organisation(None);
    let mut identifier = dummy_identifier();
    identifier.id = identifier_id;
    identifier.organisation = organisation.clone().into();
    // dummy_identifier() defaults to a DID identifier

    let mut identifier_repository = MockIdentifierRepository::default();
    let returned = identifier.clone();
    identifier_repository
        .expect_get()
        .returning(move |_| Ok(returned.clone()));

    let service = setup_service(Mocks {
        identifier_repository,
        session_provider: StaticSessionProvider::new_with_org(organisation.id),
        ..Default::default()
    });

    let err = service
        .add_certificates(&identifier_id, vec![])
        .await
        .unwrap_err();

    assert_eq!(err.error_code(), ErrorCode::BR_0514);
}

#[tokio::test]
async fn test_add_certificate_authorities_wrong_identifier_type() {
    let identifier_id: shared_types::IdentifierId = Uuid::new_v4().into();
    let organisation = dummy_organisation(None);
    let identifier = certificate_identifier(identifier_id, organisation.clone(), vec![]);

    let mut identifier_repository = MockIdentifierRepository::default();
    let returned = identifier.clone();
    identifier_repository
        .expect_get()
        .returning(move |_| Ok(returned.clone()));

    let service = setup_service(Mocks {
        identifier_repository,
        session_provider: StaticSessionProvider::new_with_org(organisation.id),
        ..Default::default()
    });

    let err = service
        .add_certificate_authorities(&identifier_id, vec![])
        .await
        .unwrap_err();

    assert_eq!(err.error_code(), ErrorCode::BR_0514);
}

#[tokio::test]
async fn test_remove_certificate_happy_path() {
    let identifier_id: shared_types::IdentifierId = Uuid::new_v4().into();
    let organisation = dummy_organisation(None);
    let cert_a = dummy_certificate(identifier_id);
    let mut cert_b = dummy_certificate(identifier_id);
    cert_b.fingerprint = "fingerprint-b".to_string();
    let identifier = certificate_identifier(
        identifier_id,
        organisation.clone(),
        vec![cert_a.clone(), cert_b.clone()],
    );

    let mut identifier_repository = MockIdentifierRepository::default();
    let returned = identifier.clone();
    identifier_repository
        .expect_get()
        .returning(move |_| Ok(returned.clone()));
    identifier_repository
        .expect_update()
        .once()
        .withf(|_, request| {
            *request == crate::model::identifier::UpdateIdentifierRequest::default()
        })
        .returning(|_, _| Ok(()));

    let mut certificate_repository = MockCertificateRepository::default();
    let deleted_id = cert_b.id;
    certificate_repository
        .expect_delete()
        .once()
        .withf(move |cert| cert.id == deleted_id)
        .returning(|_| Ok(()));

    let mut ecosystem_provider = MockEcosystemDirectory::new();
    ecosystem_provider
        .expect_enabled_ecosystems()
        .returning(Vec::new);

    let mut trust_list_regenerator = MockTrustListRegenerator::new();
    trust_list_regenerator
        .expect_regenerate_for_identifier()
        .with(mockall::predicate::eq(identifier_id))
        .once()
        .returning(|_| Ok(()));

    let service = setup_service(Mocks {
        trust_list_regenerator: Some(trust_list_regenerator),
        identifier_repository,
        certificate_repository,
        ecosystem_provider,
        session_provider: StaticSessionProvider::new_with_org(organisation.id),
        ..Default::default()
    });

    service
        .remove_certificate(&identifier_id, &cert_b.id)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_remove_certificate_prunes_orphaned_trust_information() {
    let identifier_id: shared_types::IdentifierId = Uuid::new_v4().into();
    let organisation = dummy_organisation(None);
    let cert_a = dummy_certificate(identifier_id);
    let mut cert_b = dummy_certificate(identifier_id);
    cert_b.fingerprint = "fingerprint-b".to_string();
    let mut identifier = certificate_identifier(
        identifier_id,
        organisation.clone(),
        vec![cert_a.clone(), cert_b.clone()],
    );
    let trust_info_id: shared_types::IdentifierTrustInformationId = Uuid::new_v4().into();
    let blob_id: shared_types::BlobId = Uuid::new_v4().into();
    identifier.trust_information = RelatedVec::from(vec![
        crate::model::identifier_trust_information::IdentifierTrustInformation {
            id: trust_info_id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            valid_from: None,
            valid_to: None,
            intended_use: None,
            allowed_issuance_types: vec![],
            allowed_verification_types: vec![],
            identifier_id,
            blob_id,
        },
    ]);

    let mut identifier_repository = MockIdentifierRepository::default();
    let returned = identifier.clone();
    identifier_repository
        .expect_get()
        .times(2)
        .returning(move |_| Ok(returned.clone()));
    identifier_repository
        .expect_update()
        .once()
        .returning(|_, _| Ok(()));

    let mut certificate_repository = MockCertificateRepository::default();
    certificate_repository
        .expect_delete()
        .once()
        .returning(|_| Ok(()));

    let mut ecosystem_provider = MockEcosystemDirectory::new();
    ecosystem_provider
        .expect_enabled_ecosystems()
        .returning(move || {
            let mut ecosystem = MockEcosystem::new();
            ecosystem
                .expect_config_name()
                .return_const(EcosystemId::from("EUDI"));
            ecosystem
                .expect_orphaned_identifier_trust_information()
                .once()
                .returning(move |_| Ok(vec![trust_info_id]));
            vec![Arc::new(ecosystem) as Arc<dyn Ecosystem>]
        });

    let mut identifier_trust_information_repository =
        MockIdentifierTrustInformationRepository::default();
    identifier_trust_information_repository
        .expect_delete()
        .once()
        .withf(move |id| *id == trust_info_id)
        .returning(|_| Ok(()));

    let mut sequence = mockall::Sequence::new();
    let mut blob_storage = MockBlobStorage::default();
    blob_storage
        .expect_delete_many()
        .once()
        .in_sequence(&mut sequence)
        .withf(move |ids| ids == [blob_id])
        .returning(|_| Ok(()));
    let blob_storage = Arc::new(blob_storage);
    let mut blob_storage_provider = MockBlobStorageProvider::default();
    blob_storage_provider
        .expect_get_blob_storage()
        .once()
        .returning(move |_| Ok(blob_storage.clone()));

    let mut trust_list_regenerator = MockTrustListRegenerator::new();
    trust_list_regenerator
        .expect_regenerate_for_identifier()
        .with(mockall::predicate::eq(identifier_id))
        .once()
        .in_sequence(&mut sequence)
        .returning(|_| Ok(()));

    let service = setup_service(Mocks {
        trust_list_regenerator: Some(trust_list_regenerator),
        identifier_repository,
        certificate_repository,
        ecosystem_provider,
        identifier_trust_information_repository,
        blob_storage_provider,
        session_provider: StaticSessionProvider::new_with_org(organisation.id),
        ..Default::default()
    });

    service
        .remove_certificate(&identifier_id, &cert_b.id)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_remove_last_certificate_fails() {
    let identifier_id: shared_types::IdentifierId = Uuid::new_v4().into();
    let organisation = dummy_organisation(None);
    let cert = dummy_certificate(identifier_id);
    let identifier =
        certificate_identifier(identifier_id, organisation.clone(), vec![cert.clone()]);

    let mut identifier_repository = MockIdentifierRepository::default();
    let returned = identifier.clone();
    identifier_repository
        .expect_get()
        .returning(move |_| Ok(returned.clone()));

    let service = setup_service(Mocks {
        identifier_repository,
        session_provider: StaticSessionProvider::new_with_org(organisation.id),
        ..Default::default()
    });

    let err = service
        .remove_certificate(&identifier_id, &cert.id)
        .await
        .unwrap_err();

    assert_eq!(err.error_code(), ErrorCode::BR_0515);
}

#[tokio::test]
async fn test_remove_certificate_not_belonging_to_identifier() {
    let identifier_id: shared_types::IdentifierId = Uuid::new_v4().into();
    let organisation = dummy_organisation(None);
    let cert_a = dummy_certificate(identifier_id);
    let identifier = certificate_identifier(identifier_id, organisation.clone(), vec![cert_a]);

    let mut identifier_repository = MockIdentifierRepository::default();
    let returned = identifier.clone();
    identifier_repository
        .expect_get()
        .returning(move |_| Ok(returned.clone()));

    let service = setup_service(Mocks {
        identifier_repository,
        session_provider: StaticSessionProvider::new_with_org(organisation.id),
        ..Default::default()
    });

    let foreign_certificate_id: shared_types::CertificateId = Uuid::new_v4().into();
    let err = service
        .remove_certificate(&identifier_id, &foreign_certificate_id)
        .await
        .unwrap_err();

    assert_eq!(err.error_code(), ErrorCode::BR_0223);
}

#[tokio::test]
async fn test_remove_certificate_already_deleted() {
    let identifier_id: shared_types::IdentifierId = Uuid::new_v4().into();
    let organisation = dummy_organisation(None);
    let cert_a = dummy_certificate(identifier_id);
    let mut cert_b = dummy_certificate(identifier_id);
    cert_b.deleted_at = Some(crate::clock::now_utc());
    let identifier = certificate_identifier(
        identifier_id,
        organisation.clone(),
        vec![cert_a.clone(), cert_b.clone()],
    );

    let mut identifier_repository = MockIdentifierRepository::default();
    let returned = identifier.clone();
    identifier_repository
        .expect_get()
        .returning(move |_| Ok(returned.clone()));

    let service = setup_service(Mocks {
        identifier_repository,
        session_provider: StaticSessionProvider::new_with_org(organisation.id),
        ..Default::default()
    });

    let err = service
        .remove_certificate(&identifier_id, &cert_b.id)
        .await
        .unwrap_err();

    assert_eq!(err.error_code(), ErrorCode::BR_0223);
}

#[tokio::test]
async fn test_remove_certificate_wrong_identifier_type() {
    let identifier_id: shared_types::IdentifierId = Uuid::new_v4().into();
    let organisation = dummy_organisation(None);
    let cert_a = dummy_certificate(identifier_id);
    let cert_b = dummy_certificate(identifier_id);
    let identifier = ca_identifier(
        identifier_id,
        organisation.clone(),
        vec![cert_a.clone(), cert_b.clone()],
    );

    let mut identifier_repository = MockIdentifierRepository::default();
    let returned = identifier.clone();
    identifier_repository
        .expect_get()
        .returning(move |_| Ok(returned.clone()));

    let service = setup_service(Mocks {
        identifier_repository,
        session_provider: StaticSessionProvider::new_with_org(organisation.id),
        ..Default::default()
    });

    let err = service
        .remove_certificate(&identifier_id, &cert_a.id)
        .await
        .unwrap_err();

    assert_eq!(err.error_code(), ErrorCode::BR_0514);
}

fn setup_service_for_identifier(identifier: Identifier) -> IdentifierService {
    let organisation_id = identifier.organisation.id();
    let mut identifier_repository = MockIdentifierRepository::new();
    identifier_repository
        .expect_get()
        .once()
        .return_once(move |_| Ok(identifier));

    setup_service(Mocks {
        identifier_repository,
        session_provider: StaticSessionProvider::new_with_org(organisation_id),
        ..Default::default()
    })
}

fn did_keys_request() -> CreateDidRequestKeysDTO {
    let key_id = Uuid::new_v4().into();
    CreateDidRequestKeysDTO {
        authentication: vec![key_id],
        assertion_method: vec![key_id],
        key_agreement: vec![],
        capability_invocation: vec![],
        capability_delegation: vec![],
    }
}

fn patch_did_keys_request() -> PatchIdentifierRequestDTO {
    PatchIdentifierRequestDTO {
        did: Some(PatchIdentifierDidRequestDTO {
            keys: did_keys_request(),
        }),
        ..Default::default()
    }
}

#[tokio::test]
async fn test_update_did_keys_success() {
    let identifier = dummy_identifier();
    let identifier_id = identifier.id;
    let IdentifierData::Did(did) = &identifier.data else {
        panic!("dummy identifier is a DID identifier");
    };
    let did_id = did.id();

    let organisation_id = identifier.organisation.id();
    let mut identifier_repository = MockIdentifierRepository::new();
    identifier_repository
        .expect_get()
        .once()
        .return_once(move |_| Ok(identifier));

    identifier_repository
        .expect_update()
        .once()
        .returning(|_, _| Ok(()));

    let mut identifier_creator = MockIdentifierCreator::new();
    identifier_creator
        .expect_update_local_did_keys()
        .once()
        .withf(move |id, keys| *id == did_id && keys.authentication.len() == 1)
        .returning(|_, _| Ok(()));

    let service = setup_service(Mocks {
        identifier_repository,
        identifier_creator,
        session_provider: StaticSessionProvider::new_with_org(organisation_id),
        ..Default::default()
    });

    service
        .update_identifier(&identifier_id, patch_did_keys_request())
        .await
        .unwrap();
}

#[tokio::test]
async fn test_update_did_keys_fails_for_non_did_identifier() {
    let identifier = Identifier {
        data: IdentifierData::Key(dummy_key().into()),
        ..dummy_identifier()
    };
    let identifier_id = identifier.id;
    let service = setup_service_for_identifier(identifier);

    let error = service
        .update_identifier(&identifier_id, patch_did_keys_request())
        .await
        .unwrap_err();

    assert_eq!(error.error_code(), ErrorCode::BR_0513);
    assert!(matches!(
        error,
        IdentifierServiceError::InvalidUpdateForIdentifierType {
            attribute: "did",
            ..
        }
    ));
}

#[tokio::test]
async fn test_update_did_keys_fails_for_deactivated_identifier() {
    let identifier = Identifier {
        state: IdentifierState::Deactivated,
        ..dummy_identifier()
    };
    let identifier_id = identifier.id;
    let service = setup_service_for_identifier(identifier);

    let error = service
        .update_identifier(&identifier_id, patch_did_keys_request())
        .await
        .unwrap_err();

    assert_eq!(error.error_code(), ErrorCode::BR_0181);
}

#[tokio::test]
async fn test_update_did_keys_fails_for_remote_identifier() {
    let identifier = Identifier {
        is_remote: true,
        ..dummy_identifier()
    };
    let identifier_id = identifier.id;
    let service = setup_service_for_identifier(identifier);

    let error = service
        .update_identifier(&identifier_id, patch_did_keys_request())
        .await
        .unwrap_err();

    assert_eq!(error.error_code(), ErrorCode::BR_0513);
}

#[tokio::test]
async fn test_update_did_keys_not_found_for_deleted_identifier() {
    let identifier = Identifier {
        deleted_at: Some(get_dummy_date()),
        ..dummy_identifier()
    };
    let identifier_id = identifier.id;
    let service = setup_service_for_identifier(identifier);

    let error = service
        .update_identifier(&identifier_id, patch_did_keys_request())
        .await
        .unwrap_err();

    assert_eq!(error.error_code(), ErrorCode::BR_0207);
}
