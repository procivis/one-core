use std::collections::HashMap;
use std::sync::Arc;

use shared_types::TrustCollectionId;
use similar_asserts::assert_eq;
use standardized_types::etsi_119_475::Credential;
use standardized_types::etsi_119_475::registration_certificate::{
    Payload, Status, SupervisoryAuthority,
};
use standardized_types::jwk::{JwkUse, PublicJwk, PublicJwkEc};
use standardized_types::openid4vp::dcql::{CredentialFormat, SdJwtVcMeta};
use url::Url;
use uuid::Uuid;

use crate::error::{ErrorCode, ErrorCodeMixin};
use crate::model::certificate::Certificate;
use crate::model::identifier::{GetIdentifierList, Identifier, IdentifierData, IdentifierType};
use crate::model::relation::RelatedVec;
use crate::model::trust_collection::{GetTrustCollectionList, TrustCollection};
use crate::model::trust_list_role::TrustListRoleEnum;
use crate::model::trust_list_subscription::{
    GetTrustListSubscriptionList, TrustListSubscription, TrustListSubscriptionState,
};
use crate::proto::identifier_creator::{
    IdentifierName, MockIdentifierCreator, RemoteIdentifierOutcome, RemoteIdentifierRelation,
};
use crate::proto::jwt::model::JWTPayload;
use crate::proto::session_provider::test::StaticSessionProvider;
use crate::proto::transaction_manager::NoTransactionManager;
use crate::proto::wrp_validator::MockWRPValidator;
use crate::proto::wrp_validator::error::WRPValidatorError;
use crate::proto::wrp_validator::model::{AccessCertificateResult, RegistrationCertificateResult};
use crate::provider::blob_storage::MockBlobStorage;
use crate::provider::blob_storage::provider::MockBlobStorageProvider;
use crate::provider::credential_formatter::model::IdentifierDetails;
use crate::provider::ecosystem::directory::MockEcosystemDirectory;
use crate::provider::signer::registration_certificate::model::WRPRegistrationCertificatePayload;
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
use crate::repository::organisation_repository::MockOrganisationRepository;
use crate::repository::proof_schema_repository::MockProofSchemaRepository;
use crate::repository::trust_collection_repository::MockTrustCollectionRepository;
use crate::repository::trust_list_subscription_repository::MockTrustListSubscriptionRepository;
use crate::service::common_dto::ListQueryDTO;
use crate::service::identifier::IdentifierService;
use crate::service::identifier::dto::{
    CertificateRolesMatchMode, CreateIdentifierKeyRequestDTO, CreateIdentifierRequestDTO,
    CreateIdentifierTrustInformationRequestDTO, CreateRemoteCertificateChainDTO,
    CreateRemoteIdentifierRequestDTO, IdentifierFilterParamsDTO, IdentifierTrustInformationType,
    ResolveTrustEntriesRequestDTO,
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
    blob_storage_provider: MockBlobStorageProvider,
    wrp_validator: MockWRPValidator,
    ecosystem_provider: MockEcosystemDirectory,
}

fn setup_service(mocks: Mocks) -> IdentifierService {
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
        blob_storage_provider: Arc::new(mocks.blob_storage_provider),
        config: Arc::new(generic_config().core),
        identifier_creator: Arc::new(mocks.identifier_creator),
        session_provider: Arc::new(mocks.session_provider),
        trust_list_subscriber_provider: Arc::new(mocks.trust_list_subscriber_provider),
        transaction_manager: Arc::new(NoTransactionManager),
        wrp_validator: Arc::new(mocks.wrp_validator),
        ecosystem_provider: Arc::new(mocks.ecosystem_provider),
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
    let organisation_id = Uuid::new_v4().into();
    let trust_collection = TrustCollection {
        ecosystem: "EUDI".into(),
        id: trust_collection_id,
        name: "test trust collection".to_string(),
        created_date: now,
        last_modified: now,
        deactivated_at: None,
        remote_trust_collection_url: None,
        organisation_id,
        organisation: None,
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
            trust_collection_id,
            trust_collection: Some(trust_collection.clone()),
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
    identifier.id = identifier_id;
    identifier.is_remote = true;
    identifier.data = IdentifierData::Certificate(RelatedVec::from(vec![]));

    identifier_repository
        .expect_get_identifier_list()
        .returning(move |_| {
            Ok(GetIdentifierList {
                values: vec![identifier.clone()],
                total_items: 1,
                total_pages: 1,
            })
        });

    let trust_collection_id = Uuid::new_v4().into();
    let (subscription, trust_collection) = dummy_trust_list_subscription(trust_collection_id);

    trust_list_subscription_repository
        .expect_list()
        .returning(move |_| {
            Ok(GetTrustListSubscriptionList {
                values: vec![subscription.clone()],
                total_items: 1,
                total_pages: 1,
            })
        });

    trust_collection_repository
        .expect_list()
        .returning(move |_| {
            Ok(GetTrustCollectionList {
                values: vec![trust_collection.clone()],
                total_items: 1,
                total_pages: 1,
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
async fn test_resolve_trust_entries_filters_local() {
    // given
    let mut identifier_repository = MockIdentifierRepository::default();
    let mut trust_list_subscription_repository = MockTrustListSubscriptionRepository::default();
    let mut trust_collection_repository = MockTrustCollectionRepository::default();
    let mut trust_list_subscriber_provider = MockTrustListSubscriberProvider::default();

    let identifier_id = Uuid::new_v4().into();
    let mut identifier = dummy_identifier();
    identifier.id = identifier_id;
    identifier.is_remote = false; // Local
    identifier.data = IdentifierData::Certificate(RelatedVec::from(vec![]));

    identifier_repository
        .expect_get_identifier_list()
        .returning(move |_| {
            Ok(GetIdentifierList {
                values: vec![identifier.clone()],
                total_items: 1,
                total_pages: 1,
            })
        });

    trust_list_subscription_repository
        .expect_list()
        .returning(move |_| {
            Ok(GetTrustListSubscriptionList {
                values: vec![dummy_trust_list_subscription(Uuid::new_v4().into()).0],
                total_items: 1,
                total_pages: 1,
            })
        });

    trust_collection_repository
        .expect_list()
        .returning(move |_| {
            Ok(GetTrustCollectionList {
                values: vec![],
                total_items: 0,
                total_pages: 0,
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
                total_items: 0,
                total_pages: 0,
            })
        });

    trust_list_subscription_repository
        .expect_list()
        .returning(move |_| {
            Ok(GetTrustListSubscriptionList {
                values: vec![],
                total_items: 0,
                total_pages: 0,
            })
        });

    trust_collection_repository
        .expect_list()
        .returning(move |_| {
            Ok(GetTrustCollectionList {
                values: vec![],
                total_items: 0,
                total_pages: 0,
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
    identifier.id = identifier_id;
    identifier.is_remote = true;
    identifier.data = IdentifierData::Certificate(RelatedVec::from(vec![]));

    identifier_repository
        .expect_get_identifier_list()
        .returning(move |_| {
            Ok(GetIdentifierList {
                values: vec![identifier.clone()],
                total_items: 1,
                total_pages: 1,
            })
        });

    trust_list_subscription_repository
        .expect_list()
        .returning(move |_| {
            Ok(GetTrustListSubscriptionList {
                values: vec![dummy_trust_list_subscription(Uuid::new_v4().into()).0],
                total_items: 1,
                total_pages: 1,
            })
        });

    trust_collection_repository
        .expect_list()
        .returning(move |_| {
            Ok(GetTrustCollectionList {
                values: vec![],
                total_items: 0,
                total_pages: 0,
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
    identifier.id = identifier_id;
    identifier.is_remote = true;
    identifier.data = IdentifierData::Key(dummy_key().into());

    identifier_repository
        .expect_get_identifier_list()
        .returning(move |_| {
            Ok(GetIdentifierList {
                values: vec![identifier.clone()],
                total_items: 1,
                total_pages: 1,
            })
        });

    trust_list_subscription_repository
        .expect_list()
        .returning(move |_| {
            Ok(GetTrustListSubscriptionList {
                values: vec![dummy_trust_list_subscription(Uuid::new_v4().into()).0],
                total_items: 1,
                total_pages: 1,
            })
        });

    trust_collection_repository
        .expect_list()
        .returning(move |_| {
            Ok(GetTrustCollectionList {
                values: vec![],
                total_items: 0,
                total_pages: 0,
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
async fn test_create_identifier_with_trust_information() {
    let session_provider = StaticSessionProvider::new_random();
    let mut organisation_repository = MockOrganisationRepository::default();
    let mut key_repository = MockKeyRepository::default();
    let dummy_key = dummy_key();
    let key_id = dummy_key.id;
    key_repository
        .expect_get_key()
        .returning(move |_| Ok(dummy_key.clone()));
    let mut identifier_creator = MockIdentifierCreator::default();
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

    let organisation_id = session_provider.0.organisation_id.unwrap();
    organisation_repository
        .expect_get_organisation()
        .returning(move |_| Ok(dummy_organisation(Some(organisation_id))));

    let identifier_id = Uuid::new_v4().into();
    let mut identifier = dummy_identifier();
    identifier.data =
        IdentifierData::Certificate(RelatedVec::from(vec![dummy_certificate(identifier_id)]));
    identifier.id = identifier_id;
    identifier.organisation = dummy_organisation(Some(organisation_id)).into();

    identifier_creator
        .expect_create_local_identifier()
        .returning(move |_, _, _| Ok(identifier.clone()));
    let mut wrp_validator = MockWRPValidator::new();
    wrp_validator
        .expect_validate_access_certificate()
        .once()
        .returning(|_, _| {
            Ok(AccessCertificateResult {
                trust_entity: None,
                relying_party_id: "test_wrp".to_string(),
                registry_url: None,
            })
        });
    wrp_validator
        .expect_validate_registration_certificate()
        .once()
        .returning(|_, rp_id, _, _| {
            assert_eq!(rp_id, "test_wrp");
            Ok(RegistrationCertificateResult {
                trust_entity: None,
                payload: dummy_reg_cert(),
            })
        });

    let service = setup_service(Mocks {
        organisation_repository,
        key_repository,
        identifier_creator,
        identifier_trust_information_repository,
        blob_storage_provider,
        session_provider,
        wrp_validator,
        ..Default::default()
    });

    let result = service
        .create_identifier(CreateIdentifierRequestDTO {
            name: "test identifier".to_string(),
            did: None,
            key: Some(CreateIdentifierKeyRequestDTO { key_id }),
            key_id: None,
            certificates: None,
            certificate_authorities: None,
            organisation_id,
            trust_information: vec![CreateIdentifierTrustInformationRequestDTO {
                data: "dummy reg cert".to_string(),
                r#type: IdentifierTrustInformationType::RegistrationCertificate,
            }],
        })
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_create_identifier_with_inconsistent_reg_certs_fails() {
    // given
    let session_provider = StaticSessionProvider::new_random();
    let mut organisation_repository = MockOrganisationRepository::default();
    let mut key_repository = MockKeyRepository::default();
    let dummy_key = dummy_key();
    let key_id = dummy_key.id;
    key_repository
        .expect_get_key()
        .returning(move |_| Ok(dummy_key.clone()));
    let mut identifier_creator = MockIdentifierCreator::default();
    let mut identifier_trust_information_repository =
        MockIdentifierTrustInformationRepository::default();
    // Only the first trust_info item is persisted; the second fails consistency check
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

    let organisation_id = session_provider.0.organisation_id.unwrap();
    organisation_repository
        .expect_get_organisation()
        .returning(move |_| Ok(dummy_organisation(Some(organisation_id))));

    let identifier_id = Uuid::new_v4().into();
    let mut identifier = dummy_identifier();
    identifier.data =
        IdentifierData::Certificate(RelatedVec::from(vec![dummy_certificate(identifier_id)]));
    identifier.id = identifier_id;
    identifier.organisation = dummy_organisation(Some(organisation_id)).into();

    identifier_creator
        .expect_create_local_identifier()
        .returning(move |_, _, _| Ok(identifier.clone()));

    let mut wrp_validator = MockWRPValidator::new();
    wrp_validator
        .expect_validate_access_certificate()
        .once()
        .returning(|_, _| {
            Ok(AccessCertificateResult {
                trust_entity: None,
                relying_party_id: "test_wrp".to_string(),
                registry_url: None,
            })
        });
    wrp_validator
        .expect_validate_registration_certificate()
        .times(2)
        .returning(|_, _, _, _| {
            Ok(RegistrationCertificateResult {
                trust_entity: None,
                payload: dummy_reg_cert(),
            })
        });
    wrp_validator
        .expect_validate_registration_certificates_consistency()
        .once()
        .returning(|_, _| {
            Err(WRPValidatorError::RegistrationCertificateMissmatch {
                field_name: "name".to_string(),
                first_value: "\"RP One\"".to_string(),
                second_value: "\"RP Two\"".to_string(),
            })
        });

    let service = setup_service(Mocks {
        organisation_repository,
        key_repository,
        identifier_creator,
        identifier_trust_information_repository,
        blob_storage_provider,
        session_provider,
        wrp_validator,
        ..Default::default()
    });

    // when
    let result = service
        .create_identifier(CreateIdentifierRequestDTO {
            name: "test identifier".to_string(),
            did: None,
            key: Some(CreateIdentifierKeyRequestDTO { key_id }),
            key_id: None,
            certificates: None,
            certificate_authorities: None,
            organisation_id,
            trust_information: vec![
                CreateIdentifierTrustInformationRequestDTO {
                    data: "first reg cert".to_string(),
                    r#type: IdentifierTrustInformationType::RegistrationCertificate,
                },
                CreateIdentifierTrustInformationRequestDTO {
                    data: "second reg cert".to_string(),
                    r#type: IdentifierTrustInformationType::RegistrationCertificate,
                },
            ],
        })
        .await;

    // then
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0224);
}

fn dummy_reg_cert() -> JWTPayload<Payload> {
    WRPRegistrationCertificatePayload {
        issued_at: None,
        expires_at: None,
        invalid_before: None,
        issuer: None,
        subject: Some("subject".to_string()),
        audience: None,
        jwt_id: None,
        proof_of_possession_key: None,
        custom: Payload {
            name: "".to_string(),
            sub_ln: None,
            sub_gn: None,
            sub_fn: None,
            country: "".to_string(),
            registry_uri: Url::parse("https://example.com").unwrap(),
            service_descriptions: vec![],
            entitlements: vec![],
            privacy_policy: Url::parse("https://example.com").unwrap(),
            info_uri: Url::parse("https://example.com").unwrap(),
            supervisory_authority: SupervisoryAuthority {
                email: "".to_string(),
                phone: "".to_string(),
                uri: "".to_string(),
            },
            policy_id: vec![],
            certificate_policy: Url::parse("https://example.com").unwrap(),
            status: Status {
                status_list: HashMap::new(),
            },
            provides_attestations: Some(vec![Credential {
                format: CredentialFormat::SdJwt(SdJwtVcMeta {
                    vct_values: vec!["https://example.com".to_string()],
                }),
                claim: None,
            }]),
            credentials: Some(vec![Credential {
                format: CredentialFormat::SdJwt(SdJwtVcMeta {
                    vct_values: vec!["https://example2.com".to_string()],
                }),
                claim: None,
            }]),
            purpose: None,
            intended_use_id: Some("intended_use_id".to_string()),
            public_body: None,
            support_uri: Url::parse("https://example.com").unwrap(),
            intermediary: None,
        },
    }
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
            total_pages: 0,
            total_items: 0,
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
        .withf(move |org, details, name| {
            org.id == organisation_id
                && matches!(details, IdentifierDetails::Did(d) if *d == expected_did)
                && matches!(name, IdentifierName::Name(n) if n == "my-did")
        })
        .once()
        .returning(move |_, _, _| {
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
        .returning(move |_, _, _| {
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
        .withf(move |org, details, name| {
            org.id == organisation_id
                && matches!(details, IdentifierDetails::Key(k) if *k == expected_jwk)
                && matches!(name, IdentifierName::Name(n) if n == "my-key")
        })
        .once()
        .returning(move |_, _, _| {
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
        .returning(move |_, _, _| {
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
        .withf(move |org, name, chains, identifier_type| {
            org.id == organisation_id
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
        .withf(move |org, name, received_chains, identifier_type| {
            org.id == organisation_id
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
        .withf(move |org, name, chains, identifier_type| {
            org.id == organisation_id
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
        .withf(move |org, name, received_chains, identifier_type| {
            org.id == organisation_id
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
                total_pages: 1,
                total_items: 1,
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
