use std::str::FromStr;
use std::sync::Arc;

use mockall::Sequence;
use mockall::predicate::{always, eq};
use shared_types::{DidId, DidValue, TrustAnchorId, TrustEntityId, TrustEntityKey};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::did::{Did, DidType};
use crate::model::organisation::Organisation;
use crate::model::trust_anchor::TrustAnchor;
use crate::model::trust_entity::{TrustEntity, TrustEntityRole, TrustEntityState, TrustEntityType};
use crate::provider::did_method::provider::MockDidMethodProvider;
use crate::provider::http_client::MockHttpClient;
use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
use crate::provider::key_storage::provider::MockKeyProvider;
use crate::provider::trust_management::provider::MockTrustManagementProvider;
use crate::repository::did_repository::MockDidRepository;
use crate::repository::identifier_repository::MockIdentifierRepository;
use crate::repository::organisation_repository::MockOrganisationRepository;
use crate::repository::trust_anchor_repository::MockTrustAnchorRepository;
use crate::repository::trust_entity_repository::MockTrustEntityRepository;
use crate::service::certificate::validator::MockCertificateValidator;
use crate::service::error::{BusinessLogicError, ServiceError};
use crate::service::test_utilities::{dummy_did, get_dummy_date};
use crate::service::trust_entity::TrustEntityService;
use crate::service::trust_entity::dto::CreateTrustEntityRequestDTO;

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
        .expect_get_by_entity_key_and_trust_anchor_id()
        .with(
            eq::<TrustEntityKey>((&generic_did(did_id).did).into()),
            eq(trust_anchor_id),
        )
        .times(1)
        .return_once(|_, _| Ok(None));
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
async fn test_create_trust_entity_failed_only_one_entity_can_be_create_for_one_did() {
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

    let mut seq = Sequence::new();

    let mut trust_entity_repository = MockTrustEntityRepository::default();
    trust_entity_repository
        .expect_get_by_entity_key_and_trust_anchor_id()
        .with(
            eq::<TrustEntityKey>((&generic_did(did_id).did).into()),
            eq(trust_anchor_id),
        )
        .times(1)
        .return_once(|_, _| Ok(None))
        .in_sequence(&mut seq);
    trust_entity_repository
        .expect_get_by_entity_key_and_trust_anchor_id()
        .with(
            eq::<TrustEntityKey>((&generic_did(did_id).did).into()),
            eq(trust_anchor_id),
        )
        .times(1)
        .return_once(|_, _| Ok(Some(generic_trust_entity(Uuid::new_v4().into()))))
        .in_sequence(&mut seq);

    trust_entity_repository
        .expect_create()
        .times(1)
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
