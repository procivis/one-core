use std::sync::Arc;

use one_core::model::certificate::{
    Certificate, CertificateFilterValue, CertificateRole, CertificateState,
    UpdateCertificateRequest,
};
use one_core::model::list_filter::ListFilterValue;
use one_core::repository::certificate_repository::CertificateRepository;
use one_core::repository::error::DataLayerError;
use one_core::repository::key_repository::MockKeyRepository;
use one_core::repository::organisation_repository::MockOrganisationRepository;
use one_core::service::test_utilities::dummy_organisation;
use shared_types::{IdentifierId, OrganisationId};
use similar_asserts::assert_eq;
use uuid::Uuid;

use super::CertificateProvider;
use crate::test_utilities::{
    get_dummy_date, insert_identifier, insert_organisation_to_database,
    setup_test_data_layer_and_connection,
};
use crate::transaction_context::TransactionManagerImpl;

struct TestSetup {
    pub provider: CertificateProvider,
    pub identifier_id: IdentifierId,
    pub organisation_id: OrganisationId,
}

async fn setup() -> TestSetup {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;

    let organisation_id = insert_organisation_to_database(&db, None).await.unwrap();

    let identifier_id = insert_identifier(
        &db,
        "identifier",
        Uuid::new_v4(),
        None,
        organisation_id,
        false,
    )
    .await
    .unwrap();

    TestSetup {
        provider: CertificateProvider {
            db: TransactionManagerImpl::new(db),
            key_repository: Arc::new(MockKeyRepository::default()),
            organisation_repository: Arc::new(MockOrganisationRepository::default()),
        },
        identifier_id,
        organisation_id,
    }
}

#[tokio::test]
async fn test_create_certificate() {
    let setup = setup().await;
    let id = Uuid::new_v4().into();

    let certificate = Certificate {
        id,
        identifier_id: setup.identifier_id,
        organisation: dummy_organisation(Some(setup.organisation_id)).into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        expiry_date: get_dummy_date(),
        name: "test_identifier".to_string(),
        chain: "chain".to_string(),
        fingerprint: "fingerprint".to_string(),
        state: CertificateState::Active,
        roles: vec![],
        key: None,
        deleted_at: None,
    };

    assert_eq!(id, setup.provider.create(certificate).await.unwrap());
}

#[tokio::test]
async fn test_get_certificate() {
    let setup = setup().await;

    let certificate = Certificate {
        id: Uuid::new_v4().into(),
        identifier_id: setup.identifier_id,
        organisation: dummy_organisation(Some(setup.organisation_id)).into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        expiry_date: get_dummy_date(),
        name: "test_identifier".to_string(),
        chain: "chain".to_string(),
        fingerprint: "fingerprint".to_string(),
        state: CertificateState::Active,
        roles: vec![
            CertificateRole::AssertionMethod,
            CertificateRole::Authentication,
        ],
        key: None,
        deleted_at: None,
    };

    setup.provider.create(certificate.clone()).await.unwrap();

    let non_existent_id = Uuid::new_v4().into();
    assert!(matches!(
        setup.provider.get(non_existent_id).await,
        Err(DataLayerError::EntityNotFound { .. })
    ));

    let retrieved = setup.provider.get(certificate.id).await.unwrap();
    assert_eq!(retrieved.id, certificate.id);
    assert_eq!(retrieved.identifier_id, certificate.identifier_id);
    assert_eq!(retrieved.name, certificate.name);
    assert_eq!(retrieved.chain, certificate.chain);
    assert_eq!(retrieved.state, certificate.state);
    assert_eq!(retrieved.expiry_date, certificate.expiry_date);
    assert_eq!(retrieved.roles, certificate.roles);
    assert!(retrieved.key.is_none());
}

#[tokio::test]
async fn test_update_certificate() {
    let setup = setup().await;

    let certificate = Certificate {
        id: Uuid::new_v4().into(),
        identifier_id: setup.identifier_id,
        organisation: dummy_organisation(Some(setup.organisation_id)).into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        expiry_date: get_dummy_date(),
        name: "test_identifier".to_string(),
        chain: "chain".to_string(),
        fingerprint: "fingerprint".to_string(),
        state: CertificateState::Active,
        roles: vec![],
        key: None,
        deleted_at: None,
    };

    setup.provider.create(certificate.clone()).await.unwrap();

    setup
        .provider
        .update(
            &certificate.id,
            UpdateCertificateRequest {
                state: Some(CertificateState::Expired),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let retrieved = setup.provider.get(certificate.id).await.unwrap();

    assert_eq!(retrieved.state, CertificateState::Expired);
}

#[tokio::test]
async fn test_get_returns_soft_deleted_certificate() {
    let setup = setup().await;
    let id: shared_types::CertificateId = Uuid::new_v4().into();
    let certificate = Certificate {
        id,
        identifier_id: setup.identifier_id,
        organisation: dummy_organisation(Some(setup.organisation_id)).into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        expiry_date: get_dummy_date(),
        name: "cert".to_string(),
        chain: "chain".to_string(),
        fingerprint: "fp-get-soft-deleted".to_string(),
        state: CertificateState::Active,
        roles: vec![],
        key: None,
        deleted_at: None,
    };
    setup.provider.create(certificate.clone()).await.unwrap();
    setup.provider.delete(&certificate).await.unwrap();

    let retrieved = setup
        .provider
        .get(id)
        .await
        .expect("soft-deleted certificate should still be retrievable");
    assert_eq!(retrieved.id, id);
    assert!(retrieved.deleted_at.is_some());
}

#[tokio::test]
async fn test_delete_certificate_sets_deleted_at() {
    let setup = setup().await;
    let id = Uuid::new_v4().into();
    let certificate = Certificate {
        id,
        identifier_id: setup.identifier_id,
        organisation: dummy_organisation(Some(setup.organisation_id)).into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        expiry_date: get_dummy_date(),
        name: "cert".to_string(),
        chain: "chain".to_string(),
        fingerprint: "fp-delete".to_string(),
        state: CertificateState::Active,
        roles: vec![],
        key: None,
        deleted_at: None,
    };
    setup.provider.create(certificate.clone()).await.unwrap();

    setup.provider.delete(&certificate).await.unwrap();

    let retrieved = setup
        .provider
        .get(id)
        .await
        .expect("soft-deleted certificate should still be retrievable");
    assert!(retrieved.deleted_at.is_some());
}

#[tokio::test]
async fn test_list_filters_soft_deleted_certificates() {
    use one_core::model::certificate::{CertificateListQuery, SortableCertificateColumn};
    use one_core::model::common::SortDirection;
    use one_core::model::list_query::{ListPagination, ListSorting};

    let setup = setup().await;
    let live_id: shared_types::CertificateId = Uuid::new_v4().into();
    let dead_id: shared_types::CertificateId = Uuid::new_v4().into();

    let mk = |id, fp: &str| Certificate {
        id,
        identifier_id: setup.identifier_id,
        organisation: dummy_organisation(Some(setup.organisation_id)).into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        expiry_date: get_dummy_date(),
        name: fp.to_string(),
        chain: "chain".to_string(),
        fingerprint: fp.to_string(),
        state: CertificateState::Active,
        roles: vec![],
        key: None,
        deleted_at: None,
    };
    let live = mk(live_id, "fp-live");
    let dead = mk(dead_id, "fp-dead");
    setup.provider.create(live.clone()).await.unwrap();
    setup.provider.create(dead.clone()).await.unwrap();

    setup.provider.delete(&dead).await.unwrap();

    let list = setup
        .provider
        .list(CertificateListQuery {
            include_count: true,
            pagination: Some(ListPagination {
                page: 0,
                page_size: 10,
            }),
            sorting: Some(ListSorting {
                column: SortableCertificateColumn::CreatedDate,
                direction: Some(SortDirection::Descending),
            }),
            filtering: Some(CertificateFilterValue::Deleted(false).condition()),
            include: None,
        })
        .await
        .unwrap();

    assert_eq!(list.total_items.unwrap(), 1);
    assert_eq!(list.values[0].id, live_id);
}

#[tokio::test]
async fn test_list_includes_soft_deleted_certificates() {
    use one_core::model::certificate::{CertificateListQuery, SortableCertificateColumn};
    use one_core::model::common::SortDirection;
    use one_core::model::list_query::{ListPagination, ListSorting};

    let setup = setup().await;
    let live_id: shared_types::CertificateId = Uuid::new_v4().into();
    let dead_id: shared_types::CertificateId = Uuid::new_v4().into();

    let mk = |id, fp: &str| Certificate {
        id,
        identifier_id: setup.identifier_id,
        organisation: dummy_organisation(Some(setup.organisation_id)).into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        expiry_date: get_dummy_date(),
        name: fp.to_string(),
        chain: "chain".to_string(),
        fingerprint: fp.to_string(),
        state: CertificateState::Active,
        roles: vec![],
        key: None,
        deleted_at: None,
    };
    let live = mk(live_id, "fp-live");
    let dead = mk(dead_id, "fp-dead");
    setup.provider.create(live.clone()).await.unwrap();
    setup.provider.create(dead.clone()).await.unwrap();

    setup.provider.delete(&dead).await.unwrap();

    let list = setup
        .provider
        .list(CertificateListQuery {
            include_count: true,
            pagination: Some(ListPagination {
                page: 0,
                page_size: 10,
            }),
            sorting: Some(ListSorting {
                column: SortableCertificateColumn::CreatedDate,
                direction: Some(SortDirection::Descending),
            }),
            filtering: None,
            include: None,
        })
        .await
        .unwrap();

    assert_eq!(list.total_items.unwrap(), 2);
}

#[tokio::test]
async fn test_unique_fingerprint_allows_reuse_after_soft_delete() {
    let setup = setup().await;
    let mk = |name: &str, fp: &str| Certificate {
        id: Uuid::new_v4().into(),
        identifier_id: setup.identifier_id,
        organisation: dummy_organisation(Some(setup.organisation_id)).into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        expiry_date: get_dummy_date(),
        name: name.to_string(),
        chain: "chain".to_string(),
        fingerprint: fp.to_string(),
        state: CertificateState::Active,
        roles: vec![],
        key: None,
        deleted_at: None,
    };

    let first = mk("first", "fp-reuse");
    setup.provider.create(first.clone()).await.unwrap();
    setup.provider.delete(&first).await.unwrap();

    let second = mk("second", "fp-reuse");
    setup.provider.create(second).await.unwrap();
}
