use std::sync::Arc;

use one_core::model::certificate::{Certificate, CertificateState, UpdateCertificateRequest};
use one_core::repository::certificate_repository::CertificateRepository;
use one_core::repository::key_repository::MockKeyRepository;
use one_core::repository::organisation_repository::MockOrganisationRepository;
use shared_types::{IdentifierId, OrganisationId};
use similar_asserts::assert_eq;
use uuid::Uuid;

use super::CertificateProvider;
use crate::test_utilities::{
    get_dummy_date, insert_identifier, insert_organisation_to_database,
    setup_test_data_layer_and_connection,
};

struct TestSetup {
    pub provider: CertificateProvider,
    pub identifier_id: IdentifierId,
    pub organisation_id: OrganisationId,
}

async fn setup() -> TestSetup {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;

    let organisation_id = insert_organisation_to_database(&db, None, None)
        .await
        .unwrap();

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
            db,
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
        organisation_id: Some(setup.organisation_id),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        expiry_date: get_dummy_date(),
        name: "test_identifier".to_string(),
        chain: "chain".to_string(),
        fingerprint: "fingerprint".to_string(),
        state: CertificateState::Active,
        key: None,
    };

    assert_eq!(id, setup.provider.create(certificate).await.unwrap());
}

#[tokio::test]
async fn test_get_certificate() {
    let setup = setup().await;

    let certificate = Certificate {
        id: Uuid::new_v4().into(),
        identifier_id: setup.identifier_id,
        organisation_id: Some(setup.organisation_id),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        expiry_date: get_dummy_date(),
        name: "test_identifier".to_string(),
        chain: "chain".to_string(),
        fingerprint: "fingerprint".to_string(),
        state: CertificateState::Active,
        key: None,
    };

    setup.provider.create(certificate.clone()).await.unwrap();

    let non_existent_id = Uuid::new_v4().into();
    assert!(
        setup
            .provider
            .get(non_existent_id, &Default::default())
            .await
            .unwrap()
            .is_none()
    );

    let retrieved = setup
        .provider
        .get(certificate.id, &Default::default())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retrieved.id, certificate.id);
    assert_eq!(retrieved.identifier_id, certificate.identifier_id);
    assert_eq!(retrieved.name, certificate.name);
    assert_eq!(retrieved.chain, certificate.chain);
    assert_eq!(retrieved.state, certificate.state);
    assert_eq!(retrieved.expiry_date, certificate.expiry_date);
    assert!(retrieved.key.is_none());
}

#[tokio::test]
async fn test_update_certificate() {
    let setup = setup().await;

    let certificate = Certificate {
        id: Uuid::new_v4().into(),
        identifier_id: setup.identifier_id,
        organisation_id: Some(setup.organisation_id),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        expiry_date: get_dummy_date(),
        name: "test_identifier".to_string(),
        chain: "chain".to_string(),
        fingerprint: "fingerprint".to_string(),
        state: CertificateState::Active,
        key: None,
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

    let retrieved = setup
        .provider
        .get(certificate.id, &Default::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(retrieved.state, CertificateState::Expired);
}
