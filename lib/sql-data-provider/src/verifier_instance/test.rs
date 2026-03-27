use one_core::model::organisation::Organisation;
use one_core::model::verifier_instance::VerifierInstance;
use one_core::repository::verifier_instance_repository::VerifierInstanceRepository;
use shared_types::VerifierInstanceId;
use similar_asserts::assert_eq;
use uuid::Uuid;

use super::VerifierInstanceProvider;
use crate::test_utilities::{
    dummy_organisation, insert_organisation_to_database, setup_test_data_layer_and_connection,
};
use crate::transaction_context::TransactionManagerImpl;

struct TestSetup {
    pub provider: VerifierInstanceProvider,
    pub organisation: Organisation,
}

#[tokio::test]
async fn create_verifier_instance_success() {
    let TestSetup {
        provider,
        organisation,
    } = setup_empty().await;

    let id = Uuid::new_v4().into();
    let result = provider
        .create(test_verifier_instance(id, organisation))
        .await;

    assert!(result.is_ok());
    assert_eq!(id, result.unwrap());
}

#[tokio::test]
async fn get_verifier_instance_success() {
    let TestSetup {
        provider,
        organisation,
    } = setup_empty().await;

    let id = Uuid::new_v4().into();
    provider
        .create(test_verifier_instance(id, organisation))
        .await
        .unwrap();

    let result = provider
        .get(&id, &Default::default())
        .await
        .unwrap()
        .unwrap();

    // no relations
    assert!(result.organisation.is_none());
    assert_eq!(result.id, id);
}

#[tokio::test]
async fn get_by_org_id_success() {
    let TestSetup {
        provider,
        organisation,
    } = setup_empty().await;

    let id = Uuid::new_v4().into();
    provider
        .create(test_verifier_instance(id, organisation.clone()))
        .await
        .unwrap();

    let result = provider
        .get_by_org_id(&organisation.id)
        .await
        .unwrap()
        .unwrap();

    // no relations
    assert_eq!(result.id, id);
}

fn test_verifier_instance(id: VerifierInstanceId, organisation: Organisation) -> VerifierInstance {
    let now = one_core::clock::now_utc();
    VerifierInstance {
        id,
        created_date: now,
        last_modified: now,
        provider_type: "test_type".to_string(),
        provider_name: "test_name".to_string(),
        provider_url: "test_url".to_string(),
        organisation: Some(organisation),
    }
}

async fn setup_empty() -> TestSetup {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;

    let organisation_id = insert_organisation_to_database(&db, None, None)
        .await
        .unwrap();

    TestSetup {
        provider: VerifierInstanceProvider {
            db: TransactionManagerImpl::new(db),
            organisation_repository: data_layer.organisation_repository,
        },
        organisation: dummy_organisation(Some(organisation_id)),
    }
}
