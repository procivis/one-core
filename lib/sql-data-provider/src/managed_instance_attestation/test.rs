use one_core::model::managed_instance_attestation::ManagedInstanceAttestation;
use one_core::model::wallet_attestation::AttestationType;
use one_core::repository::managed_instance_attestation_repository::ManagedInstanceAttestationRepository;
use shared_types::{ManagedInstanceAttestationId, ManagedInstanceId};
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::managed_instance_attestation::ManagedInstanceAttestationProvider;
use crate::test_utilities::{
    insert_organisation_to_database, insert_wallet_instance_to_database,
    setup_test_data_layer_and_connection,
};
use crate::transaction_context::TransactionManagerImpl;

#[tokio::test]
async fn test_get_attestation_by_wallet_instance() {
    let test_setup = setup(1).await;
    let provider = test_setup.provider;

    let id: ManagedInstanceAttestationId = Uuid::new_v4().into();
    let now = one_core::clock::now_utc();
    let attested_key = ManagedInstanceAttestation {
        id,
        instance_id: test_setup.wallet_unit_ids[0],
        created_date: now,
        last_modified: now,
        expiration_date: now,
        r#type: AttestationType::KeyAttestation,
        attestation_content_hash: None,
        revocation: None,
    };
    provider
        .create_attestation(attested_key.clone())
        .await
        .unwrap();

    let reloaded = provider
        .get_by_instance_id(&test_setup.wallet_unit_ids[0])
        .await
        .unwrap();
    assert_eq!(reloaded.len(), 1);
    assert_eq!(reloaded[0].id, attested_key.id);
}

struct TestSetup {
    pub provider: ManagedInstanceAttestationProvider,
    pub wallet_unit_ids: Vec<ManagedInstanceId>,
}

async fn setup(n: usize) -> TestSetup {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;

    let organisation_id = insert_organisation_to_database(&db, None).await.unwrap();
    let mut wallet_unit_ids = vec![];
    for i in 0..n {
        let wallet_unit_id =
            insert_wallet_instance_to_database(&db, organisation_id, format!("wallet{i}")).await;
        wallet_unit_ids.push(wallet_unit_id);
    }

    TestSetup {
        provider: ManagedInstanceAttestationProvider {
            db: TransactionManagerImpl::new(db.clone()),
            revocation_list_repository: data_layer.revocation_list_repository.clone(),
        },
        wallet_unit_ids,
    }
}
