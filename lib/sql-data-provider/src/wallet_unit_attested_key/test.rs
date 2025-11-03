use one_core::model::wallet_unit_attested_key::{
    WalletUnitAttestedKey, WalletUnitAttestedKeyUpsertRequest,
};
use one_core::repository::wallet_unit_attested_key_repository::WalletUnitAttestedKeyRepository;
use shared_types::{WalletUnitAttestedKeyId, WalletUnitId};
use similar_asserts::assert_eq;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::test_utilities::{
    insert_organisation_to_database, insert_wallet_unit_to_database, random_jwk,
    setup_test_data_layer_and_connection,
};
use crate::transaction_context::TransactionManagerImpl;
use crate::wallet_unit_attested_key::WalletUnitAttestedKeyProvider;

#[tokio::test]
async fn test_upsert_wallet_unit_attested_key_success() {
    let test_setup = setup(1).await;
    let provider = test_setup.provider;

    let id: WalletUnitAttestedKeyId = Uuid::new_v4().into();
    let request = WalletUnitAttestedKeyUpsertRequest {
        id,
        wallet_unit_id: test_setup.wallet_unit_ids[0],
        expiration_date: OffsetDateTime::now_utc(),
        public_key_jwk: random_jwk(),
        revocation_list_index: Some(17),
        revocation_list: None,
    };
    provider.upsert_attested_key(request.clone()).await.unwrap();

    let reloaded = provider
        .get_attested_key(&id, &Default::default())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reloaded.wallet_unit_id, request.wallet_unit_id);
    assert_eq!(reloaded.expiration_date, request.expiration_date);
    assert_eq!(reloaded.public_key_jwk, request.public_key_jwk);
    assert_eq!(reloaded.revocation_list, request.revocation_list);
    assert_eq!(
        reloaded.revocation_list_index,
        request.revocation_list_index
    );
}

#[tokio::test]
async fn test_upsert_wallet_unit_attested_key_conflict_success() {
    let test_setup = setup(2).await;
    let provider = test_setup.provider;

    let id: WalletUnitAttestedKeyId = Uuid::new_v4().into();
    let now = OffsetDateTime::now_utc();
    let original_attested_key = WalletUnitAttestedKey {
        id,
        wallet_unit_id: test_setup.wallet_unit_ids[0],
        created_date: now,
        last_modified: now,
        expiration_date: now,
        public_key_jwk: random_jwk(),
        revocation_list_index: Some(17),
        revocation_list: None,
    };
    provider
        .create_attested_key(original_attested_key.clone())
        .await
        .unwrap();

    let request = WalletUnitAttestedKeyUpsertRequest {
        id,
        wallet_unit_id: test_setup.wallet_unit_ids[1],
        expiration_date: OffsetDateTime::now_utc(),
        public_key_jwk: random_jwk(),
        revocation_list_index: Some(42),
        revocation_list: None,
    };
    provider.upsert_attested_key(request.clone()).await.unwrap();

    let reloaded = provider
        .get_attested_key(&id, &Default::default())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reloaded.created_date, original_attested_key.created_date);
    assert_eq!(reloaded.wallet_unit_id, request.wallet_unit_id);
    assert_eq!(reloaded.expiration_date, request.expiration_date);
    assert_eq!(reloaded.public_key_jwk, request.public_key_jwk);
    assert_eq!(reloaded.revocation_list, request.revocation_list);
    assert_eq!(
        reloaded.revocation_list_index,
        request.revocation_list_index
    );
}

#[tokio::test]
async fn test_get_wallet_unit_attested_key_by_wallet_unit() {
    let test_setup = setup(1).await;
    let provider = test_setup.provider;

    let id: WalletUnitAttestedKeyId = Uuid::new_v4().into();
    let now = OffsetDateTime::now_utc();
    let attested_key = WalletUnitAttestedKey {
        id,
        wallet_unit_id: test_setup.wallet_unit_ids[0],
        created_date: now,
        last_modified: now,
        expiration_date: now,
        public_key_jwk: random_jwk(),
        revocation_list_index: Some(17),
        revocation_list: None,
    };
    provider
        .create_attested_key(attested_key.clone())
        .await
        .unwrap();

    let reloaded = provider
        .get_by_wallet_unit_id(&test_setup.wallet_unit_ids[0], &Default::default())
        .await
        .unwrap();
    assert_eq!(reloaded.len(), 1);
    assert_eq!(reloaded[0].id, attested_key.id);
}

struct TestSetup {
    pub provider: WalletUnitAttestedKeyProvider,
    pub wallet_unit_ids: Vec<WalletUnitId>,
}

async fn setup(n: usize) -> TestSetup {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;

    let organisation_id = insert_organisation_to_database(&db, None, None)
        .await
        .unwrap();
    let mut wallet_unit_ids = vec![];
    for i in 0..n {
        let wallet_unit_id =
            insert_wallet_unit_to_database(&db, organisation_id, format!("wallet{i}")).await;
        wallet_unit_ids.push(wallet_unit_id);
    }

    TestSetup {
        provider: WalletUnitAttestedKeyProvider {
            db: TransactionManagerImpl::new(db.clone()),
            revocation_list_repository: data_layer.revocation_list_repository.clone(),
        },
        wallet_unit_ids,
    }
}
