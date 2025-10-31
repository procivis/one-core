use one_core::model::holder_wallet_unit::{
    HolderWalletUnit, HolderWalletUnitRelations, UpdateHolderWalletUnitRequest,
};
use one_core::model::key::{Key, KeyRelations};
use one_core::model::organisation::{Organisation, OrganisationRelations};
use one_core::model::wallet_unit::{WalletProviderType, WalletUnitStatus};
use one_core::model::wallet_unit_attestation::{
    WalletUnitAttestation, WalletUnitAttestationRelations,
};
use one_core::repository::holder_wallet_unit_repository::HolderWalletUnitRepository;
use shared_types::HolderWalletUnitId;
use similar_asserts::assert_eq;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::holder_wallet_unit::HolderWalletUnitProvider;
use crate::test_utilities::{
    dummy_organisation, get_dummy_date, insert_key_to_database, insert_organisation_to_database,
    setup_test_data_layer_and_connection,
};
use crate::transaction_context::TransactionManagerImpl;

struct TestSetup {
    pub provider: HolderWalletUnitProvider,
    pub organisation: Organisation,
    pub key: Key,
}

#[tokio::test]
async fn create_holder_wallet_unit_success() {
    let TestSetup {
        provider,
        organisation,
        key,
        ..
    } = setup_empty().await;

    let id = Uuid::new_v4().into();
    let result = provider
        .create_holder_wallet_unit(test_wallet_unit(id, organisation, key).try_into().unwrap())
        .await;

    assert!(result.is_ok());

    let response = result.unwrap();
    assert_eq!(id, response);
}

#[tokio::test]
async fn get_holder_wallet_unit_success() {
    let TestSetup {
        provider,
        organisation,
        key,
        ..
    } = setup_empty().await;

    let id = Uuid::new_v4().into();
    provider
        .create_holder_wallet_unit(test_wallet_unit(id, organisation, key).try_into().unwrap())
        .await
        .unwrap();

    let result = provider
        .get_holder_wallet_unit(&id, &HolderWalletUnitRelations::default())
        .await
        .unwrap()
        .unwrap();

    // no relations
    assert!(result.authentication_key.is_none());
    assert_eq!(result.id, id);
}

#[tokio::test]
async fn update_holder_wallet_unit_success() {
    let TestSetup {
        provider,
        organisation,
        key,
        ..
    } = setup_empty().await;

    let id = Uuid::new_v4().into();
    provider
        .create_holder_wallet_unit(
            test_wallet_unit(id, organisation.clone(), key.clone())
                .try_into()
                .unwrap(),
        )
        .await
        .unwrap();

    let now = OffsetDateTime::now_utc();
    let update_request = UpdateHolderWalletUnitRequest {
        status: Some(WalletUnitStatus::Revoked),
        wallet_unit_attestations: Some(vec![WalletUnitAttestation {
            id: Uuid::new_v4().into(),
            created_date: now,
            last_modified: now,
            expiration_date: now,
            attestation: "dummy attestation".to_string(),
            holder_wallet_unit_id: id,
            revocation_list_url: None,
            revocation_list_index: None,
            attested_key: Some(key.clone()),
        }]),
    };

    provider
        .update_holder_wallet_unit(&id, update_request)
        .await
        .unwrap();

    let reloaded = provider
        .get_holder_wallet_unit(
            &id,
            &HolderWalletUnitRelations {
                wallet_unit_attestations: Some(WalletUnitAttestationRelations {
                    attested_key: Some(KeyRelations::default()),
                }),
                organisation: Some(OrganisationRelations::default()),
                authentication_key: Some(KeyRelations::default()),
            },
        )
        .await
        .unwrap()
        .unwrap();
    assert!(reloaded.wallet_unit_attestations.is_some());
    assert_eq!(reloaded.wallet_unit_attestations.unwrap().len(), 1);
    assert_eq!(reloaded.organisation.unwrap().id, organisation.id);
    assert_eq!(reloaded.authentication_key.unwrap().id, key.id);
}

fn test_wallet_unit(
    id: HolderWalletUnitId,
    organisation: Organisation,
    key: Key,
) -> HolderWalletUnit {
    let now = OffsetDateTime::now_utc();
    HolderWalletUnit {
        id,
        created_date: now,
        last_modified: now,
        status: WalletUnitStatus::Pending,
        wallet_provider_type: WalletProviderType::ProcivisOne,
        wallet_provider_name: "test_name".to_string(),
        wallet_provider_url: "test_url".to_string(),
        organisation: Some(organisation),
        authentication_key: Some(key),
        provider_wallet_unit_id: Uuid::new_v4().into(),
        wallet_unit_attestations: None,
    }
}

async fn setup_empty() -> TestSetup {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;

    let organisation_id = insert_organisation_to_database(&db, None, None)
        .await
        .unwrap();

    let key_id = insert_key_to_database(
        &db,
        "ED25519".to_string(),
        vec![],
        vec![],
        None,
        organisation_id,
    )
    .await
    .unwrap();
    TestSetup {
        provider: HolderWalletUnitProvider {
            db: TransactionManagerImpl::new(db),
            organisation_repository: data_layer.organisation_repository,
            key_repository: data_layer.key_repository,
            wallet_unit_attestation_repository: data_layer.wallet_unit_attestation_repository,
        },
        organisation: dummy_organisation(Some(organisation_id)),
        key: Key {
            id: key_id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            public_key: vec![],
            name: "test_key".to_string(),
            key_reference: Some("private".to_string().bytes().collect()),
            storage_type: "INTERNAL".to_string(),
            key_type: "ED25519".to_string(),
            organisation: None,
        },
    }
}
