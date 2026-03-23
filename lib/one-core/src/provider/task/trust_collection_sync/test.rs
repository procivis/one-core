use std::sync::Arc;

use mockall::Sequence;
use serde_json::json;
use similar_asserts::assert_eq;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::holder_wallet_unit::HolderWalletUnit;
use crate::model::trust_collection::{GetTrustCollectionList, TrustCollection};
use crate::model::wallet_unit::{WalletProviderType, WalletUnitStatus};
use crate::proto::transaction_manager::NoTransactionManager;
use crate::proto::trust_collection::manager::TrustCollectionManagerImpl;
use crate::proto::trust_list_subscription_sync::MockTrustListSubscriptionSync;
use crate::provider::task::Task;
use crate::provider::task::trust_collection_sync::TrustCollectionSyncTask;
use crate::provider::wallet_provider_client::MockWalletProviderClient;
use crate::repository::holder_wallet_unit_repository::MockHolderWalletUnitRepository;
use crate::repository::trust_collection_repository::MockTrustCollectionRepository;
use crate::service::test_utilities::dummy_organisation;
use crate::service::wallet_provider::dto::{
    FeatureFlags, ProviderTrustCollectionDTO, WalletProviderMetadataResponseDTO,
    WalletUnitAttestationMetadataDTO,
};

#[tokio::test]
async fn test_sync_trust_collections() {
    let mut wallet_unit_repository = MockHolderWalletUnitRepository::new();
    wallet_unit_repository
        .expect_get_holder_wallet_unit()
        .once()
        .returning(|_, _| Ok(Some(dummy_wallet_unit())));
    let mut wallet_unit_client = MockWalletProviderClient::new();
    let collection_to_keep = dummy_collection("to be kept".to_string());
    let collection_to_delete = dummy_collection("to be deleted".to_string());
    let collection_to_create_remote = dummy_collection("to be created".to_string());
    let id_to_delete = collection_to_delete.id;
    let id_to_keep = collection_to_keep.id;
    let id_to_create_remote = collection_to_create_remote.id;
    let keep = collection_to_keep.clone();
    let create = collection_to_create_remote.clone();
    wallet_unit_client
        .expect_get_wallet_provider_metadata()
        .once()
        .withf(move |url| {
            url == "https://wallet-provider.org/ssi/wallet-provider/v1/wallet-provider"
        })
        .returning(move |_| Ok(dummy_provider_metadata(&[keep.clone(), create.clone()])));

    let mut seq = Sequence::new();
    let mut collection_repository = MockTrustCollectionRepository::new();
    let keep = collection_to_keep.clone();
    collection_repository
        .expect_list()
        .once()
        .returning(move |_| {
            Ok(GetTrustCollectionList {
                values: vec![keep.clone(), collection_to_delete.clone()],
                total_pages: 1,
                total_items: 1,
            })
        })
        .in_sequence(&mut seq);

    let collection_to_create_local = dummy_collection("to be created".to_string());
    let id_to_create_local = collection_to_create_local.id;
    collection_repository
        .expect_list()
        .once()
        .returning(move |_| {
            Ok(GetTrustCollectionList {
                values: vec![
                    collection_to_keep.clone(),
                    collection_to_create_local.clone(),
                ],
                total_pages: 1,
                total_items: 2,
            })
        })
        .in_sequence(&mut seq);
    collection_repository
        .expect_delete()
        .once()
        .returning(move |id| {
            assert_eq!(id, id_to_delete);
            Ok(())
        });
    collection_repository
        .expect_create()
        .once()
        .withf(move |collection| {
            collection.name == "to be created"
                && collection
                    .remote_trust_collection_url
                    .as_ref()
                    .unwrap()
                    .to_string()
                    == format!(
                        "https://wallet-provider.org/ssi/trust-collection/v1/{id_to_create_remote}"
                    )
        })
        .returning(move |collection| Ok(collection.id));
    let collection_repository = Arc::new(collection_repository);
    let collection_sync = TrustCollectionManagerImpl::new(
        collection_repository.clone(),
        Arc::new(NoTransactionManager),
    );
    let mut subscription_sync = MockTrustListSubscriptionSync::new();
    subscription_sync
        .expect_sync_subscriptions()
        .withf(move |collection| collection.id == id_to_create_local || collection.id == id_to_keep)
        .times(2)
        .returning(|_| Ok(()));

    let task = TrustCollectionSyncTask::new(
        Arc::new(wallet_unit_repository),
        Arc::new(wallet_unit_client),
        Arc::new(collection_sync),
        collection_repository,
        Arc::new(subscription_sync),
    );

    let result = task
        .run(Some(json!({"holderWalletUnitId": Uuid::new_v4()})))
        .await
        .unwrap();
    assert_eq!(result["trustCollectionIds"].as_array().unwrap().len(), 2);
}

fn dummy_collection(name: String) -> TrustCollection {
    TrustCollection {
        id: Uuid::new_v4().into(),
        name,
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        deactivated_at: None,
        remote_trust_collection_url: None,
        organisation_id: Uuid::new_v4().into(),
        organisation: None,
    }
}

fn dummy_wallet_unit() -> HolderWalletUnit {
    let now = OffsetDateTime::now_utc();
    HolderWalletUnit {
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
        wallet_provider_type: WalletProviderType::ProcivisOne,
        wallet_provider_name: "wallet-provider".to_string(),
        wallet_provider_url: "https://wallet-provider.org".to_string(),
        provider_wallet_unit_id: Uuid::new_v4().into(),
        status: WalletUnitStatus::Active,
        organisation: Some(dummy_organisation(None)),
        authentication_key: None,
        wallet_unit_attestations: None,
    }
}

fn dummy_provider_metadata(collections: &[TrustCollection]) -> WalletProviderMetadataResponseDTO {
    WalletProviderMetadataResponseDTO {
        wallet_unit_attestation: WalletUnitAttestationMetadataDTO {
            app_integrity_check_required: false,
            enabled: false,
            required: false,
        },
        name: "dummy provider".to_string(),
        app_version: None,
        trust_collections: collections
            .iter()
            .map(|c| ProviderTrustCollectionDTO {
                id: c.id,
                name: c.name.clone(),
                logo: "logo".to_string(),
                display_name: vec![],
                description: vec![],
            })
            .collect(),
        feature_flags: FeatureFlags {
            trust_ecosystems_enabled: true,
        },
    }
}
