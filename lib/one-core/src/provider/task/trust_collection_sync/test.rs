use std::sync::Arc;

use mockall::Sequence;
use serde_json::json;
use similar_asserts::assert_eq;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::holder_wallet_unit::HolderWalletUnit;
use crate::model::trust_collection::{GetTrustCollectionList, TrustCollection};
use crate::model::verifier_instance::VerifierInstance;
use crate::model::wallet_unit::{WalletProviderType, WalletUnitStatus};
use crate::proto::transaction_manager::NoTransactionManager;
use crate::proto::trust_collection::manager::TrustCollectionManagerImpl;
use crate::proto::trust_list_subscription_sync::MockTrustListSubscriptionSync;
use crate::proto::verifier_provider_client::MockVerifierProviderClient;
use crate::proto::wallet_provider_client::MockWalletProviderClient;
use crate::provider::task::Task;
use crate::provider::task::trust_collection_sync::TrustCollectionSyncTask;
use crate::provider::verifier;
use crate::repository::holder_wallet_unit_repository::MockHolderWalletUnitRepository;
use crate::repository::trust_collection_repository::MockTrustCollectionRepository;
use crate::repository::verifier_instance_repository::MockVerifierInstanceRepository;
use crate::service::test_utilities::dummy_organisation;
use crate::service::verifier_provider;
use crate::service::verifier_provider::dto::VerifierProviderMetadataResponseDTO;
use crate::service::wallet_provider::dto::{
    FeatureFlags, ProviderTrustCollectionDTO, WalletProviderMetadataResponseDTO,
    WalletUnitAttestationMetadataDTO,
};

#[tokio::test]
async fn test_sync_trust_collections_wallet() {
    let mut wallet_unit_repository = MockHolderWalletUnitRepository::new();
    wallet_unit_repository
        .expect_get_holder_wallet_unit()
        .once()
        .returning(|_, _| Ok(Some(dummy_wallet_unit())));
    let mut wallet_unit_client = MockWalletProviderClient::new();
    let collection_to_keep = dummy_collection("to be kept".to_string());
    let collection_to_delete = dummy_collection("to be deleted".to_string());
    let collection_to_create_remote = dummy_collection("to be created".to_string());
    let remote_collection_url = format!(
        "https://wallet-provider.org/ssi/trust-collection/v1/{}",
        collection_to_create_remote.id
    );
    let keep = collection_to_keep.clone();
    wallet_unit_client
        .expect_get_wallet_provider_metadata()
        .once()
        .withf(move |url| {
            url == "https://wallet-provider.org/ssi/wallet-provider/v1/wallet-provider"
        })
        .returning(move |_| {
            Ok(dummy_wallet_provider_metadata(&[
                keep.clone(),
                collection_to_create_remote.clone(),
            ]))
        });

    let (collection_repository, subscription_sync) = setup_mocks(
        collection_to_keep,
        collection_to_delete,
        remote_collection_url,
    );
    let collection_repository = Arc::new(collection_repository);
    let collection_sync = TrustCollectionManagerImpl::new(
        collection_repository.clone(),
        Arc::new(NoTransactionManager),
    );
    let task = TrustCollectionSyncTask::new(
        Arc::new(wallet_unit_repository),
        Arc::new(wallet_unit_client),
        Arc::new(MockVerifierInstanceRepository::new()),
        Arc::new(MockVerifierProviderClient::new()),
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

#[tokio::test]
async fn test_sync_trust_collections_verifier() {
    let mut verifier_instance_repository = MockVerifierInstanceRepository::new();
    verifier_instance_repository
        .expect_get()
        .once()
        .returning(|_, _| Ok(Some(dummy_verifier_instance())));
    let mut verifier_client = MockVerifierProviderClient::new();
    let collection_to_keep = dummy_collection("to be kept".to_string());
    let collection_to_delete = dummy_collection("to be deleted".to_string());
    let collection_to_create_remote = dummy_collection("to be created".to_string());
    let remote_collection_url = format!(
        "https://verifier-provider.org/ssi/trust-collection/v1/{}",
        collection_to_create_remote.id
    );
    let keep = collection_to_keep.clone();
    verifier_client
        .expect_get_verifier_provider_metadata()
        .once()
        .withf(move |url| {
            url == "https://verifier-provider.org/ssi/verifier-provider/v1/verifier-provider"
        })
        .returning(move |_| {
            Ok(dummy_verifier_provider_metadata(&[
                keep.clone(),
                collection_to_create_remote.clone(),
            ]))
        });

    let (collection_repository, subscription_sync) = setup_mocks(
        collection_to_keep,
        collection_to_delete,
        remote_collection_url,
    );
    let collection_repository = Arc::new(collection_repository);
    let collection_sync = TrustCollectionManagerImpl::new(
        collection_repository.clone(),
        Arc::new(NoTransactionManager),
    );
    let task = TrustCollectionSyncTask::new(
        Arc::new(MockHolderWalletUnitRepository::new()),
        Arc::new(MockWalletProviderClient::new()),
        Arc::new(verifier_instance_repository),
        Arc::new(verifier_client),
        Arc::new(collection_sync),
        collection_repository,
        Arc::new(subscription_sync),
    );

    let result = task
        .run(Some(json!({"verifierInstanceId": Uuid::new_v4()})))
        .await
        .unwrap();
    assert_eq!(result["trustCollectionIds"].as_array().unwrap().len(), 2);
}

fn setup_mocks(
    collection_to_keep: TrustCollection,
    collection_to_delete: TrustCollection,
    remote_collection_url: String,
) -> (MockTrustCollectionRepository, MockTrustListSubscriptionSync) {
    let id_to_delete = collection_to_delete.id;
    let id_to_keep = collection_to_keep.id;
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
                    == remote_collection_url
        })
        .returning(move |collection| Ok(collection.id));
    let mut subscription_sync = MockTrustListSubscriptionSync::new();
    subscription_sync
        .expect_sync_subscriptions()
        .withf(move |collection| collection.id == id_to_create_local || collection.id == id_to_keep)
        .times(2)
        .returning(|_| Ok(()));
    (collection_repository, subscription_sync)
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

fn dummy_verifier_instance() -> VerifierInstance {
    let now = OffsetDateTime::now_utc();
    VerifierInstance {
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
        provider_type: "provider-type".to_string(),
        provider_name: "verifier-provider".to_string(),
        provider_url: "https://verifier-provider.org".to_string(),
        organisation: Some(dummy_organisation(None)),
    }
}

fn dummy_wallet_provider_metadata(
    collections: &[TrustCollection],
) -> WalletProviderMetadataResponseDTO {
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

fn dummy_verifier_provider_metadata(
    collections: &[TrustCollection],
) -> VerifierProviderMetadataResponseDTO {
    VerifierProviderMetadataResponseDTO {
        verifier_name: "verifier-provider".to_string(),
        app_version: None,
        trust_collections: collections
            .iter()
            .map(|c| verifier_provider::dto::ProviderTrustCollectionDTO {
                id: c.id,
                name: c.name.clone(),
                logo: "logo".to_string(),
                display_name: vec![],
                description: vec![],
            })
            .collect(),
        feature_flags: verifier::model::FeatureFlags {
            trust_ecosystems_enabled: true,
        },
    }
}
