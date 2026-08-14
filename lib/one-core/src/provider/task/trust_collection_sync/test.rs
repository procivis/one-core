use std::sync::Arc;

use mockall::Sequence;
use similar_asserts::assert_eq;
use url::Url;
use uuid::Uuid;

use crate::model::common::GetListResponse;
use crate::model::instance::{Instance, InstanceRole, InstanceStatus, WalletProviderType};
use crate::model::trust_collection::{GetTrustCollectionList, TrustCollection};
use crate::proto::transaction_manager::NoTransactionManager;
use crate::proto::trust_collection::manager::TrustCollectionManagerImpl;
use crate::proto::trust_list_subscription_sync::MockTrustListSubscriptionSync;
use crate::proto::verifier_provider_client::MockVerifierProviderClient;
use crate::proto::wallet_provider_client::MockWalletProviderClient;
use crate::provider::task::Task;
use crate::provider::task::trust_collection_sync::TrustCollectionSyncTask;
use crate::repository::instance_repository::MockInstanceRepository;
use crate::repository::organisation_repository::MockOrganisationRepository;
use crate::repository::trust_collection_repository::MockTrustCollectionRepository;
use crate::service::managed_instance::dto::{
    FeatureFlags, ProviderTrustCollectionDTO, WalletProviderMetadataResponseDTO,
    WalletUnitAttestationMetadataDTO,
};
use crate::service::test_utilities::dummy_organisation;
use crate::service::verifier_provider;
use crate::service::verifier_provider::dto::VerifierProviderMetadataResponseDTO;

#[tokio::test]
async fn test_sync_trust_collections_wallet() {
    let mut seq = Sequence::new();
    let mut wallet_instance_repository = MockInstanceRepository::new();
    wallet_instance_repository
        .expect_list()
        .once()
        .returning(|_| Ok(GetListResponse::one(dummy_wallet_unit())))
        .in_sequence(&mut seq);
    wallet_instance_repository
        .expect_list()
        .once()
        .returning(|_| Ok(GetListResponse::empty()))
        .in_sequence(&mut seq);
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
        .withf(|target| {
            target.metadata_url
                == "https://wallet-provider.org/ssi/wallet-provider/v1/wallet-provider"
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
        Arc::new(MockOrganisationRepository::default()),
        Arc::new(NoTransactionManager),
    );
    let task = TrustCollectionSyncTask::new(
        Arc::new(wallet_instance_repository),
        Arc::new(wallet_unit_client),
        Arc::new(MockVerifierProviderClient::new()),
        Arc::new(collection_sync),
        collection_repository,
        Arc::new(subscription_sync),
    );

    let result = task.run(None).await.unwrap();
    assert_eq!(result["syncedTrustCollectionsCount"], 2);
}

#[tokio::test]
async fn test_sync_trust_collections_verifier() {
    let mut seq = Sequence::new();
    let mut wallet_instance_repository = MockInstanceRepository::new();
    wallet_instance_repository
        .expect_list()
        .once()
        .returning(|_| Ok(GetListResponse::one(dummy_verifier_instance())))
        .in_sequence(&mut seq);
    wallet_instance_repository
        .expect_list()
        .once()
        .returning(|_| Ok(GetListResponse::empty()))
        .in_sequence(&mut seq);
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
        Arc::new(MockOrganisationRepository::default()),
        Arc::new(NoTransactionManager),
    );
    let task = TrustCollectionSyncTask::new(
        Arc::new(wallet_instance_repository),
        Arc::new(MockWalletProviderClient::new()),
        Arc::new(verifier_client),
        Arc::new(collection_sync),
        collection_repository,
        Arc::new(subscription_sync),
    );

    let result = task.run(None).await.unwrap();
    assert_eq!(result["syncedTrustCollectionsCount"], 2);
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
        ecosystem: "EUDI".into(),
        id: Uuid::new_v4().into(),
        name,
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        deactivated_at: None,
        remote_trust_collection_url: Some(Url::parse("https://remote.collection").unwrap()),
        organisation: dummy_organisation(None).into(),
    }
}

fn dummy_wallet_unit() -> Instance {
    let now = crate::clock::now_utc();
    Instance {
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
        provider_type: WalletProviderType::ProcivisOne,
        provider_name: "wallet-provider".to_string(),
        provider_url: "https://wallet-provider.org".to_string(),
        provider_instance_id: Uuid::new_v4().into(),
        status: InstanceStatus::Active,
        role: InstanceRole::Wallet,
        organisation: dummy_organisation(None).into(),
        authentication_key: None,
        wallet_unit_attestations: Default::default(),
        nonce: None,
        user_nonce: None,
    }
}

fn dummy_verifier_instance() -> Instance {
    let now = crate::clock::now_utc();
    Instance {
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
        provider_type: WalletProviderType::ProcivisOne,
        provider_name: "verifier-provider".to_string(),
        provider_url: "https://verifier-provider.org".to_string(),
        provider_instance_id: Uuid::new_v4().into(),
        status: InstanceStatus::Active,
        role: InstanceRole::Verifier,
        organisation: dummy_organisation(None).into(),
        authentication_key: None,
        wallet_unit_attestations: Default::default(),
        nonce: None,
        user_nonce: None,
    }
}

fn dummy_verifier_provider_metadata(
    collections: &[TrustCollection],
) -> VerifierProviderMetadataResponseDTO {
    VerifierProviderMetadataResponseDTO {
        name: "verifier-provider".to_string(),
        app_version: None,
        trust_collections: collections
            .iter()
            .map(|c| verifier_provider::dto::ProviderTrustCollectionDTO {
                id: c.id,
                name: c.name.clone(),
                logo: "logo".to_string(),
                display_name: vec![],
                description: vec![],
                default_selected: None,
            })
            .collect(),
        feature_flags: verifier_provider::dto::FeatureFlags {
            trust_ecosystems_enabled: true,
            access_certificate_provisioning_enabled: false,
        },
        verifier_app_attestation: WalletUnitAttestationMetadataDTO {
            app_integrity_check_required: false,
            enabled: false,
            required: false,
        },
        user_authentication: None,
        proof_schemas: None,
        credential_schemas: None,
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
                default_selected: None,
            })
            .collect(),
        document_signers: vec![],
        feature_flags: FeatureFlags {
            trust_ecosystems_enabled: true,
            refresh_credential_batch_enabled: true,
            document_signing_enabled: false,
        },
        user_authentication: None,
    }
}
