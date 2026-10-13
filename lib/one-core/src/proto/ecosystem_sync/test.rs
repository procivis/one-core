use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use mockall::Sequence;
use shared_types::{EcosystemId, TrustCollectionId};
use similar_asserts::assert_eq;
use url::Url;
use uuid::Uuid;

use crate::model::instance::{Instance, InstanceRole, InstanceStatus, WalletProviderType};
use crate::model::list_filter::ListFilterCondition;
use crate::model::organisation::{Organisation, OrganisationConfiguration};
use crate::model::trust_collection::{
    GetTrustCollectionList, TrustCollection, TrustCollectionFilterValue,
};
use crate::proto::ecosystem_sync::{EcosystemSync, EcosystemSyncProto};
use crate::proto::schema_import::MockSchemaImporter;
use crate::proto::transaction_manager::NoTransactionManager;
use crate::proto::trust_collection::MockTrustCollectionManager;
use crate::proto::trust_collection::manager::TrustCollectionManagerImpl;
use crate::proto::trust_list_subscription_sync::{
    MockTrustListSubscriptionSync, TrustListSubscriptionSyncError,
};
use crate::proto::verifier_provider_client::MockVerifierProviderClient;
use crate::proto::wallet_provider_client::MockWalletProviderClient;
use crate::repository::instance_repository::MockInstanceRepository;
use crate::repository::organisation_repository::MockOrganisationRepository;
use crate::repository::trust_collection_repository::MockTrustCollectionRepository;
use crate::service::managed_instance::dto::{
    EcosystemMetadataDTO, EcosystemTrustCollectionDTO, FeatureFlags,
    WalletProviderMetadataResponseDTO, WalletUnitAttestationMetadataDTO,
};
use crate::service::test_utilities::dummy_organisation;
use crate::service::verifier_provider;
use crate::service::verifier_provider::dto::VerifierProviderMetadataResponseDTO;

const ECOSYSTEM: &str = "EUDI";

#[tokio::test]
async fn test_sync_trust_collections_wallet() {
    let instance = dummy_wallet_unit(organisation_selecting(&[ECOSYSTEM]));
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
    let ecosystem_sync = EcosystemSyncProto::new(
        Arc::new(MockInstanceRepository::new()),
        Arc::new(wallet_unit_client),
        Arc::new(MockVerifierProviderClient::new()),
        Arc::new(collection_sync),
        collection_repository,
        Arc::new(subscription_sync),
        Arc::new(permissive_schema_importer()),
    );

    let synced = ecosystem_sync.sync_instance(&instance).await.unwrap();
    assert_eq!(synced, 2);
}

#[tokio::test]
async fn test_sync_trust_collections_verifier() {
    let instance = dummy_verifier_instance(organisation_selecting(&[ECOSYSTEM]));
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
    let ecosystem_sync = EcosystemSyncProto::new(
        Arc::new(MockInstanceRepository::new()),
        Arc::new(MockWalletProviderClient::new()),
        Arc::new(verifier_client),
        Arc::new(collection_sync),
        collection_repository,
        Arc::new(subscription_sync),
        Arc::new(permissive_schema_importer()),
    );

    let synced = ecosystem_sync.sync_instance(&instance).await.unwrap();
    assert_eq!(synced, 2);
}

/// The collections advertised by a provider are always mirrored locally, but without a
/// selected ecosystem none of them is subscribed to.
#[tokio::test]
async fn test_no_selected_ecosystem_mirrors_collections_without_subscribing() {
    let instance = dummy_wallet_unit(organisation_selecting(&[]));

    let collection_to_create_remote = dummy_collection("to be created".to_string());
    let mut wallet_unit_client = MockWalletProviderClient::new();
    wallet_unit_client
        .expect_get_wallet_provider_metadata()
        .once()
        .returning(move |_| {
            Ok(dummy_wallet_provider_metadata(std::slice::from_ref(
                &collection_to_create_remote,
            )))
        });

    let mut collection_repository = MockTrustCollectionRepository::new();
    collection_repository
        .expect_list()
        .once()
        .returning(|_| Ok(GetTrustCollectionList::empty()));
    collection_repository
        .expect_create()
        .once()
        .withf(move |collection| collection.name == "to be created")
        .returning(|collection| Ok(collection.id));
    let collection_repository = Arc::new(collection_repository);
    let collection_sync = TrustCollectionManagerImpl::new(
        collection_repository.clone(),
        Arc::new(MockOrganisationRepository::default()),
        Arc::new(NoTransactionManager),
    );

    let ecosystem_sync = EcosystemSyncProto::new(
        Arc::new(MockInstanceRepository::new()),
        Arc::new(wallet_unit_client),
        Arc::new(MockVerifierProviderClient::new()),
        Arc::new(collection_sync),
        collection_repository,
        // no `expect_sync_subscriptions`: nothing may be subscribed to
        Arc::new(MockTrustListSubscriptionSync::new()),
        Arc::new(permissive_schema_importer()),
    );

    let synced = ecosystem_sync.sync_instance(&instance).await.unwrap();
    assert_eq!(synced, 0);
}

/// A mix of subscribed and unsubscribed collections within one selected ecosystem can
/// only come from the deprecated per-collection selection, which the ecosystem sync
/// must honour rather than silently re-subscribe.
/// TODO (ONE-10972): remove together with the deprecated per-collection selection API.
#[tokio::test]
async fn test_legacy_deselected_collection_is_not_subscribed() {
    let instance = dummy_wallet_unit(organisation_selecting(&[ECOSYSTEM]));

    let selected = dummy_collection("legacy selected".to_string());
    let deselected = dummy_collection("legacy deselected".to_string());
    let selected_id = selected.id;

    let mut wallet_unit_client = MockWalletProviderClient::new();
    let advertised = vec![selected.clone(), deselected.clone()];
    wallet_unit_client
        .expect_get_wallet_provider_metadata()
        .once()
        .returning(move |_| Ok(dummy_wallet_provider_metadata(&advertised)));

    let mut collection_repository = MockTrustCollectionRepository::new();
    let mut seq = Sequence::new();

    // the legacy pre-state: both collections exist, only one is subscribed
    let both = vec![selected.clone(), deselected.clone()];
    collection_repository
        .expect_list()
        .once()
        .returning(move |_| Ok(GetTrustCollectionList::one_page_of(both.clone())))
        .in_sequence(&mut seq);
    let subscribed = selected.clone();
    collection_repository
        .expect_list()
        .once()
        .returning(move |_| Ok(GetTrustCollectionList::one(subscribed.clone())))
        .in_sequence(&mut seq);

    // the manager's own read while mirroring, then the post-sync read
    let both = vec![selected.clone(), deselected.clone()];
    collection_repository
        .expect_list()
        .times(2)
        .returning(move |_| Ok(GetTrustCollectionList::one_page_of(both.clone())))
        .in_sequence(&mut seq);

    let collection_repository = Arc::new(collection_repository);
    let collection_sync = TrustCollectionManagerImpl::new(
        collection_repository.clone(),
        Arc::new(MockOrganisationRepository::default()),
        Arc::new(NoTransactionManager),
    );

    let mut subscription_sync = MockTrustListSubscriptionSync::new();
    subscription_sync
        .expect_sync_subscriptions()
        .once()
        .withf(move |collection| collection.id == selected_id)
        .returning(|_| Ok(()));

    let ecosystem_sync = EcosystemSyncProto::new(
        Arc::new(MockInstanceRepository::new()),
        Arc::new(wallet_unit_client),
        Arc::new(MockVerifierProviderClient::new()),
        Arc::new(collection_sync),
        collection_repository,
        Arc::new(subscription_sync),
        Arc::new(permissive_schema_importer()),
    );

    let synced = ecosystem_sync.sync_instance(&instance).await.unwrap();
    assert_eq!(synced, 1);
}

/// Syncing pulls in the schemas the provider publishes for every ecosystem the
/// organisation selected, and leaves the ones it did not select alone.
#[tokio::test]
async fn test_sync_imports_schemas_of_selected_ecosystems_only() {
    const UNSELECTED_ECOSYSTEM: &str = "UNSELECTED";

    let organisation = organisation_selecting(&[ECOSYSTEM]);
    let instance = dummy_wallet_unit(organisation.clone());

    let mut instance_repository = MockInstanceRepository::new();
    instance_repository
        .expect_get_by_role()
        .once()
        .withf(|role, _| *role == InstanceRole::Wallet)
        .returning(move |_, _| Ok(Some(instance.clone())));
    instance_repository
        .expect_get_by_role()
        .once()
        .withf(|role, _| *role == InstanceRole::Verifier)
        .returning(|_, _| Ok(None));

    let mut wallet_unit_client = MockWalletProviderClient::new();
    wallet_unit_client
        .expect_get_wallet_provider_metadata()
        .once()
        .returning(|_| {
            Ok(WalletProviderMetadataResponseDTO {
                ecosystems: vec![
                    ecosystem_publishing_schemas(ECOSYSTEM, "https://provider.org/selected"),
                    ecosystem_publishing_schemas(
                        UNSELECTED_ECOSYSTEM,
                        "https://provider.org/unselected",
                    ),
                ],
                ..dummy_wallet_provider_metadata(&[])
            })
        });

    let mut collection_manager = MockTrustCollectionManager::new();
    collection_manager
        .expect_sync_remote_trust_collections()
        .once()
        .returning(|_, _, _| Ok(vec![]));

    let mut collection_repository = MockTrustCollectionRepository::new();
    collection_repository
        .expect_list()
        .returning(|_| Ok(GetTrustCollectionList::empty()));

    let mut schema_importer = MockSchemaImporter::new();
    schema_importer
        .expect_import_schemas()
        .once()
        .withf(|credential_schemas, proof_schemas, _| {
            credential_schemas.to_vec() == ["https://provider.org/selected/credential"]
                && proof_schemas.to_vec() == ["https://provider.org/selected/proof"]
        })
        .returning(|_, _, _| ());

    let ecosystem_sync = EcosystemSyncProto::new(
        Arc::new(instance_repository),
        Arc::new(wallet_unit_client),
        Arc::new(MockVerifierProviderClient::new()),
        Arc::new(collection_manager),
        Arc::new(collection_repository),
        // no `expect_sync_subscriptions`: the provider advertises no collection
        Arc::new(MockTrustListSubscriptionSync::new()),
        Arc::new(schema_importer),
    );

    let synced = ecosystem_sync
        .sync_organisation(&organisation)
        .await
        .unwrap();
    assert_eq!(synced, 0);
}

#[tokio::test]
async fn test_collection_failing_to_sync_does_not_stop_the_remaining_ones() {
    let instance = dummy_wallet_unit(organisation_selecting(&[ECOSYSTEM]));
    let collection_to_keep = dummy_collection("to be kept".to_string());
    let collection_to_delete = dummy_collection("to be deleted".to_string());
    let collection_to_create_remote = dummy_collection("to be created".to_string());
    let remote_collection_url = format!(
        "https://wallet-provider.org/ssi/trust-collection/v1/{}",
        collection_to_create_remote.id
    );
    let keep = collection_to_keep.clone();
    let mut wallet_unit_client = MockWalletProviderClient::new();
    wallet_unit_client
        .expect_get_wallet_provider_metadata()
        .once()
        .returning(move |_| {
            Ok(dummy_wallet_provider_metadata(&[
                keep.clone(),
                collection_to_create_remote.clone(),
            ]))
        });

    let (collection_repository, _) = setup_collection_repository(
        collection_to_keep,
        collection_to_delete,
        remote_collection_url,
    );
    let mut subscription_sync = MockTrustListSubscriptionSync::new();
    let attempts = Arc::new(AtomicUsize::new(0));
    let attempted = attempts.clone();
    subscription_sync
        .expect_sync_subscriptions()
        .times(2)
        .returning(move |collection| {
            // only the first of the two collections fails
            if attempted.fetch_add(1, Ordering::SeqCst) == 0 {
                return Err(TrustListSubscriptionSyncError::NotRemote(collection.id));
            }
            Ok(())
        });

    let collection_repository = Arc::new(collection_repository);
    let collection_sync = TrustCollectionManagerImpl::new(
        collection_repository.clone(),
        Arc::new(MockOrganisationRepository::default()),
        Arc::new(NoTransactionManager),
    );
    let ecosystem_sync = EcosystemSyncProto::new(
        Arc::new(MockInstanceRepository::new()),
        Arc::new(wallet_unit_client),
        Arc::new(MockVerifierProviderClient::new()),
        Arc::new(collection_sync),
        collection_repository,
        Arc::new(subscription_sync),
        Arc::new(permissive_schema_importer()),
    );

    let synced = ecosystem_sync.sync_instance(&instance).await.unwrap();
    assert_eq!(synced, 1);
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
}

fn setup_mocks(
    collection_to_keep: TrustCollection,
    collection_to_delete: TrustCollection,
    remote_collection_url: String,
) -> (MockTrustCollectionRepository, MockTrustListSubscriptionSync) {
    let id_to_keep = collection_to_keep.id;
    let (collection_repository, id_to_create_local) = setup_collection_repository(
        collection_to_keep,
        collection_to_delete,
        remote_collection_url,
    );

    let mut subscription_sync = MockTrustListSubscriptionSync::new();
    subscription_sync
        .expect_sync_subscriptions()
        .withf(move |collection| collection.id == id_to_create_local || collection.id == id_to_keep)
        .times(2)
        .returning(|_| Ok(()));
    (collection_repository, subscription_sync)
}

/// Mirrors a provider advertising `collection_to_keep` and a collection to be created,
/// while `collection_to_delete` is no longer advertised. Returns the repository along with
/// the id of the collection it creates.
fn setup_collection_repository(
    collection_to_keep: TrustCollection,
    collection_to_delete: TrustCollection,
    remote_collection_url: String,
) -> (MockTrustCollectionRepository, TrustCollectionId) {
    let id_to_delete = collection_to_delete.id;
    let mut seq = Sequence::new();
    let mut collection_repository = MockTrustCollectionRepository::new();

    // the two reads of the legacy per-collection selection: no collection is
    // subscribed yet, so the ecosystem selection governs in full
    let keep = collection_to_keep.clone();
    let delete = collection_to_delete.clone();
    collection_repository
        .expect_list()
        .once()
        .returning(move |_| {
            Ok(GetTrustCollectionList::one_page_of(vec![
                keep.clone(),
                delete.clone(),
            ]))
        })
        .in_sequence(&mut seq);
    collection_repository
        .expect_list()
        .once()
        .returning(|_| Ok(GetTrustCollectionList::empty()))
        .in_sequence(&mut seq);

    let keep = collection_to_keep.clone();
    collection_repository
        .expect_list()
        .once()
        .returning(move |_| {
            Ok(GetTrustCollectionList {
                values: vec![keep.clone(), collection_to_delete.clone()],
                total_pages: Some(1),
                total_items: Some(1),
            })
        })
        .in_sequence(&mut seq);

    let collection_to_create_local = dummy_collection("to be created".to_string());
    let id_to_create_local = collection_to_create_local.id;
    collection_repository
        .expect_list()
        .once()
        // only the collections of the selected ecosystems get subscribed to
        .withf(|query| {
            filtered_ecosystems(query.filtering.as_ref().unwrap())
                == vec![EcosystemId::from(ECOSYSTEM)]
        })
        .returning(move |_| {
            Ok(GetTrustCollectionList {
                values: vec![
                    collection_to_keep.clone(),
                    collection_to_create_local.clone(),
                ],
                total_pages: Some(1),
                total_items: Some(2),
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
                && collection.ecosystem.as_ref() == ECOSYSTEM
                && collection
                    .remote_trust_collection_url
                    .as_ref()
                    .unwrap()
                    .to_string()
                    == remote_collection_url
        })
        .returning(move |collection| Ok(collection.id));
    (collection_repository, id_to_create_local)
}

/// Collects the ecosystems a trust collection list query filters on.
fn filtered_ecosystems(
    condition: &ListFilterCondition<TrustCollectionFilterValue>,
) -> Vec<EcosystemId> {
    match condition {
        ListFilterCondition::And(conditions) | ListFilterCondition::Or(conditions) => {
            conditions.iter().flat_map(filtered_ecosystems).collect()
        }
        ListFilterCondition::Value(TrustCollectionFilterValue::Ecosystems(ecosystems)) => {
            ecosystems.to_owned()
        }
        ListFilterCondition::Value(_) => vec![],
    }
}

fn organisation_selecting(ecosystems: &[&str]) -> Organisation {
    Organisation {
        configuration: OrganisationConfiguration {
            selected_ecosystems: ecosystems.iter().map(|e| EcosystemId::from(*e)).collect(),
            ..Default::default()
        },
        ..dummy_organisation(None)
    }
}

fn dummy_collection(name: String) -> TrustCollection {
    TrustCollection {
        ecosystem: ECOSYSTEM.into(),
        id: Uuid::new_v4().into(),
        name,
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        deactivated_at: None,
        remote_trust_collection_url: Some(Url::parse("https://remote.collection").unwrap()),
        organisation: dummy_organisation(None).into(),
    }
}

fn dummy_wallet_unit(organisation: Organisation) -> Instance {
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
        organisation: organisation.into(),
        authentication_key: None,
        wallet_attestations: Default::default(),
        nonce: None,
        user_nonce: None,
    }
}

fn dummy_verifier_instance(organisation: Organisation) -> Instance {
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
        organisation: organisation.into(),
        authentication_key: None,
        wallet_attestations: Default::default(),
        nonce: None,
        user_nonce: None,
    }
}

/// Advertises all collections within a single ecosystem, mirroring what a provider
/// exposes under `ecosystems`.
fn dummy_ecosystems(collections: &[TrustCollection]) -> Vec<EcosystemMetadataDTO> {
    vec![EcosystemMetadataDTO {
        name: ECOSYSTEM.into(),
        display_name: vec![],
        description: vec![],
        logo: "logo".to_string(),
        default_selected: false,
        trust_collections: collections
            .iter()
            .map(|c| EcosystemTrustCollectionDTO {
                id: c.id,
                name: c.name.clone(),
            })
            .collect(),
        credential_schemas: vec![],
        proof_schemas: vec![],
    }]
}

/// A schema importer accepting whatever the provider advertises, for the tests that are
/// only about trust collection syncing.
fn permissive_schema_importer() -> MockSchemaImporter {
    let mut schema_importer = MockSchemaImporter::new();
    schema_importer
        .expect_import_schemas()
        .returning(|_, _, _| ());
    schema_importer
}

/// An ecosystem publishing one credential and one proof schema under `base_url`.
fn ecosystem_publishing_schemas(name: &str, base_url: &str) -> EcosystemMetadataDTO {
    EcosystemMetadataDTO {
        name: name.into(),
        credential_schemas: vec![format!("{base_url}/credential")],
        proof_schemas: vec![format!("{base_url}/proof")],
        ..dummy_ecosystems(&[]).remove(0)
    }
}

fn dummy_verifier_provider_metadata(
    collections: &[TrustCollection],
) -> VerifierProviderMetadataResponseDTO {
    VerifierProviderMetadataResponseDTO {
        name: "verifier-provider".to_string(),
        app_version: None,
        trust_collections: vec![],
        feature_flags: verifier_provider::dto::FeatureFlags {
            ecosystems_enabled: true,
            access_certificate_provisioning_enabled: false,
            ecosystems_enforcement_enabled: false,
        },
        verifier_app_attestation: WalletUnitAttestationMetadataDTO {
            app_integrity_check_required: false,
            enabled: false,
            required: false,
        },
        user_authentication: None,
        proof_schemas: None,
        credential_schemas: None,
        ecosystems: dummy_ecosystems(collections),
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
        trust_collections: vec![],
        document_signers: vec![],
        feature_flags: FeatureFlags {
            ecosystems_enabled: true,
            refresh_credential_batch_enabled: true,
            document_signing_enabled: false,
            ecosystems_enforcement_enabled: false,
            dc_api_integration_enabled: true,
        },
        user_authentication: None,
        ecosystems: dummy_ecosystems(collections),
    }
}
