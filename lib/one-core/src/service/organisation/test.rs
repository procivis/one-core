use std::sync::Arc;

use mockall::Sequence;
use mockall::predicate::{always, eq};
use serde_json::json;
use shared_types::{EcosystemId, OrganisationId, TrustCollectionId};
use similar_asserts::assert_eq;
use uuid::Uuid;

use super::OrganisationService;
use super::dto::{CreateOrganisationRequestDTO, OrganisationFilterParamsDTO};
use super::error::OrganisationServiceError;
use crate::config::core_config::{
    ConfigEntryDisplay, CoreConfig, EcosystemProviderType, Fields, Params,
};
use crate::error::{ErrorCode, ErrorCodeMixin};
use crate::model::common::GetListResponse;
use crate::model::instance::{
    Instance, InstanceList, InstanceRole, InstanceStatus, WalletProviderType,
};
use crate::model::organisation::{
    GetOrganisationList, Organisation, OrganisationConfiguration, OrganisationListQuery,
};
use crate::model::trust_collection::TrustCollection;
use crate::proto::trust_list_subscription_sync::MockTrustListSubscriptionSync;
use crate::proto::verifier_provider_client::MockVerifierProviderClient;
use crate::proto::wallet_provider_client::MockWalletProviderClient;
use crate::repository::error::{DataLayerError, EntityKind};
use crate::repository::identifier_repository::MockIdentifierRepository;
use crate::repository::instance_repository::MockInstanceRepository;
use crate::repository::organisation_repository::MockOrganisationRepository;
use crate::repository::trust_collection_repository::MockTrustCollectionRepository;
use crate::repository::trust_list_subscription_repository::MockTrustListSubscriptionRepository;
use crate::service::common_dto::ListQueryDTO;
use crate::service::managed_instance::dto::{
    EcosystemMetadataDTO, EcosystemTrustCollectionDTO, FeatureFlags as WalletProviderFeatureFlags,
    ProviderTrustCollectionDTO, WalletProviderMetadataResponseDTO,
    WalletUnitAttestationMetadataDTO,
};
use crate::service::organisation::dto::{TrustCollectionInfoDTO, UpsertOrganisationRequestDTO};
use crate::service::test_utilities::dummy_organisation;
use crate::service::verifier_provider::dto::{
    FeatureFlags as VerifierProviderFeatureFlags, VerifierProviderMetadataResponseDTO,
};

fn setup_service(organisation_repository: MockOrganisationRepository) -> OrganisationService {
    setup_service_with_mocks(organisation_repository, MockInstanceRepository::new())
}

fn setup_service_with_mocks(
    organisation_repository: MockOrganisationRepository,
    holder_wallet_instance_repository: MockInstanceRepository,
) -> OrganisationService {
    OrganisationService {
        organisation_repository: Arc::new(organisation_repository),
        identifier_repository: Arc::new(MockIdentifierRepository::new()),
        instance_repository: Arc::new(holder_wallet_instance_repository),
        wallet_provider_client: Arc::new(MockWalletProviderClient::default()),
        verifier_provider_client: Arc::new(MockVerifierProviderClient::default()),
        trust_list_subscription_sync: Arc::new(MockTrustListSubscriptionSync::default()),
        trust_collection_repository: Arc::new(MockTrustCollectionRepository::default()),
        trust_subscription_repository: Arc::new(MockTrustListSubscriptionRepository::default()),
        core_config: Arc::new(Default::default()),
    }
}

#[tokio::test]
async fn test_create_organisation_id_not_set() {
    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_create_organisation()
        .times(1)
        .returning(|org| Ok(org.id));

    let service = setup_service(organisation_repository);
    let result = service.create_organisation(Default::default()).await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_create_organisation_id_set() {
    let mut sequence = Sequence::new();
    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_create_organisation()
        .times(1)
        .in_sequence(&mut sequence)
        .returning(|org| Ok(org.id));

    let service = setup_service(organisation_repository);
    let id = Uuid::new_v4().into();
    let result = service
        .create_organisation(CreateOrganisationRequestDTO {
            id: Some(id),
            parent_organisation: None,
        })
        .await
        .unwrap();

    assert_eq!(result, id);
}

#[tokio::test]
async fn test_create_organisation_already_exists() {
    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_create_organisation()
        .times(1)
        .returning(|_| Err(DataLayerError::AlreadyExists));

    let service = setup_service(organisation_repository);
    let id = Uuid::new_v4().into();
    let result = service
        .create_organisation(CreateOrganisationRequestDTO {
            id: Some(id),
            parent_organisation: None,
        })
        .await;

    assert!(matches!(
        result,
        Err(OrganisationServiceError::AlreadyExists)
    ));
}

#[tokio::test]
async fn test_get_organisation_success() {
    let mut organisation_repository = MockOrganisationRepository::default();

    let organisation = dummy_organisation(None);
    let org_clone = organisation.clone();
    organisation_repository
        .expect_get_organisation()
        .times(1)
        .with(eq(organisation.id.to_owned()))
        .returning(move |_| Ok(org_clone.clone()));

    let mut instance_repository = MockInstanceRepository::new();
    instance_repository
        .expect_get_by_role()
        .times(2)
        .returning(|_, _| Ok(None));

    let service = setup_service_with_mocks(organisation_repository, instance_repository);
    let result = service.get_organisation(&organisation.id).await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.id, organisation.id);
    assert_eq!(result.created_date, organisation.created_date);
    assert_eq!(result.last_modified, organisation.last_modified);
    assert!(result.wallet_instance.is_none());
    assert!(result.verifier_instance.is_none());
}

#[tokio::test]
async fn test_get_organisation_failure() {
    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation()
        .times(1)
        .returning(|id| {
            Err(DataLayerError::EntityNotFound {
                kind: EntityKind::Organisation,
                id: (*id).into(),
            })
        });

    let service = setup_service(organisation_repository);
    let result = service.get_organisation(&Uuid::new_v4().into()).await;

    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0022);
}

#[tokio::test]
async fn test_get_organisation_list_success() {
    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation_list()
        .times(1)
        .returning(|_: OrganisationListQuery| {
            Ok(GetOrganisationList {
                values: vec![dummy_organisation(None)],
                total_items: 1,
                total_pages: 1,
            })
        });

    let service = setup_service(organisation_repository);
    let result = service
        .get_organisation_list(ListQueryDTO {
            page: 0,
            page_size: 10,
            sort: None,
            sort_direction: None,
            filter: OrganisationFilterParamsDTO::default(),
            include: None,
        })
        .await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.values.len(), 1);
    assert_eq!(result.total_pages, 1);
    assert_eq!(result.total_items, 1);
}

#[tokio::test]
async fn test_get_organisation_list_failure() {
    let mut organisation_repository = MockOrganisationRepository::default();
    organisation_repository
        .expect_get_organisation_list()
        .times(1)
        .returning(|_: OrganisationListQuery| Err(anyhow::anyhow!("TEST").into()));

    let service = setup_service(organisation_repository);
    let result = service
        .get_organisation_list(ListQueryDTO {
            page: 0,
            page_size: 10,
            sort: None,
            sort_direction: None,
            filter: OrganisationFilterParamsDTO::default(),
            include: None,
        })
        .await;

    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0054);
}

fn dummy_instance(
    id: Uuid,
    organisation: crate::model::organisation::Organisation,
    role: InstanceRole,
) -> Instance {
    Instance {
        id: id.into(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        provider_type: WalletProviderType::ProcivisOne,
        provider_name: "PROCIVIS_ONE".to_string(),
        provider_url: "https://provider.example".to_string(),
        provider_instance_id: Uuid::new_v4().into(),
        status: InstanceStatus::Active,
        role,
        nonce: None,
        user_nonce: None,
        organisation: organisation.into(),
        authentication_key: None,
        wallet_unit_attestations: Default::default(),
    }
}

/// An organisation that has selected the given ecosystems.
fn organisation_selecting(id: OrganisationId, ecosystems: &[&str]) -> Organisation {
    Organisation {
        configuration: OrganisationConfiguration {
            selected_ecosystems: ecosystems.iter().map(|e| EcosystemId::from(*e)).collect(),
            ..Default::default()
        },
        ..dummy_organisation(Some(id))
    }
}

/// An ecosystem of the given name, holding one remote trust collection.
fn named_ecosystem(name: &str, collection_name: &str) -> EcosystemMetadataDTO {
    EcosystemMetadataDTO {
        name: name.into(),
        display_name: vec![],
        description: vec![],
        logo: "logo".to_string(),
        default_selected: true,
        trust_collections: vec![EcosystemTrustCollectionDTO {
            id: Uuid::new_v4().into(),
            name: collection_name.to_string(),
        }],
        credential_schemas: vec![],
        proof_schemas: vec![],
    }
}

fn wallet_metadata(
    trust_collections: Vec<ProviderTrustCollectionDTO>,
) -> WalletProviderMetadataResponseDTO {
    WalletProviderMetadataResponseDTO {
        wallet_unit_attestation: WalletUnitAttestationMetadataDTO {
            app_integrity_check_required: false,
            enabled: false,
            required: false,
        },
        name: "PROCIVIS_ONE".to_string(),
        app_version: None,
        trust_collections,
        document_signers: vec![],
        feature_flags: WalletProviderFeatureFlags {
            ecosystems_enabled: true,
            refresh_credential_batch_enabled: true,
            document_signing_enabled: false,
            ecosystems_enforcement_enabled: false,
        },
        user_authentication: None,
        ecosystems: vec![],
    }
}

fn verifier_metadata(
    trust_collections: Vec<ProviderTrustCollectionDTO>,
) -> VerifierProviderMetadataResponseDTO {
    VerifierProviderMetadataResponseDTO {
        name: "PROCIVIS_ONE".to_string(),
        app_version: None,
        trust_collections,
        feature_flags: VerifierProviderFeatureFlags {
            ecosystems_enabled: true,
            access_certificate_provisioning_enabled: false,
            ecosystems_enforcement_enabled: false,
        },
        verifier_app_attestation:
            crate::service::managed_instance::dto::WalletUnitAttestationMetadataDTO {
                app_integrity_check_required: false,
                enabled: false,
                required: false,
            },
        user_authentication: None,
        proof_schemas: None,
        credential_schemas: None,
        ecosystems: vec![],
    }
}

fn wallet_metadata_with_ecosystems(
    ecosystems: Vec<EcosystemMetadataDTO>,
) -> WalletProviderMetadataResponseDTO {
    WalletProviderMetadataResponseDTO {
        ecosystems,
        ..wallet_metadata(vec![])
    }
}

fn verifier_metadata_with_ecosystems(
    ecosystems: Vec<EcosystemMetadataDTO>,
) -> VerifierProviderMetadataResponseDTO {
    VerifierProviderMetadataResponseDTO {
        ecosystems,
        ..verifier_metadata(vec![])
    }
}

fn local_trust_collection(
    id: Uuid,
    name: &str,
    organisation_id: OrganisationId,
) -> TrustCollection {
    TrustCollection {
        ecosystem: "EUDI".into(),
        id: id.into(),
        name: name.to_string(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        deactivated_at: None,
        remote_trust_collection_url: Some("https://remote.example/collection".parse().unwrap()),
        organisation: dummy_organisation(Some(organisation_id)).into(),
    }
}

#[tokio::test]
async fn test_get_trust_collections_from_verifier_provider_only() {
    let (result, local_collection_id) = verifier_provider_trust_collections(&["EUDI"]).await;

    assert_eq!(result.len(), 1);
    assert_eq!(
        result[0].collection.id,
        TrustCollectionId::from(local_collection_id)
    );
    assert!(result[0].selected);
}

/// The deprecated endpoint reports a collection as selected exactly when the organisation
/// selected the ecosystem owning it.
#[tokio::test]
async fn test_get_trust_collections_unselected_ecosystem_is_not_selected() {
    let (result, local_collection_id) = verifier_provider_trust_collections(&["OTHER"]).await;

    assert_eq!(result.len(), 1);
    assert_eq!(
        result[0].collection.id,
        TrustCollectionId::from(local_collection_id)
    );
    assert!(!result[0].selected);
}

/// Runs `get_trust_collections` for an organisation whose only provider is a verifier
/// advertising a single `EUDI` collection, and that selected `selected_ecosystems`.
/// Returns the result together with the id of the local collection it resolves to.
async fn verifier_provider_trust_collections(
    selected_ecosystems: &[&str],
) -> (Vec<TrustCollectionInfoDTO>, Uuid) {
    let organisation_id = Uuid::new_v4().into();
    let verifier_instance_id = Uuid::new_v4();
    let local_collection_id = Uuid::new_v4();

    let organisation = organisation_selecting(organisation_id, selected_ecosystems);

    let mut organisation_repository = MockOrganisationRepository::default();
    let org_clone = organisation.clone();
    organisation_repository
        .expect_get_organisation()
        .with(eq(organisation_id))
        .returning(move |_| Ok(org_clone.clone()));

    let mut instance_repository = MockInstanceRepository::new();
    instance_repository
        .expect_get_by_role()
        .with(eq(InstanceRole::Wallet), always())
        .returning(|_, _| Ok(None));
    let instance_org = organisation.clone();
    instance_repository
        .expect_get_by_role()
        .with(eq(InstanceRole::Verifier), eq(organisation_id))
        .returning(move |_, _| {
            Ok(Some(dummy_instance(
                verifier_instance_id,
                instance_org.clone(),
                InstanceRole::Verifier,
            )))
        });

    let mut verifier_provider_client = MockVerifierProviderClient::default();
    verifier_provider_client
        .expect_get_verifier_provider_metadata()
        .returning(move |_| {
            Ok(verifier_metadata_with_ecosystems(vec![named_ecosystem(
                "EUDI",
                "Verifier Ecosystem",
            )]))
        });

    let mut trust_collection_repository = MockTrustCollectionRepository::default();
    trust_collection_repository
        .expect_list()
        .returning(move |_| {
            Ok(GetListResponse {
                values: vec![local_trust_collection(
                    local_collection_id,
                    "Verifier Ecosystem",
                    organisation_id,
                )],
                total_pages: 1,
                total_items: 1,
            })
        });

    let service = OrganisationService {
        organisation_repository: Arc::new(organisation_repository),
        identifier_repository: Arc::new(MockIdentifierRepository::new()),
        instance_repository: Arc::new(instance_repository),
        wallet_provider_client: Arc::new(MockWalletProviderClient::default()),
        verifier_provider_client: Arc::new(verifier_provider_client),
        trust_list_subscription_sync: Arc::new(MockTrustListSubscriptionSync::default()),
        trust_collection_repository: Arc::new(trust_collection_repository),
        trust_subscription_repository: Arc::new(MockTrustListSubscriptionRepository::default()),
        core_config: Arc::new(Default::default()),
    };

    let result = service
        .get_trust_collections(&organisation_id)
        .await
        .unwrap();
    (result, local_collection_id)
}

/// A per-collection selection made through the deprecated API leaves one collection of
/// an ecosystem subscribed and another not; the deprecated endpoint keeps reporting that
/// selection rather than flattening it to the ecosystem selection.
/// TODO (ONE-10972): remove together with the deprecated per-collection selection API.
#[tokio::test]
async fn test_get_trust_collections_reports_legacy_per_collection_selection() {
    let organisation_id = Uuid::new_v4().into();
    let verifier_instance_id = Uuid::new_v4();
    let selected_id = Uuid::new_v4();
    let deselected_id = Uuid::new_v4();

    let organisation = organisation_selecting(organisation_id, &["EUDI"]);

    let mut organisation_repository = MockOrganisationRepository::default();
    let org_clone = organisation.clone();
    organisation_repository
        .expect_get_organisation()
        .returning(move |_| Ok(org_clone.clone()));

    let mut instance_repository = MockInstanceRepository::new();
    instance_repository
        .expect_get_by_role()
        .with(eq(InstanceRole::Wallet), always())
        .returning(|_, _| Ok(None));
    let instance_org = organisation.clone();
    instance_repository
        .expect_get_by_role()
        .with(eq(InstanceRole::Verifier), eq(organisation_id))
        .returning(move |_, _| {
            Ok(Some(dummy_instance(
                verifier_instance_id,
                instance_org.clone(),
                InstanceRole::Verifier,
            )))
        });

    let mut verifier_provider_client = MockVerifierProviderClient::default();
    verifier_provider_client
        .expect_get_verifier_provider_metadata()
        .returning(move |_| {
            Ok(verifier_metadata_with_ecosystems(vec![
                EcosystemMetadataDTO {
                    name: "EUDI".into(),
                    display_name: vec![],
                    description: vec![],
                    logo: "logo".to_string(),
                    default_selected: true,
                    trust_collections: vec![
                        EcosystemTrustCollectionDTO {
                            id: Uuid::new_v4().into(),
                            name: "Selected".to_string(),
                        },
                        EcosystemTrustCollectionDTO {
                            id: Uuid::new_v4().into(),
                            name: "Deselected".to_string(),
                        },
                    ],
                    credential_schemas: vec![],
                    proof_schemas: vec![],
                },
            ]))
        });

    let mut seq = Sequence::new();
    let mut trust_collection_repository = MockTrustCollectionRepository::default();
    trust_collection_repository
        .expect_list()
        .once()
        .returning(move |_| {
            Ok(GetListResponse::one_page_of(vec![
                local_trust_collection(selected_id, "Selected", organisation_id),
                local_trust_collection(deselected_id, "Deselected", organisation_id),
            ]))
        })
        .in_sequence(&mut seq);
    // only one of the two is subscribed, so a per-collection selection is in effect
    trust_collection_repository
        .expect_list()
        .once()
        .returning(move |_| {
            Ok(GetListResponse::one(local_trust_collection(
                selected_id,
                "Selected",
                organisation_id,
            )))
        })
        .in_sequence(&mut seq);

    let service = OrganisationService {
        organisation_repository: Arc::new(organisation_repository),
        identifier_repository: Arc::new(MockIdentifierRepository::new()),
        instance_repository: Arc::new(instance_repository),
        wallet_provider_client: Arc::new(MockWalletProviderClient::default()),
        verifier_provider_client: Arc::new(verifier_provider_client),
        trust_list_subscription_sync: Arc::new(MockTrustListSubscriptionSync::default()),
        trust_collection_repository: Arc::new(trust_collection_repository),
        trust_subscription_repository: Arc::new(MockTrustListSubscriptionRepository::default()),
        core_config: Arc::new(Default::default()),
    };

    let result = service
        .get_trust_collections(&organisation_id)
        .await
        .unwrap();

    assert_eq!(result.len(), 2);
    assert_eq!(
        result[0].collection.id,
        TrustCollectionId::from(selected_id)
    );
    assert!(result[0].selected);
    assert_eq!(
        result[1].collection.id,
        TrustCollectionId::from(deselected_id)
    );
    assert!(!result[1].selected);
}

/// A core config knowing only the `EUDI` ecosystem.
fn config_with_eudi_ecosystem() -> CoreConfig {
    let mut config = CoreConfig::default();
    config.ecosystem.insert(
        "EUDI".into(),
        Fields {
            r#type: EcosystemProviderType::Eudi,
            display: ConfigEntryDisplay::TranslationId("ecosystem.eudi".to_string()),
            order: None,
            priority: None,
            enabled: true,
            capabilities: None,
            params: Some(Params {
                public: Some(json!({
                    "logo": "config-logo",
                    "description": { "en": "EUDI ecosystem" },
                })),
                private: None,
            }),
        },
    );
    config
}

#[tokio::test]
async fn test_get_ecosystems_deduplicates_providers_and_filters_unknown_ecosystems() {
    let organisation_id = Uuid::new_v4().into();
    let wallet_instance_id = Uuid::new_v4();
    let verifier_instance_id = Uuid::new_v4();

    let mut organisation = dummy_organisation(Some(organisation_id));
    organisation.configuration.selected_ecosystems = vec!["EUDI".into()];

    let mut organisation_repository = MockOrganisationRepository::default();
    let org_clone = organisation.clone();
    organisation_repository
        .expect_get_organisation()
        .with(eq(organisation_id))
        .returning(move |_| Ok(org_clone.clone()));

    let mut instance_repository = MockInstanceRepository::new();
    let wallet_org = organisation.clone();
    instance_repository
        .expect_get_by_role()
        .with(eq(InstanceRole::Wallet), eq(organisation_id))
        .returning(move |_, _| {
            Ok(Some(dummy_instance(
                wallet_instance_id,
                wallet_org.clone(),
                InstanceRole::Wallet,
            )))
        });
    let verifier_org = organisation.clone();
    instance_repository
        .expect_get_by_role()
        .with(eq(InstanceRole::Verifier), eq(organisation_id))
        .returning(move |_, _| {
            Ok(Some(dummy_instance(
                verifier_instance_id,
                verifier_org.clone(),
                InstanceRole::Verifier,
            )))
        });

    let mut wallet_provider_client = MockWalletProviderClient::default();
    wallet_provider_client
        .expect_get_wallet_provider_metadata()
        .returning(|_| {
            Ok(wallet_metadata_with_ecosystems(vec![
                named_ecosystem("EUDI", "Wallet Collection"),
                // not configured locally, must be filtered out
                named_ecosystem("UNKNOWN", "Unknown Collection"),
            ]))
        });

    let mut verifier_provider_client = MockVerifierProviderClient::default();
    verifier_provider_client
        .expect_get_verifier_provider_metadata()
        // same ecosystem as the wallet provider, must be reported only once
        .returning(|_| {
            Ok(verifier_metadata_with_ecosystems(vec![named_ecosystem(
                "EUDI",
                "Verifier Collection",
            )]))
        });

    let service = OrganisationService {
        organisation_repository: Arc::new(organisation_repository),
        identifier_repository: Arc::new(MockIdentifierRepository::new()),
        instance_repository: Arc::new(instance_repository),
        wallet_provider_client: Arc::new(wallet_provider_client),
        verifier_provider_client: Arc::new(verifier_provider_client),
        trust_list_subscription_sync: Arc::new(MockTrustListSubscriptionSync::default()),
        trust_collection_repository: Arc::new(MockTrustCollectionRepository::default()),
        trust_subscription_repository: Arc::new(MockTrustListSubscriptionRepository::default()),
        core_config: Arc::new(config_with_eudi_ecosystem()),
    };

    let result = service.get_ecosystems(&organisation_id).await.unwrap();

    assert_eq!(result.len(), 1);
    assert_eq!(result[0].name, EcosystemId::from("EUDI"));
    assert!(result[0].selected);
    assert_eq!(result[0].logo, "logo");
}

#[tokio::test]
async fn test_get_ecosystems_reports_unselected_ecosystem() {
    let organisation_id = Uuid::new_v4().into();
    let wallet_instance_id = Uuid::new_v4();

    let organisation = dummy_organisation(Some(organisation_id));

    let mut organisation_repository = MockOrganisationRepository::default();
    let org_clone = organisation.clone();
    organisation_repository
        .expect_get_organisation()
        .returning(move |_| Ok(org_clone.clone()));

    let mut instance_repository = MockInstanceRepository::new();
    let wallet_org = organisation.clone();
    instance_repository
        .expect_get_by_role()
        .with(eq(InstanceRole::Wallet), eq(organisation_id))
        .returning(move |_, _| {
            Ok(Some(dummy_instance(
                wallet_instance_id,
                wallet_org.clone(),
                InstanceRole::Wallet,
            )))
        });
    instance_repository
        .expect_get_by_role()
        .with(eq(InstanceRole::Verifier), always())
        .returning(|_, _| Ok(None));

    let mut wallet_provider_client = MockWalletProviderClient::default();
    wallet_provider_client
        .expect_get_wallet_provider_metadata()
        .returning(|_| {
            Ok(wallet_metadata_with_ecosystems(vec![named_ecosystem(
                "EUDI",
                "Wallet Collection",
            )]))
        });

    let service = OrganisationService {
        organisation_repository: Arc::new(organisation_repository),
        identifier_repository: Arc::new(MockIdentifierRepository::new()),
        instance_repository: Arc::new(instance_repository),
        wallet_provider_client: Arc::new(wallet_provider_client),
        verifier_provider_client: Arc::new(MockVerifierProviderClient::default()),
        trust_list_subscription_sync: Arc::new(MockTrustListSubscriptionSync::default()),
        trust_collection_repository: Arc::new(MockTrustCollectionRepository::default()),
        trust_subscription_repository: Arc::new(MockTrustListSubscriptionRepository::default()),
        core_config: Arc::new(config_with_eudi_ecosystem()),
    };

    let result = service.get_ecosystems(&organisation_id).await.unwrap();

    assert_eq!(result.len(), 1);
    assert!(!result[0].selected);
}

#[tokio::test]
async fn test_get_ecosystems_without_instances_lists_configured_ecosystems() {
    let organisation_id = Uuid::new_v4().into();

    let mut organisation = dummy_organisation(Some(organisation_id));
    organisation.configuration.selected_ecosystems = vec!["EUDI".into()];

    let mut organisation_repository = MockOrganisationRepository::default();
    let org_clone = organisation.clone();
    organisation_repository
        .expect_get_organisation()
        .returning(move |_| Ok(org_clone.clone()));

    let mut instance_repository = MockInstanceRepository::new();
    instance_repository
        .expect_get_by_role()
        .returning(|_, _| Ok(None));

    let service = OrganisationService {
        organisation_repository: Arc::new(organisation_repository),
        identifier_repository: Arc::new(MockIdentifierRepository::new()),
        instance_repository: Arc::new(instance_repository),
        // no instance to query, so the providers must not be contacted
        wallet_provider_client: Arc::new(MockWalletProviderClient::default()),
        verifier_provider_client: Arc::new(MockVerifierProviderClient::default()),
        trust_list_subscription_sync: Arc::new(MockTrustListSubscriptionSync::default()),
        trust_collection_repository: Arc::new(MockTrustCollectionRepository::default()),
        trust_subscription_repository: Arc::new(MockTrustListSubscriptionRepository::default()),
        core_config: Arc::new(config_with_eudi_ecosystem()),
    };

    let result = service.get_ecosystems(&organisation_id).await.unwrap();

    assert_eq!(result.len(), 1);
    assert_eq!(result[0].name, EcosystemId::from("EUDI"));
    assert!(result[0].selected);
    assert_eq!(result[0].logo, "config-logo");
    assert_eq!(result[0].description[0].lang, "en");
    assert_eq!(result[0].description[0].value, "EUDI ecosystem");
}

#[tokio::test]
async fn test_upsert_organisation_rejects_trust_collections_spanning_multiple_providers() {
    let organisation_id = Uuid::new_v4().into();
    let wallet_instance_id = Uuid::new_v4();
    let verifier_instance_id = Uuid::new_v4();
    let wallet_local_id = Uuid::new_v4();
    let verifier_local_id = Uuid::new_v4();

    let organisation = dummy_organisation(Some(organisation_id));

    let wallet_instance = dummy_instance(
        wallet_instance_id,
        organisation.clone(),
        InstanceRole::Wallet,
    );
    let verifier_instance = dummy_instance(
        verifier_instance_id,
        organisation.clone(),
        InstanceRole::Verifier,
    );

    let mut organisation_repository = MockOrganisationRepository::default();
    let org_clone = organisation.clone();
    organisation_repository
        .expect_get_organisation()
        .returning(move |_| Ok(org_clone.clone()));
    organisation_repository
        .expect_update_organisation()
        .returning(|_, _| Ok(()));

    let mut instance_repository = MockInstanceRepository::new();
    instance_repository
        .expect_get_by_role()
        .with(eq(InstanceRole::Wallet), eq(organisation_id))
        .returning({
            let wallet_instance = wallet_instance.clone();
            move |_, _| Ok(Some(wallet_instance.clone()))
        });
    instance_repository
        .expect_get_by_role()
        .with(eq(InstanceRole::Verifier), eq(organisation_id))
        .returning({
            let verifier_instance = verifier_instance.clone();
            move |_, _| Ok(Some(verifier_instance.clone()))
        });
    instance_repository.expect_list().returning(move |_| {
        Ok(InstanceList {
            total_items: 2,
            total_pages: 0,
            values: vec![wallet_instance.clone(), verifier_instance.clone()],
        })
    });

    let mut wallet_provider_client = MockWalletProviderClient::default();
    wallet_provider_client
        .expect_get_wallet_provider_metadata()
        .returning(|_| {
            Ok(wallet_metadata_with_ecosystems(vec![named_ecosystem(
                "EUDI",
                "Wallet Ecosystem",
            )]))
        });

    let mut verifier_provider_client = MockVerifierProviderClient::default();
    verifier_provider_client
        .expect_get_verifier_provider_metadata()
        .returning(|_| {
            Ok(verifier_metadata_with_ecosystems(vec![named_ecosystem(
                "EUDI",
                "Verifier Ecosystem",
            )]))
        });

    let mut trust_collection_repository = MockTrustCollectionRepository::default();
    trust_collection_repository
        .expect_list()
        .returning(move |_| {
            Ok(GetListResponse {
                values: vec![
                    local_trust_collection(wallet_local_id, "Wallet Ecosystem", organisation_id),
                    local_trust_collection(
                        verifier_local_id,
                        "Verifier Ecosystem",
                        organisation_id,
                    ),
                ],
                total_pages: 1,
                total_items: 2,
            })
        });

    let service = OrganisationService {
        organisation_repository: Arc::new(organisation_repository),
        identifier_repository: Arc::new(MockIdentifierRepository::new()),
        instance_repository: Arc::new(instance_repository),
        wallet_provider_client: Arc::new(wallet_provider_client),
        verifier_provider_client: Arc::new(verifier_provider_client),
        trust_list_subscription_sync: Arc::new(MockTrustListSubscriptionSync::default()),
        trust_collection_repository: Arc::new(trust_collection_repository),
        trust_subscription_repository: Arc::new(MockTrustListSubscriptionRepository::default()),
        core_config: Arc::new(Default::default()),
    };

    let result = service
        .upsert_organisation(UpsertOrganisationRequestDTO {
            id: organisation_id,
            deactivate: None,
            wallet_provider: None,
            wallet_provider_issuer: None,
            verifier_provider: None,
            verifier_provider_issuer: None,
            configuration: None,
            trust_collections: Some(vec![wallet_local_id.into(), verifier_local_id.into()]),
            parent_organisation: None,
        })
        .await;

    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0472);
}
