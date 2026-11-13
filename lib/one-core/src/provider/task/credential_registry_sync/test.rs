use std::sync::Arc;

use serde_json::json;
use shared_types::{CredentialId, CredentialSchemaFormatClaimSchemaId, OrganisationId};
use similar_asserts::assert_eq;
use uuid::Uuid;

use super::CredentialRegistrySync;
use crate::config::core_config::CoreConfig;
use crate::model::credential::GetCredentialList;
use crate::model::credential_schema_format_claim_schema::CredentialSchemaFormatClaimSchema;
use crate::model::instance::{Instance, InstanceRole, InstanceStatus, WalletProviderType};
use crate::model::localized_text::{LocalizedText, LocalizedTextEntityType, LocalizedTextField};
use crate::proto::native_credential_manager::{
    DigitalCredentialClaim, DigitalCredentialDisplay, DigitalCredentialMetadata,
    MockNativeCredentialManager,
};
use crate::proto::wallet_provider_client::MockWalletProviderClient;
use crate::provider::task::Task;
use crate::repository::credential_repository::MockCredentialRepository;
use crate::repository::instance_repository::MockInstanceRepository;
use crate::service::managed_instance::dto::{
    FeatureFlags, WalletProviderMetadataResponseDTO, WalletUnitAttestationMetadataDTO,
};
use crate::service::test_utilities::{
    dummy_credential, dummy_organisation, generic_config, get_dummy_date, holder_single_credential,
};

#[derive(Default)]
struct Mocks {
    credential_repository: MockCredentialRepository,
    config: Option<CoreConfig>,
    native_credential_manager: MockNativeCredentialManager,
    instance_repository: MockInstanceRepository,
    wallet_provider_client: MockWalletProviderClient,
}

fn setup(mocks: Mocks) -> CredentialRegistrySync {
    CredentialRegistrySync::new(
        Arc::new(mocks.config.unwrap_or(generic_config().core)),
        Arc::new(mocks.credential_repository),
        Some(Arc::new(mocks.native_credential_manager)),
        Arc::new(mocks.instance_repository),
        Arc::new(mocks.wallet_provider_client),
    )
}

fn wallet_instance(organisation_id: OrganisationId) -> Instance {
    Instance {
        id: Uuid::new_v4().into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        provider_type: WalletProviderType::ProcivisOne,
        provider_name: "wallet-provider".to_string(),
        provider_url: "https://wallet-provider.org".to_string(),
        provider_instance_id: Uuid::new_v4().into(),
        status: InstanceStatus::Active,
        nonce: None,
        user_nonce: None,
        role: InstanceRole::Wallet,
        organisation: dummy_organisation(Some(organisation_id)).into(),
        authentication_key: None,
        wallet_attestations: Default::default(),
    }
}

fn wallet_provider_metadata(dc_api_integration_enabled: bool) -> WalletProviderMetadataResponseDTO {
    WalletProviderMetadataResponseDTO {
        wallet_unit_attestation: WalletUnitAttestationMetadataDTO {
            app_integrity_check_required: false,
            enabled: false,
            required: false,
        },
        name: "wallet-provider".to_string(),
        app_version: None,
        trust_collections: vec![],
        document_signers: vec![],
        feature_flags: FeatureFlags {
            dc_api_integration_enabled,
            ..Default::default()
        },
        user_authentication: None,
        ecosystems: vec![],
    }
}

fn wallet_mocks(
    organisation_id: OrganisationId,
    dc_api_integration_enabled: bool,
) -> (MockInstanceRepository, MockWalletProviderClient) {
    let mut instance_repository = MockInstanceRepository::new();
    instance_repository
        .expect_get_by_role()
        .once()
        .withf(move |role, org_id| *role == InstanceRole::Wallet && *org_id == organisation_id)
        .return_once(move |_, _| Ok(Some(wallet_instance(organisation_id))));

    let mut wallet_provider_client = MockWalletProviderClient::new();
    wallet_provider_client
        .expect_get_wallet_provider_metadata()
        .once()
        .withf(|target| {
            target.metadata_url
                == "https://wallet-provider.org/ssi/wallet-provider/v1/wallet-provider"
        })
        .return_once(move |_| Ok(wallet_provider_metadata(dc_api_integration_enabled)));

    (instance_repository, wallet_provider_client)
}

#[tokio::test]
async fn test_synchronize_dc_api_integration_disabled() {
    let organisation_id: OrganisationId = Uuid::new_v4().into();
    let (instance_repository, wallet_provider_client) = wallet_mocks(organisation_id, false);

    let mut native_credential_manager = MockNativeCredentialManager::new();
    native_credential_manager
        .expect_synchronize()
        .once()
        .withf(|credentials| credentials.is_empty())
        .return_once(|_| Ok(()));

    let task = setup(Mocks {
        native_credential_manager,
        instance_repository,
        wallet_provider_client,
        ..Default::default()
    });

    let result = task
        .run(Some(json!({
            "organisationId": organisation_id,
            "language": "en"
        })))
        .await
        .unwrap();
    assert_eq!(result, json!({ "registeredCredentials": [] }));
}

#[tokio::test]
async fn test_synchronize_missing_wallet_instance() {
    let organisation_id: OrganisationId = Uuid::new_v4().into();

    let mut instance_repository = MockInstanceRepository::new();
    instance_repository
        .expect_get_by_role()
        .once()
        .return_once(|_, _| Ok(None));

    let task = setup(Mocks {
        instance_repository,
        ..Default::default()
    });

    let result = task
        .run(Some(json!({
            "organisationId": organisation_id,
            "language": "en"
        })))
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_synchronize_empty_list() {
    let organisation_id: OrganisationId = Uuid::new_v4().into();
    let (instance_repository, wallet_provider_client) = wallet_mocks(organisation_id, true);
    let expected_registered_credentials: Vec<CredentialId> = vec![];

    let mut credential_repository = MockCredentialRepository::new();
    credential_repository
        .expect_get_credential_list()
        .once()
        .return_once(|_| {
            Ok(GetCredentialList {
                values: vec![],
                total_pages: None,
                total_items: None,
            })
        });

    let mut native_credential_manager = MockNativeCredentialManager::new();
    native_credential_manager
        .expect_synchronize()
        .once()
        .withf(|credentials| credentials.is_empty())
        .return_once(|_| Ok(()));

    let task = setup(Mocks {
        credential_repository,
        native_credential_manager,
        instance_repository,
        wallet_provider_client,
        ..Default::default()
    });

    let result = task
        .run(Some(json!({
            "organisationId": organisation_id,
            "language": "en"
        })))
        .await
        .unwrap();
    assert_eq!(
        result,
        json!({ "registeredCredentials": expected_registered_credentials })
    );
}

#[tokio::test]
async fn test_synchronize_mdoc_single() {
    let mut credential = holder_single_credential(dummy_credential());
    {
        let credential = credential.holder_mut().unwrap();
        let mut cred_schema = credential.common.schema.as_mut().await.unwrap();
        cred_schema.name = "cred-schema-name".to_string();
        let mut claim_schemas = cred_schema.claim_schemas.as_mut().await.unwrap();
        let claim_schema = claim_schemas.first_mut().unwrap();
        claim_schema.translations = vec![LocalizedText {
            entity_id: claim_schema.id.into(),
            field: LocalizedTextField::Name,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            lang: "en".to_string(),
            value: "translated-label".to_string(),
            entity_type: LocalizedTextEntityType::ClaimSchema,
        }]
        .into();

        let mut claims = credential.data.claims.as_mut().await.unwrap();
        claims.first_mut().unwrap().schema = claim_schema.clone().into();

        let mut format = credential.data.format.as_mut().await.unwrap();
        format.format = "MDOC".into();
        format.ecosystem_schema_id = "doctype".to_string();
        format.claim_mappings = vec![CredentialSchemaFormatClaimSchema {
            id: CredentialSchemaFormatClaimSchemaId::new(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            credential_schema_format_id: format.id,
            claim_schema_id: claim_schema.id,
            technical_key: "technical_key".to_string(),
            namespace: Some("namespace".to_string()),
        }]
        .into();
    }

    let organisation_id: OrganisationId = Uuid::new_v4().into();
    let (instance_repository, wallet_provider_client) = wallet_mocks(organisation_id, true);
    let expected_registered_credentials = vec![credential.common().id];

    let mut credential_repository = MockCredentialRepository::new();
    credential_repository
        .expect_get_credential_list()
        .once()
        .return_once({
            let credential = credential.clone();
            move |_| {
                Ok(GetCredentialList {
                    values: vec![credential],
                    total_pages: None,
                    total_items: None,
                })
            }
        });

    let mut native_credential_manager = MockNativeCredentialManager::new();
    native_credential_manager
        .expect_synchronize()
        .once()
        .withf(move |credentials| {
            assert_eq!(credentials.len(), 1);
            let registration = credentials.first().unwrap();

            assert_eq!(registration.credential_id, credential.common().id);
            assert_eq!(
                registration.metadata,
                DigitalCredentialMetadata::Mdoc {
                    doctype: "doctype".to_string()
                }
            );
            assert_eq!(
                registration.claims,
                vec![DigitalCredentialClaim {
                    path: vec!["namespace".to_string(), "technical_key".to_string()],
                    display_name: Some("translated-label".to_string()),
                    selectively_disclosable: false
                }]
            );
            assert_eq!(
                registration.display,
                DigitalCredentialDisplay {
                    credential_name: "cred-schema-name".to_string(),
                    issuer_name: None,
                    logo: None,
                }
            );
            true
        })
        .return_once(|_| Ok(()));

    let task = setup(Mocks {
        credential_repository,
        native_credential_manager,
        instance_repository,
        wallet_provider_client,
        ..Default::default()
    });

    let result = task
        .run(Some(json!({
            "organisationId": organisation_id,
            "language": "en"
        })))
        .await
        .unwrap();
    assert_eq!(
        result,
        json!({ "registeredCredentials": expected_registered_credentials })
    );
}

#[tokio::test]
async fn test_synchronize_sdjwtvc_single() {
    let mut credential = holder_single_credential(dummy_credential());
    {
        let credential = credential.holder_mut().unwrap();
        let mut cred_schema = credential.common.schema.as_mut().await.unwrap();
        cred_schema.name = "cred-schema-name".to_string();
        let mut claim_schemas = cred_schema.claim_schemas.as_mut().await.unwrap();
        let claim_schema = claim_schemas.first_mut().unwrap();
        claim_schema.translations = vec![LocalizedText {
            entity_id: claim_schema.id.into(),
            field: LocalizedTextField::Name,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            lang: "en".to_string(),
            value: "translated-label".to_string(),
            entity_type: LocalizedTextEntityType::ClaimSchema,
        }]
        .into();

        let mut claims = credential.data.claims.as_mut().await.unwrap();
        claims.first_mut().unwrap().schema = claim_schema.clone().into();

        let mut format = credential.data.format.as_mut().await.unwrap();
        format.format = "SD_JWT_VC".into();
        format.ecosystem_schema_id = "vct".to_string();
        format.claim_mappings = vec![CredentialSchemaFormatClaimSchema {
            id: CredentialSchemaFormatClaimSchemaId::new(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            credential_schema_format_id: format.id,
            claim_schema_id: claim_schema.id,
            technical_key: "technical_key".to_string(),
            namespace: None,
        }]
        .into();
    }

    let organisation_id: OrganisationId = Uuid::new_v4().into();
    let (instance_repository, wallet_provider_client) = wallet_mocks(organisation_id, true);
    let expected_registered_credentials = vec![credential.common().id];

    let mut credential_repository = MockCredentialRepository::new();
    credential_repository
        .expect_get_credential_list()
        .once()
        .return_once({
            let credential = credential.clone();
            move |_| {
                Ok(GetCredentialList {
                    values: vec![credential],
                    total_pages: None,
                    total_items: None,
                })
            }
        });

    let mut native_credential_manager = MockNativeCredentialManager::new();
    native_credential_manager
        .expect_synchronize()
        .once()
        .withf(move |credentials| {
            assert_eq!(credentials.len(), 1);
            let registration = credentials.first().unwrap();

            assert_eq!(registration.credential_id, credential.common().id);
            assert_eq!(
                registration.metadata,
                DigitalCredentialMetadata::SdJwtVc {
                    vct: "vct".to_string()
                }
            );
            assert_eq!(
                registration.claims,
                vec![DigitalCredentialClaim {
                    path: vec!["technical_key".to_string()],
                    display_name: Some("translated-label".to_string()),
                    selectively_disclosable: false
                }]
            );
            assert_eq!(
                registration.display,
                DigitalCredentialDisplay {
                    credential_name: "cred-schema-name".to_string(),
                    issuer_name: None,
                    logo: None,
                }
            );
            true
        })
        .return_once(|_| Ok(()));

    let task = setup(Mocks {
        credential_repository,
        native_credential_manager,
        instance_repository,
        wallet_provider_client,
        ..Default::default()
    });

    let result = task
        .run(Some(json!({
            "organisationId": organisation_id,
            "language": "en"
        })))
        .await
        .unwrap();
    assert_eq!(
        result,
        json!({ "registeredCredentials": expected_registered_credentials })
    );
}
