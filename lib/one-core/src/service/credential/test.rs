use std::ops::Add;
use std::sync::Arc;
use std::vec;

use assert2::let_assert;
use mockall::predicate::*;
use serde_json::json;
use serde_yaml;
use shared_types::CredentialId;
use similar_asserts::assert_eq;
use time::Duration;
use uuid::Uuid;

use super::CredentialService;
use super::dto::{
    CreateCredentialRequestDTO, CredentialFilterParamsDTO, CredentialRequestClaimDTO,
    DetailCredentialClaimValueResponseDTO,
};
use super::error::CredentialServiceError;
use super::validator::validate_create_request;
use crate::config::core_config::CoreConfig;
use crate::error::{ErrorCode, ErrorCodeMixin};
use crate::mapper::credential_schema_claim::backfill_default_translations;
use crate::model::certificate::{Certificate, CertificateState};
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{
    Credential, CredentialRole, CredentialStateEnum, CredentialType, GetCredentialList,
};
use crate::model::credential_schema::{CredentialSchema, KeyStorageSecurity};
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::credential_schema_format_claim_schema::CredentialSchemaFormatClaimSchema;
use crate::model::did::{Did, DidType, KeyRole, RelatedKey};
use crate::model::identifier::{Identifier, IdentifierData, IdentifierState};
use crate::model::key::Key;
use crate::model::relation::RelatedVec;
use crate::proto::credential_validity_manager::MockCredentialValidityManager;
use crate::proto::notification_scheduler::MockNotificationScheduler;
use crate::proto::session_provider::test::StaticSessionProvider;
use crate::proto::session_provider::{NoSessionProvider, SessionProvider};
use crate::proto::transaction_manager::NoTransactionManager;
use crate::provider::blob_storage::provider::MockBlobStorageProvider;
use crate::provider::credential_formatter::MockCredentialFormatter;
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::ecosystem::directory::MockEcosystemDirectory;
use crate::provider::issuance_protocol::MockIssuanceProtocol;
use crate::provider::issuance_protocol::dto::IssuanceProtocolCapabilities;
use crate::provider::issuance_protocol::model::ShareResponse;
use crate::provider::issuance_protocol::provider::MockIssuanceProtocolProvider;
use crate::repository::credential_repository::MockCredentialRepository;
use crate::repository::credential_schema_repository::MockCredentialSchemaRepository;
use crate::repository::error::{DataLayerError, EntityKind};
use crate::repository::identifier_repository::MockIdentifierRepository;
use crate::repository::interaction_repository::MockInteractionRepository;
use crate::service::common_dto::ListQueryDTO;
use crate::service::test_utilities::{
    dummy_did, dummy_identifier, dummy_key, dummy_organisation, generic_config,
    generic_formatter_capabilities, get_dummy_date,
};

#[derive(Default)]
struct Repositories {
    pub credential_repository: MockCredentialRepository,
    pub credential_schema_repository: MockCredentialSchemaRepository,
    pub identifier_repository: MockIdentifierRepository,
    pub interaction_repository: MockInteractionRepository,
    pub formatter_provider: MockCredentialFormatterProvider,
    pub protocol_provider: MockIssuanceProtocolProvider,
    pub config: CoreConfig,
    pub blob_storage_provider: MockBlobStorageProvider,
    pub credential_validity_manager: MockCredentialValidityManager,
    pub notification_scheduler: MockNotificationScheduler,
    pub session_provider: Option<Arc<dyn SessionProvider>>,
    pub ecosystem_provider: MockEcosystemDirectory,
}

fn setup_service(repositories: Repositories) -> CredentialService {
    CredentialService::new(
        Arc::new(repositories.credential_repository),
        Arc::new(repositories.credential_schema_repository),
        Arc::new(repositories.identifier_repository),
        Arc::new(repositories.interaction_repository),
        Arc::new(repositories.formatter_provider),
        Arc::new(repositories.protocol_provider),
        Arc::new(repositories.config),
        Arc::new(repositories.blob_storage_provider),
        repositories
            .session_provider
            .unwrap_or(Arc::new(NoSessionProvider)),
        Arc::new(repositories.credential_validity_manager),
        Arc::new(repositories.notification_scheduler),
        Arc::new(NoTransactionManager),
        Arc::new(repositories.ecosystem_provider),
    )
}

async fn generic_credential() -> Credential {
    let now = crate::clock::now_utc();

    let claim_schema = ClaimSchema {
        array: false,
        id: Uuid::new_v4().into(),
        key: "NUMBER".to_string(),
        data_type: "NUMBER".to_string(),
        created_date: now,
        last_modified: now,
        metadata: false,
        required: true,
        translations: Default::default(),
    };
    let organisation = dummy_organisation(None);

    let credential_id = Uuid::new_v4().into();
    let issuer_did = Did {
        deleted_at: None,
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
        name: "did1".to_string(),
        organisation: organisation.clone().into(),
        did: "did:example:1".parse().unwrap(),
        did_type: DidType::Local,
        did_method: "KEY".into(),
        keys: vec![RelatedKey {
            role: KeyRole::AssertionMethod,
            key: Key {
                id: Uuid::new_v4().into(),
                created_date: crate::clock::now_utc(),
                last_modified: crate::clock::now_utc(),
                public_key: vec![],
                name: "key_name".to_string(),
                key_reference: None,
                storage_type: "INTERNAL".to_string(),
                key_type: "EDDSA".to_string(),
                organisation: dummy_organisation(None).into(),
            },
            reference: "1".to_string(),
        }]
        .into(),
        deactivated: false,
        log: None,
    };

    let credential_schema_id = Uuid::new_v4().into();
    let format = CredentialSchemaFormat {
        id: Uuid::new_v4().into(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        credential_schema_id,
        format: "JWT".into(),
        ecosystem_schema_id: "CredentialSchemaId".to_owned(),
        claim_mappings: Default::default(),
    };
    Credential {
        expires_at: None,
        ecosystem: None,
        id: credential_id,
        created_date: now,
        issuance_date: None,
        last_modified: now,
        deleted_at: None,
        consumed_at: None,
        protocol: "OPENID4VCI_FINAL1".to_string(),
        redirect_uri: None,
        role: CredentialRole::Holder,
        r#type: CredentialType::Single,
        state: CredentialStateEnum::Created,
        suspend_end_date: None,
        claims: vec![Claim {
            id: Uuid::new_v4().into(),
            credential_id,
            created_date: now,
            last_modified: now,
            value: Some("123".to_string()),
            path: claim_schema.key.clone(),
            selectively_disclosable: false,
            schema: claim_schema.clone().into(),
        }]
        .into(),
        issuer_identifier: Some(
            Identifier {
                id: Uuid::new_v4().into(),
                created_date: now,
                last_modified: now,
                name: "identifier".to_string(),
                data: IdentifierData::Did((issuer_did).into()),
                is_remote: false,
                state: IdentifierState::Active,
                deleted_at: None,
                organisation: dummy_organisation(Some(uuid::Uuid::new_v4().into())).into(),
                trust_information: Default::default(),
            }
            .into(),
        ),
        issuer_certificate: None,
        holder_identifier: None,
        schema: (backfill_default_translations(
            CredentialSchema {
                expiration: None,
                ecosystem: None,
                batch_size: None,
                allow_revocation: false,
                id: credential_schema_id,
                deleted_at: None,
                imported_source_url: "CORE_URL".to_string(),
                created_date: now,
                last_modified: now,
                name: "schema".to_string(),
                key_storage_security: None,
                claim_schemas: vec![claim_schema].into(),
                organisation: organisation.into(),
                layout_properties: None,
                allow_suspension: true,
                requires_wallet_instance_attestation: false,
                transaction_code: None,
                translations: Default::default(),
                embedded_disclosure_policy: None,
                formats: vec![format.clone()].into(),
            },
            "en",
        )
        .await
        .unwrap())
        .into(),
        interaction: None,
        key: None,
        profile: None,
        credential_blob_id: None,
        wallet_unit_attestation_blob_id: None,
        wallet_instance_attestation_blob_id: None,
        webhook_url: None,
        parent: None,
        embedded_disclosure_policy: None,
        subscriber_information: None,
        format: Some(format.into()),
    }
}

async fn generic_credential_list_entity() -> Credential {
    let now = crate::clock::now_utc();

    let credential_schema_id = Uuid::new_v4().into();
    let organisation = dummy_organisation(None);
    let format = CredentialSchemaFormat {
        id: Uuid::new_v4().into(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        credential_schema_id,
        format: "JWT".into(),
        ecosystem_schema_id: "CredentialSchemaId".to_owned(),
        claim_mappings: Default::default(),
    };
    Credential {
        expires_at: None,
        ecosystem: None,
        id: Uuid::new_v4().into(),
        created_date: now,
        issuance_date: None,
        last_modified: now,
        deleted_at: None,
        consumed_at: None,
        protocol: "OPENID4VCI_FINAL1".to_string(),
        redirect_uri: None,
        role: CredentialRole::Issuer,
        r#type: CredentialType::Single,
        state: CredentialStateEnum::Created,
        suspend_end_date: None,
        claims: Default::default(),
        issuer_identifier: Some(
            Identifier {
                id: Uuid::new_v4().into(),
                created_date: now,
                last_modified: now,
                name: "identifier".to_string(),
                data: IdentifierData::Did(
                    (Did {
                        deleted_at: None,
                        id: Uuid::new_v4().into(),
                        created_date: now,
                        last_modified: now,
                        name: "did1".to_string(),
                        organisation: organisation.clone().into(),
                        did: "did:example:1".parse().unwrap(),
                        did_type: DidType::Local,
                        did_method: "KEY".into(),
                        keys: Default::default(),
                        deactivated: false,
                        log: None,
                    })
                    .into(),
                ),
                is_remote: false,
                state: IdentifierState::Active,
                deleted_at: None,
                organisation: organisation.clone().into(),
                trust_information: Default::default(),
            }
            .into(),
        ),
        issuer_certificate: None,
        holder_identifier: None,
        schema: (backfill_default_translations(
            CredentialSchema {
                expiration: None,
                ecosystem: None,
                batch_size: None,
                allow_revocation: false,
                id: credential_schema_id,
                deleted_at: None,
                imported_source_url: "CORE_URL".to_string(),
                created_date: now,
                last_modified: now,
                name: "schema".to_string(),
                key_storage_security: None,
                formats: vec![format.clone()].into(),
                claim_schemas: Default::default(),
                organisation: dummy_organisation(None).into(),
                layout_properties: None,
                allow_suspension: true,
                requires_wallet_instance_attestation: false,
                transaction_code: None,
                translations: Default::default(),
                embedded_disclosure_policy: None,
            },
            "en",
        )
        .await
        .unwrap())
        .into(),
        interaction: None,
        key: None,
        profile: None,
        credential_blob_id: None,
        wallet_unit_attestation_blob_id: None,
        wallet_instance_attestation_blob_id: None,
        webhook_url: None,
        parent: None,
        embedded_disclosure_policy: None,
        subscriber_information: None,
        format: Some(format.into()),
    }
}

#[tokio::test]
async fn test_delete_credential_success() {
    let mut credential_repository = MockCredentialRepository::default();
    let credential_schema_repository = MockCredentialSchemaRepository::default();

    let credential = generic_credential().await;
    let credential_id = credential.id;
    credential_repository
        .expect_get_credential()
        .once()
        .returning(move |_| Ok(credential.clone()));
    credential_repository
        .expect_get_credential_list()
        .once()
        .returning(|_| {
            Ok(GetCredentialList {
                values: vec![],
                total_pages: 0,
                total_items: 0,
            })
        });
    credential_repository
        .expect_delete_credentials()
        .once()
        .withf(|credentials| {
            assert_eq!(credentials.len(), 1);
            true
        })
        .returning(|_| Ok(()));

    let service = setup_service(Repositories {
        credential_repository,
        credential_schema_repository,
        config: generic_config().core,
        ..Default::default()
    });

    service.delete_credential(&credential_id).await.unwrap();
}

#[tokio::test]
async fn test_delete_credential_failed_credential_missing() {
    let mut credential_repository = MockCredentialRepository::default();

    credential_repository
        .expect_get_credential()
        .returning(|id| {
            Err(DataLayerError::EntityNotFound {
                kind: EntityKind::Credential,
                id: (*id).into(),
            })
        });

    let service = setup_service(Repositories {
        credential_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .delete_credential(&generic_credential().await.id)
        .await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0001);
}

#[tokio::test]
async fn test_delete_credential_incorrect_state() {
    let mut credential_repository = MockCredentialRepository::default();

    let mut credential = generic_credential().await;
    credential.schema.as_mut().await.unwrap().allow_revocation = true;
    credential.state = CredentialStateEnum::Accepted;
    credential.role = CredentialRole::Issuer;

    let copy = credential.clone();
    credential_repository
        .expect_get_credential()
        .returning(move |_| Ok(copy.clone()));

    let service = setup_service(Repositories {
        credential_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.delete_credential(&credential.id).await;
    assert!(matches!(
        result,
        Err(CredentialServiceError::InvalidState(_))
    ));
}

#[tokio::test]
async fn test_delete_credential_invalid_type() {
    let mut credential_repository = MockCredentialRepository::default();

    let mut credential = generic_credential().await;
    credential.r#type = CredentialType::BatchItem;
    credential.role = CredentialRole::Issuer;

    let copy = credential.clone();
    credential_repository
        .expect_get_credential()
        .returning(move |_| Ok(copy.clone()));

    let service = setup_service(Repositories {
        credential_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.delete_credential(&credential.id).await;
    assert!(matches!(
        result,
        Err(CredentialServiceError::InvalidType(_))
    ));
}

#[tokio::test]
async fn test_get_credential_list_success() {
    let mut credential_repository = MockCredentialRepository::default();
    let mut c = generic_credential_list_entity().await;
    c.state = CredentialStateEnum::Revoked;

    let credentials = GetCredentialList {
        values: vec![generic_credential_list_entity().await, c],
        total_pages: 1,
        total_items: 2,
    };
    {
        let clone = credentials.clone();
        credential_repository
            .expect_get_credential_list()
            .times(1)
            .returning(move |_| Ok(clone.clone()));
    }
    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .returning(|_| {
            let mut formatter = MockCredentialFormatter::new();
            formatter.expect_revocation_method_id().returning(|| None);
            Ok(Arc::new(formatter))
        });

    let service = setup_service(Repositories {
        credential_repository,
        config: generic_config().core,
        formatter_provider,
        ..Default::default()
    });

    let organisation_id = Uuid::new_v4().into();
    let result = service
        .get_credential_list(ListQueryDTO {
            page: 0,
            page_size: 5,
            sort: None,
            sort_direction: None,
            filter: CredentialFilterParamsDTO {
                organisation_id,
                name: None,
                search_text: None,
                search_type: None,
                exact: None,
                roles: None,
                ids: None,
                credential_schema_ids: None,
                issuers: None,
                states: None,
                profiles: None,
                created_date_after: None,
                created_date_before: None,
                last_modified_after: None,
                last_modified_before: None,
                issuance_date_after: None,
                issuance_date_before: None,
                revocation_date_after: None,
                revocation_date_before: None,
                expires_at_after: None,
                expires_at_before: None,
                parent_id: None,
                types: None,
                ecosystems: None,
            },
            include: None,
        })
        .await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(2, result.total_items);
    assert_eq!(1, result.total_pages);
    assert_eq!(2, result.values.len());
    assert_eq!(credentials.values[0].id, result.values[0].id);
    assert_eq!(None, result.values[0].revocation_date);
    assert_ne!(None, result.values[1].revocation_date);
}

#[tokio::test]
async fn test_get_credential_success() {
    let mut credential_repository = MockCredentialRepository::default();

    let credential = generic_credential().await;
    {
        let clone = credential.clone();
        credential_repository
            .expect_get_credential()
            .times(1)
            .with(eq(clone.id))
            .returning(move |_| Ok(clone.clone()));
    }

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .return_once(|_| {
            let mut formatter = MockCredentialFormatter::new();
            formatter.expect_revocation_method_id().return_const(None);
            Ok(Arc::new(formatter))
        });

    let service = setup_service(Repositories {
        credential_repository,
        formatter_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.get_credential(&credential.id).await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(credential.id, result.id);
    assert_eq!(None, result.revocation_date);
}

#[tokio::test]
async fn test_get_credential_success_suspended_credential_with_end_date() {
    let mut credential_repository = MockCredentialRepository::default();

    let mut credential = generic_credential().await;
    let now = crate::clock::now_utc();
    let suspend_end_date = now.add(Duration::hours(1));
    credential.state = CredentialStateEnum::Suspended;
    credential.suspend_end_date = Some(suspend_end_date);

    {
        let clone = credential.clone();
        credential_repository
            .expect_get_credential()
            .times(1)
            .with(eq(clone.id))
            .returning(move |_| Ok(clone.clone()));
    }

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .return_once(|_| {
            let mut formatter = MockCredentialFormatter::new();
            formatter.expect_revocation_method_id().return_const(None);
            Ok(Arc::new(formatter))
        });

    let service = setup_service(Repositories {
        credential_repository,
        formatter_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.get_credential(&credential.id).await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(credential.id, result.id);
    assert_eq!(None, result.revocation_date);
    assert_eq!(super::dto::CredentialStateEnum::Suspended, result.state);
    assert_eq!(Some(suspend_end_date), result.suspend_end_date);
}

#[tokio::test]
async fn test_get_credential_deleted() {
    let mut credential_repository = MockCredentialRepository::default();

    let credential = Credential {
        deleted_at: Some(crate::clock::now_utc()),
        ..generic_credential().await
    };
    {
        let clone = credential.clone();
        credential_repository
            .expect_get_credential()
            .times(1)
            .with(eq(clone.id))
            .returning(move |_| Ok(clone.clone()));
    }

    let service = setup_service(Repositories {
        credential_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.get_credential(&credential.id).await;

    assert!(result.is_err_and(|e| matches!(e, CredentialServiceError::NotFound(_))));
}

#[tokio::test]
async fn test_get_revoked_credential_success() {
    let mut credential_repository = MockCredentialRepository::default();

    let mut credential = generic_credential().await;
    credential.state = CredentialStateEnum::Revoked;
    credential.suspend_end_date = None;

    {
        let clone = credential.clone();
        credential_repository
            .expect_get_credential()
            .times(1)
            .with(eq(clone.id))
            .returning(move |_| Ok(clone.clone()));
    }

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .return_once(|_| {
            let mut formatter = MockCredentialFormatter::new();
            formatter.expect_revocation_method_id().return_const(None);
            Ok(Arc::new(formatter))
        });

    let service = setup_service(Repositories {
        credential_repository,
        formatter_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.get_credential(&credential.id).await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(credential.id, result.id);
    assert_ne!(None, result.revocation_date);
}

#[tokio::test]
async fn test_share_credential_success() {
    let mut credential_repository = MockCredentialRepository::default();

    let mut protocol = MockIssuanceProtocol::default();
    let mut protocol_provider = MockIssuanceProtocolProvider::default();

    let expected_url = "test_url";
    let interaction_id = Uuid::new_v4().into();
    let expires_at = crate::clock::now_utc();
    protocol
        .expect_issuer_share_credential()
        .times(1)
        .returning(move |_| {
            Ok(ShareResponse {
                url: expected_url.to_owned(),
                interaction_id,
                interaction_data: None,
                expires_at: Some(expires_at),
                transaction_code: None,
            })
        });

    let protocol = Arc::new(protocol);

    protocol_provider
        .expect_get_protocol()
        .times(1)
        .returning(move |_| Ok(protocol.clone()));

    let credential = generic_credential().await;
    {
        let clone = credential.clone();
        credential_repository
            .expect_get_credential()
            .times(1)
            .with(eq(clone.id))
            .returning(move |_| Ok(clone.clone()));
    }

    let mut interaction_repository = MockInteractionRepository::default();
    interaction_repository
        .expect_create_interaction()
        .withf(move |interaction| {
            interaction.id == interaction_id && interaction.expires_at.unwrap() == expires_at
        })
        .once()
        .returning(|interaction| Ok(interaction.id));

    credential_repository
        .expect_update_credential()
        .once()
        .withf(move |id, update| {
            id == &credential.id && update.state == Some(CredentialStateEnum::Pending)
        })
        .returning(|_, _| Ok(()));

    let service = setup_service(Repositories {
        credential_repository,
        config: generic_config().core,
        protocol_provider,
        interaction_repository,
        ..Default::default()
    });

    let result = service.share_credential(&credential.id).await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.url, expected_url);
    assert_eq!(result.expires_at.unwrap(), expires_at);
}

#[tokio::test]
async fn test_share_credential_failed_invalid_state() {
    let mut credential_repository = MockCredentialRepository::default();

    let mut credential = generic_credential().await;
    credential.state = CredentialStateEnum::Accepted;
    {
        let clone = credential.clone();
        credential_repository
            .expect_get_credential()
            .times(1)
            .with(eq(clone.id))
            .returning(move |_| Ok(clone.clone()));
    }

    let service = setup_service(Repositories {
        credential_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.share_credential(&credential.id).await;
    assert!(result.is_err_and(|e| matches!(e, CredentialServiceError::InvalidState(_))));
}

#[tokio::test]
async fn test_share_credential_failed_invalid_type() {
    let mut credential_repository = MockCredentialRepository::default();

    let mut credential = generic_credential().await;
    credential.r#type = CredentialType::BatchItem;
    {
        let clone = credential.clone();
        credential_repository
            .expect_get_credential()
            .times(1)
            .with(eq(clone.id))
            .returning(move |_| Ok(clone.clone()));
    }

    let service = setup_service(Repositories {
        credential_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.share_credential(&credential.id).await;
    assert!(result.is_err_and(|e| matches!(e, CredentialServiceError::InvalidType(_))));
}

#[tokio::test]
async fn test_share_credential_failed_inactive_identifier() {
    let mut credential_repository = MockCredentialRepository::default();

    let mut credential = generic_credential().await;
    credential
        .issuer_identifier
        .as_mut()
        .unwrap()
        .as_mut()
        .await
        .unwrap()
        .state = IdentifierState::Deactivated;
    {
        let clone = credential.clone();
        credential_repository
            .expect_get_credential()
            .times(1)
            .with(eq(clone.id))
            .returning(move |_| Ok(clone.clone()));
    }

    let service = setup_service(Repositories {
        credential_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.share_credential(&credential.id).await;
    assert!(result.is_err_and(|e| matches!(e, CredentialServiceError::IdentifierIsDeactivated(_))));
}

#[tokio::test]
async fn test_create_credential_based_on_issuer_did_success() {
    let mut credential_repository = MockCredentialRepository::default();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut identifier_repository = MockIdentifierRepository::default();

    let credential = generic_credential().await;
    let_assert!(
        Identifier {
            data: IdentifierData::Did(issuer_identifier_did),
            ..
        } = credential
            .issuer_identifier
            .as_ref()
            .unwrap()
            .as_ref()
            .await
            .unwrap()
            .to_owned()
    );
    {
        let clone = credential.clone();
        let issuer_did = issuer_identifier_did.clone();
        let credential_schema = credential.schema.as_ref().await.unwrap().to_owned();

        identifier_repository
            .expect_get_from_did_id()
            .return_once(|_| {
                Ok(Some(Identifier {
                    data: IdentifierData::Did(issuer_did),
                    ..dummy_identifier()
                }))
            });

        credential_schema_repository
            .expect_get_credential_schema()
            .times(1)
            .returning(move |_| Ok(credential_schema.clone()));

        credential_repository
            .expect_create_credential()
            .times(1)
            .returning(move |_| Ok(clone.id));
    }

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .once()
        .return_once(generic_formatter_capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .with(eq(credential
            .schema
            .as_ref()
            .await
            .unwrap()
            .format()
            .await
            .unwrap()))
        .return_once(move |_| Ok(Arc::new(formatter)));

    let mut dummy_protocol = MockIssuanceProtocol::default();
    dummy_protocol
        .expect_get_capabilities()
        .once()
        .returning(generic_capabilities);
    let mut protocol_provider = MockIssuanceProtocolProvider::default();
    protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Ok(Arc::new(dummy_protocol)));

    let service = setup_service(Repositories {
        credential_repository,
        credential_schema_repository,
        identifier_repository,
        formatter_provider,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .create_credential(CreateCredentialRequestDTO {
            credential_schema_id: credential.schema.as_ref().await.unwrap().id.to_owned(),
            issuer: None,
            issuer_did: Some(issuer_identifier_did.id()),
            issuer_key: None,
            issuer_certificate: None,
            protocol: "OPENID4VCI_FINAL1".to_string(),
            claim_values: vec![CredentialRequestClaimDTO {
                claim_schema_id: credential.claims.as_ref().await.unwrap()[0]
                    .schema
                    .as_ref()
                    .await
                    .unwrap()
                    .id
                    .to_owned(),
                value: credential.claims.as_ref().await.unwrap()[0]
                    .value
                    .to_owned()
                    .unwrap(),
                path: credential.claims.as_ref().await.unwrap()[0].path.to_owned(),
            }],
            redirect_uri: None,
            profile: None,
            webhook_destination_url: None,
            subscriber_information: None,
            ecosystem: None,
        })
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_create_credential_based_on_issuer_identifier_success() {
    let mut credential_repository = MockCredentialRepository::default();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut identifier_repository = MockIdentifierRepository::default();

    let credential = generic_credential().await;
    {
        let clone = credential.clone();
        let issuer_identifier = credential
            .issuer_identifier
            .as_ref()
            .unwrap()
            .as_ref()
            .await
            .unwrap()
            .to_owned();
        let credential_schema = credential.schema.as_ref().await.unwrap().to_owned();

        identifier_repository
            .expect_get()
            .return_once(|_| Ok(issuer_identifier));

        credential_schema_repository
            .expect_get_credential_schema()
            .times(1)
            .returning(move |_| Ok(credential_schema.clone()));

        credential_repository
            .expect_create_credential()
            .times(1)
            .returning(move |_| Ok(clone.id));
    }

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .once()
        .return_once(generic_formatter_capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .with(eq(credential
            .schema
            .as_ref()
            .await
            .unwrap()
            .format()
            .await
            .unwrap()))
        .return_once(move |_| Ok(Arc::new(formatter)));

    let mut dummy_protocol = MockIssuanceProtocol::default();
    dummy_protocol
        .expect_get_capabilities()
        .once()
        .returning(generic_capabilities);
    let mut protocol_provider = MockIssuanceProtocolProvider::default();
    protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Ok(Arc::new(dummy_protocol)));

    let service = setup_service(Repositories {
        credential_repository,
        credential_schema_repository,
        identifier_repository,
        formatter_provider,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .create_credential(CreateCredentialRequestDTO {
            credential_schema_id: credential.schema.as_ref().await.unwrap().id.to_owned(),
            issuer: Some(credential.issuer_identifier.as_ref().unwrap().id()),
            issuer_did: None,
            issuer_key: None,
            issuer_certificate: None,
            protocol: "OPENID4VCI_FINAL1".to_string(),
            claim_values: vec![CredentialRequestClaimDTO {
                claim_schema_id: credential.claims.as_ref().await.unwrap()[0]
                    .schema
                    .as_ref()
                    .await
                    .unwrap()
                    .id
                    .to_owned(),
                value: credential.claims.as_ref().await.unwrap()[0]
                    .value
                    .to_owned()
                    .unwrap(),
                path: credential.claims.as_ref().await.unwrap()[0].path.to_owned(),
            }],
            redirect_uri: None,
            profile: None,
            webhook_destination_url: None,
            subscriber_information: None,
            ecosystem: None,
        })
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_create_credential_failed_unsupported_wallet_storage_type() {
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut identifier_repository = MockIdentifierRepository::default();

    let Credential {
        schema,
        claims,
        issuer_identifier,
        ..
    } = generic_credential().await;

    let mut schema = schema.as_ref().await.unwrap().to_owned();
    let claims = claims.as_ref().await.unwrap().to_owned();
    let issuer_identifier = issuer_identifier.unwrap();

    schema.key_storage_security = Some(KeyStorageSecurity::EnhancedBasic);
    {
        let issuer_identifier = issuer_identifier.as_ref().await.unwrap().to_owned();
        let credential_schema = schema.clone();

        identifier_repository
            .expect_get()
            .return_once(|_| Ok(issuer_identifier));

        credential_schema_repository
            .expect_get_credential_schema()
            .times(1)
            .returning(move |_| Ok(credential_schema.clone()));
    }

    let service = setup_service(Repositories {
        credential_schema_repository,
        identifier_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .create_credential(CreateCredentialRequestDTO {
            credential_schema_id: schema.id,
            issuer: Some(issuer_identifier.id()),
            issuer_did: None,
            issuer_key: None,
            issuer_certificate: None,
            protocol: "OPENID4VCI_FINAL1".to_string(),
            claim_values: vec![CredentialRequestClaimDTO {
                claim_schema_id: claims[0].schema.as_ref().await.unwrap().id.to_owned(),
                value: claims[0].value.to_owned().unwrap(),
                path: claims[0].path.to_owned(),
            }],
            redirect_uri: None,
            profile: None,
            webhook_destination_url: None,
            subscriber_information: None,
            ecosystem: None,
        })
        .await;

    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0309);
}

#[tokio::test]
async fn test_create_credential_failed_formatter_doesnt_support_did_identifiers() {
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut identifier_repository = MockIdentifierRepository::default();

    let credential = generic_credential().await;
    let_assert!(
        Identifier {
            data: IdentifierData::Did(issuer_identifier_did),
            ..
        } = credential
            .issuer_identifier
            .as_ref()
            .unwrap()
            .as_ref()
            .await
            .unwrap()
            .to_owned()
    );
    {
        let issuer_did = issuer_identifier_did.clone();
        let credential_schema = credential.schema.as_ref().await.unwrap().to_owned();

        credential_schema_repository
            .expect_get_credential_schema()
            .times(1)
            .returning(move |_| Ok(credential_schema.clone()));

        identifier_repository
            .expect_get_from_did_id()
            .return_once(|_| {
                Ok(Some(Identifier {
                    data: IdentifierData::Did(issuer_did),
                    ..dummy_identifier()
                }))
            });
    }

    let mut formatter_capabilities = generic_formatter_capabilities();
    formatter_capabilities.issuance_identifier_types.clear();

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .once()
        .return_once(|| formatter_capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .with(eq(credential
            .schema
            .as_ref()
            .await
            .unwrap()
            .format()
            .await
            .unwrap()))
        .return_once(move |_| Ok(Arc::new(formatter)));

    let mut dummy_protocol = MockIssuanceProtocol::default();
    dummy_protocol
        .expect_get_capabilities()
        .once()
        .returning(generic_capabilities);
    let mut protocol_provider = MockIssuanceProtocolProvider::default();
    protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Ok(Arc::new(dummy_protocol)));

    let service = setup_service(Repositories {
        credential_schema_repository,
        identifier_repository,
        formatter_provider,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .create_credential(CreateCredentialRequestDTO {
            credential_schema_id: credential.schema.as_ref().await.unwrap().id.to_owned(),
            issuer: None,
            issuer_did: Some(issuer_identifier_did.id()),
            issuer_key: None,
            issuer_certificate: None,
            protocol: "OPENID4VCI_FINAL1".to_string(),
            claim_values: vec![CredentialRequestClaimDTO {
                claim_schema_id: credential.claims.as_ref().await.unwrap()[0]
                    .schema
                    .as_ref()
                    .await
                    .unwrap()
                    .id
                    .to_owned(),
                value: credential.claims.as_ref().await.unwrap()[0]
                    .value
                    .to_owned()
                    .unwrap(),
                path: credential.claims.as_ref().await.unwrap()[0].path.to_owned(),
            }],
            redirect_uri: None,
            profile: None,
            webhook_destination_url: None,
            subscriber_information: None,
            ecosystem: None,
        })
        .await;

    assert!(matches!(
        result,
        Err(CredentialServiceError::IncompatibleIssuanceIdentifier)
    ));
}

#[tokio::test]
async fn test_create_credential_failed_issuance_did_method_incompatible() {
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut identifier_repository = MockIdentifierRepository::default();

    let credential = generic_credential().await;
    let_assert!(
        Identifier {
            data: IdentifierData::Did(issuer_identifier_did),
            ..
        } = credential
            .issuer_identifier
            .as_ref()
            .unwrap()
            .as_ref()
            .await
            .unwrap()
            .to_owned()
    );
    {
        let issuer_did = issuer_identifier_did.clone();
        let credential_schema = credential.schema.as_ref().await.unwrap().to_owned();

        credential_schema_repository
            .expect_get_credential_schema()
            .times(1)
            .returning(move |_| Ok(credential_schema.clone()));

        identifier_repository
            .expect_get_from_did_id()
            .return_once(|_| {
                Ok(Some(Identifier {
                    data: IdentifierData::Did(issuer_did),
                    ..dummy_identifier()
                }))
            });
    }

    let mut formatter_capabilities = generic_formatter_capabilities();
    formatter_capabilities.issuance_did_methods.clear();

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .once()
        .return_once(|| formatter_capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .with(eq(credential
            .schema
            .as_ref()
            .await
            .unwrap()
            .format()
            .await
            .unwrap()))
        .return_once(move |_| Ok(Arc::new(formatter)));

    let mut dummy_protocol = MockIssuanceProtocol::default();
    dummy_protocol
        .expect_get_capabilities()
        .once()
        .returning(generic_capabilities);
    let mut protocol_provider = MockIssuanceProtocolProvider::default();
    protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Ok(Arc::new(dummy_protocol)));

    let service = setup_service(Repositories {
        credential_schema_repository,
        identifier_repository,
        formatter_provider,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .create_credential(CreateCredentialRequestDTO {
            credential_schema_id: credential.schema.as_ref().await.unwrap().id.to_owned(),
            issuer: None,
            issuer_did: Some(issuer_identifier_did.id()),
            issuer_key: None,
            issuer_certificate: None,
            protocol: "OPENID4VCI_FINAL1".to_string(),
            claim_values: vec![CredentialRequestClaimDTO {
                claim_schema_id: credential.claims.as_ref().await.unwrap()[0]
                    .schema
                    .as_ref()
                    .await
                    .unwrap()
                    .id
                    .to_owned(),
                value: credential.claims.as_ref().await.unwrap()[0]
                    .value
                    .to_owned()
                    .unwrap(),
                path: credential.claims.as_ref().await.unwrap()[0].path.to_owned(),
            }],
            redirect_uri: None,
            profile: None,
            webhook_destination_url: None,
            subscriber_information: None,
            ecosystem: None,
        })
        .await;

    assert!(matches!(
        result,
        Err(CredentialServiceError::IncompatibleIssuanceDidMethod)
    ));
}

#[tokio::test]
async fn test_create_credential_fails_if_did_is_deactivated() {
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut identifier_repository = MockIdentifierRepository::default();

    let did_id = Uuid::new_v4();
    let issuer_did = Did {
        deleted_at: None,
        id: did_id.into(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        name: "did1".to_string(),
        organisation: dummy_organisation(None).into(),
        did: "did:example:1".parse().unwrap(),
        did_type: DidType::Local,
        did_method: "KEY".into(),
        keys: Default::default(),
        deactivated: true,
        log: None,
    };

    identifier_repository
        .expect_get_from_did_id()
        .return_once(|_| {
            Ok(Some(Identifier {
                data: IdentifierData::Did((issuer_did).into()),
                ..dummy_identifier()
            }))
        });

    let credential = generic_credential().await;
    let credential_schema = credential.schema.as_ref().await.unwrap().to_owned();
    credential_schema_repository
        .expect_get_credential_schema()
        .returning(move |_| Ok(credential_schema.clone()));

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .once()
        .return_once(generic_formatter_capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .with(eq(credential
            .schema
            .as_ref()
            .await
            .unwrap()
            .format()
            .await
            .unwrap()))
        .return_once(move |_| Ok(Arc::new(formatter)));

    let mut dummy_protocol = MockIssuanceProtocol::default();
    dummy_protocol
        .expect_get_capabilities()
        .once()
        .returning(generic_capabilities);
    let mut protocol_provider = MockIssuanceProtocolProvider::default();
    protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Ok(Arc::new(dummy_protocol)));

    let service = setup_service(Repositories {
        identifier_repository,
        credential_schema_repository,
        formatter_provider,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .create_credential(CreateCredentialRequestDTO {
            credential_schema_id: Uuid::new_v4().into(),
            issuer: None,
            issuer_did: Some(did_id.into()),
            issuer_key: None,
            issuer_certificate: None,
            protocol: "OPENID4VCI_FINAL1".to_string(),
            claim_values: vec![],
            redirect_uri: None,
            profile: None,
            webhook_destination_url: None,
            subscriber_information: None,
            ecosystem: None,
        })
        .await;

    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0330);
}

#[tokio::test]
async fn test_create_credential_one_required_claim_missing_success() {
    let mut credential_repository = MockCredentialRepository::default();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut identifier_repository = MockIdentifierRepository::default();

    let credential = generic_credential().await;
    let_assert!(
        Identifier {
            data: IdentifierData::Did(issuer_identifier_did),
            ..
        } = credential
            .issuer_identifier
            .as_ref()
            .unwrap()
            .as_ref()
            .await
            .unwrap()
            .to_owned()
    );
    let credential_schema = CredentialSchema {
        claim_schemas: vec![
            ClaimSchema {
                array: false,
                id: Uuid::new_v4().into(),
                key: "required".to_string(),
                data_type: "STRING".to_string(),
                created_date: crate::clock::now_utc(),
                last_modified: crate::clock::now_utc(),
                metadata: false,
                required: true,
                translations: Default::default(),
            },
            ClaimSchema {
                array: false,
                id: Uuid::new_v4().into(),
                key: "optional".to_string(),
                data_type: "STRING".to_string(),
                created_date: crate::clock::now_utc(),
                last_modified: crate::clock::now_utc(),
                metadata: false,
                required: false,
                translations: Default::default(),
            },
        ]
        .into(),
        ..credential.schema.as_ref().await.unwrap().to_owned()
    };

    {
        let clone = credential.clone();
        let issuer_did = issuer_identifier_did.clone();
        let credential_schema_clone = credential_schema.clone();

        credential_schema_repository
            .expect_get_credential_schema()
            .returning(move |_| Ok(credential_schema_clone.clone()));

        credential_repository
            .expect_create_credential()
            .times(1)
            .returning(move |_| Ok(clone.id));

        identifier_repository
            .expect_get_from_did_id()
            .return_once(|_| {
                Ok(Some(Identifier {
                    data: IdentifierData::Did(issuer_did),
                    ..dummy_identifier()
                }))
            });
    }

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .return_once(generic_formatter_capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .with(eq(credential_schema.format().await.unwrap()))
        .return_once(move |_| Ok(Arc::new(formatter)));

    let mut dummy_protocol = MockIssuanceProtocol::default();
    dummy_protocol
        .expect_get_capabilities()
        .once()
        .returning(generic_capabilities);
    let mut protocol_provider = MockIssuanceProtocolProvider::default();
    protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Ok(Arc::new(dummy_protocol)));

    let service = setup_service(Repositories {
        credential_repository,
        credential_schema_repository,
        identifier_repository,
        formatter_provider,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let required_claim_schema_id = credential_schema.claim_schemas.as_ref().await.unwrap()[0].id;
    let create_request_template = CreateCredentialRequestDTO {
        credential_schema_id: credential.schema.as_ref().await.unwrap().id.to_owned(),
        issuer: None,
        issuer_did: Some(issuer_identifier_did.id()),
        issuer_key: None,
        issuer_certificate: None,
        protocol: "OPENID4VCI_FINAL1".to_string(),
        claim_values: vec![],
        redirect_uri: None,
        profile: None,
        webhook_destination_url: None,
        subscriber_information: None,
        ecosystem: None,
    };

    // create a credential with required claims only succeeds
    let result = service
        .create_credential(CreateCredentialRequestDTO {
            claim_values: vec![CredentialRequestClaimDTO {
                claim_schema_id: required_claim_schema_id,
                value: "value".to_string(),
                path: credential_schema.claim_schemas.as_ref().await.unwrap()[0]
                    .key
                    .to_owned(),
            }],
            ..create_request_template
        })
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_create_credential_one_required_claim_missing_fail_required_claim_not_provided() {
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut identifier_repository = MockIdentifierRepository::default();

    let credential = generic_credential().await;
    let_assert!(
        Identifier {
            data: IdentifierData::Did(issuer_identifier_did),
            ..
        } = credential
            .issuer_identifier
            .as_ref()
            .unwrap()
            .as_ref()
            .await
            .unwrap()
            .to_owned()
    );
    let credential_schema = CredentialSchema {
        claim_schemas: vec![
            ClaimSchema {
                array: false,
                id: Uuid::new_v4().into(),
                key: "required".to_string(),
                data_type: "STRING".to_string(),
                created_date: crate::clock::now_utc(),
                last_modified: crate::clock::now_utc(),
                metadata: false,
                required: true,
                translations: Default::default(),
            },
            ClaimSchema {
                array: false,
                id: Uuid::new_v4().into(),
                key: "optional".to_string(),
                data_type: "STRING".to_string(),
                created_date: crate::clock::now_utc(),
                last_modified: crate::clock::now_utc(),
                metadata: false,
                required: false,
                translations: Default::default(),
            },
        ]
        .into(),
        ..credential.schema.as_ref().await.unwrap().to_owned()
    };

    {
        let issuer_did = issuer_identifier_did.clone();
        let credential_schema_clone = credential_schema.clone();

        identifier_repository
            .expect_get_from_did_id()
            .return_once(|_| {
                Ok(Some(Identifier {
                    data: IdentifierData::Did(issuer_did),
                    ..dummy_identifier()
                }))
            });

        credential_schema_repository
            .expect_get_credential_schema()
            .returning(move |_| Ok(credential_schema_clone.clone()));
    }

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .return_once(generic_formatter_capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .with(eq(credential_schema.format().await.unwrap()))
        .return_once(move |_| Ok(Arc::new(formatter)));

    let mut dummy_protocol = MockIssuanceProtocol::default();
    dummy_protocol
        .expect_get_capabilities()
        .once()
        .returning(generic_capabilities);
    let mut protocol_provider = MockIssuanceProtocolProvider::default();
    protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Ok(Arc::new(dummy_protocol)));

    let service = setup_service(Repositories {
        credential_schema_repository,
        identifier_repository,
        formatter_provider,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let optional_claim_schema_id = credential_schema.claim_schemas.as_ref().await.unwrap()[1].id;
    let create_request_template = CreateCredentialRequestDTO {
        credential_schema_id: credential.schema.as_ref().await.unwrap().id.to_owned(),
        issuer: None,
        issuer_did: Some(issuer_identifier_did.id()),
        issuer_key: None,
        issuer_certificate: None,
        protocol: "OPENID4VCI_FINAL1".to_string(),
        claim_values: vec![],
        redirect_uri: None,
        profile: None,
        webhook_destination_url: None,
        subscriber_information: None,
        ecosystem: None,
    };

    // create a credential with only an optional claim fails
    let result = service
        .create_credential(CreateCredentialRequestDTO {
            claim_values: vec![CredentialRequestClaimDTO {
                claim_schema_id: optional_claim_schema_id,
                value: "value".to_string(),
                path: credential_schema.claim_schemas.as_ref().await.unwrap()[1]
                    .key
                    .to_owned(),
            }],
            ..create_request_template.clone()
        })
        .await;
    assert!(matches!(
        result,
        Err(CredentialServiceError::MissingClaimSchema(_))
    ));
}

#[tokio::test]
async fn test_create_credential_namespace_optional() {
    let mut credential_repository = MockCredentialRepository::default();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut identifier_repository = MockIdentifierRepository::default();

    let credential = generic_credential().await;
    let_assert!(
        Identifier {
            data: IdentifierData::Did(issuer_identifier_did),
            ..
        } = credential
            .issuer_identifier
            .as_ref()
            .unwrap()
            .as_ref()
            .await
            .unwrap()
            .to_owned()
    );

    let claim_schema_id = Uuid::new_v4().into();
    let credential_schema = {
        let schema = credential.schema.as_ref().await.unwrap().to_owned();
        let format_id = Uuid::new_v4().into();
        CredentialSchema {
            claim_schemas: vec![ClaimSchema {
                array: false,
                id: claim_schema_id,
                key: "required".to_string(),
                data_type: "STRING".to_string(),
                created_date: crate::clock::now_utc(),
                last_modified: crate::clock::now_utc(),
                metadata: false,
                required: true,
                translations: Default::default(),
            }]
            .into(),
            formats: vec![CredentialSchemaFormat {
                id: format_id,
                created_date: crate::clock::now_utc(),
                last_modified: crate::clock::now_utc(),
                credential_schema_id: schema.id,
                format: "MDOC".into(),
                ecosystem_schema_id: "doctype".to_owned(),
                claim_mappings: vec![CredentialSchemaFormatClaimSchema {
                    id: Uuid::new_v4().into(),
                    created_date: crate::clock::now_utc(),
                    last_modified: crate::clock::now_utc(),
                    credential_schema_format_id: format_id,
                    claim_schema_id,
                    technical_key: "required".to_string(),
                    namespace: Some("namespace".to_string()),
                }]
                .into(),
            }]
            .into(),
            ..schema
        }
    };

    let issuer_did = issuer_identifier_did.clone();

    credential_schema_repository
        .expect_get_credential_schema()
        .returning({
            let credential_schema = credential_schema.clone();
            move |_| Ok(credential_schema.clone())
        });

    identifier_repository.expect_get_from_did_id().returning({
        let issuer_did = issuer_did.clone();

        move |_| {
            Ok(Some(Identifier {
                data: IdentifierData::Did(issuer_did.clone()),
                ..dummy_identifier()
            }))
        }
    });

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .with(eq(credential_schema.format().await.unwrap()))
        .returning(|_| {
            let mut formatter = MockCredentialFormatter::default();
            formatter
                .expect_get_capabilities()
                .return_once(generic_formatter_capabilities);

            Ok(Arc::new(formatter))
        });

    let mut protocol_provider = MockIssuanceProtocolProvider::default();
    protocol_provider.expect_get_protocol().returning(|_| {
        let mut dummy_protocol = MockIssuanceProtocol::default();
        dummy_protocol
            .expect_get_capabilities()
            .once()
            .returning(generic_capabilities);

        Ok(Arc::new(dummy_protocol))
    });

    credential_repository
        .expect_create_credential()
        .withf(move |request| {
            // already loaded, so this does not actually block on any I/O
            let claims = futures::executor::block_on(request.claims.as_ref()).unwrap();
            assert_eq!(claims.len(), 1);
            let claim = &claims[0];
            assert_eq!(claim.value.as_ref().unwrap(), "value");
            assert_eq!(claim.path, "required");
            assert_eq!(claim.schema.id(), claim_schema_id);
            true
        })
        .returning(|request| Ok(request.id));

    let service = setup_service(Repositories {
        credential_repository,
        credential_schema_repository,
        identifier_repository,
        formatter_provider,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let create_request_template = CreateCredentialRequestDTO {
        credential_schema_id: credential_schema.id,
        issuer: None,
        issuer_did: Some(issuer_did.id()),
        issuer_key: None,
        issuer_certificate: None,
        protocol: "OPENID4VCI_FINAL1".to_string(),
        claim_values: vec![],
        redirect_uri: None,
        profile: None,
        webhook_destination_url: None,
        subscriber_information: None,
        ecosystem: None,
    };

    // not mentioning namespace
    service
        .create_credential(CreateCredentialRequestDTO {
            claim_values: vec![CredentialRequestClaimDTO {
                claim_schema_id,
                value: "value".to_string(),
                path: "required".to_string(),
            }],
            ..create_request_template.clone()
        })
        .await
        .unwrap();

    // with namespace
    service
        .create_credential(CreateCredentialRequestDTO {
            claim_values: vec![CredentialRequestClaimDTO {
                claim_schema_id,
                value: "value".to_string(),
                path: "namespace/required".to_string(),
            }],
            ..create_request_template.clone()
        })
        .await
        .unwrap();

    // not matching namespace
    let result = service
        .create_credential(CreateCredentialRequestDTO {
            claim_values: vec![CredentialRequestClaimDTO {
                claim_schema_id,
                value: "value".to_string(),
                path: "not_matching/required".to_string(),
            }],
            ..create_request_template
        })
        .await;

    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0047);
}

#[tokio::test]
async fn test_create_credential_schema_deleted() {
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut identifier_repository = MockIdentifierRepository::default();

    let credential = generic_credential().await;
    let_assert!(
        Identifier {
            data: IdentifierData::Did(issuer_identifier_did),
            ..
        } = credential
            .issuer_identifier
            .as_ref()
            .unwrap()
            .as_ref()
            .await
            .unwrap()
            .to_owned()
    );
    let credential_schema = CredentialSchema {
        deleted_at: Some(crate::clock::now_utc()),
        ..credential.schema.as_ref().await.unwrap().to_owned()
    };

    {
        let issuer_did = issuer_identifier_did.clone();
        let credential_schema_clone = credential_schema.clone();

        credential_schema_repository
            .expect_get_credential_schema()
            .returning(move |_| Ok(credential_schema_clone.clone()));

        identifier_repository
            .expect_get_from_did_id()
            .return_once(|_| {
                Ok(Some(Identifier {
                    data: IdentifierData::Did(issuer_did),
                    ..dummy_identifier()
                }))
            });
    }

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .return_once(generic_formatter_capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .with(eq(credential_schema.format().await.unwrap()))
        .return_once(move |_| Ok(Arc::new(formatter)));

    let mut dummy_protocol = MockIssuanceProtocol::default();
    dummy_protocol
        .expect_get_capabilities()
        .once()
        .returning(generic_capabilities);
    let mut protocol_provider = MockIssuanceProtocolProvider::default();
    protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Ok(Arc::new(dummy_protocol)));

    let service = setup_service(Repositories {
        credential_schema_repository,
        identifier_repository,
        formatter_provider,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let claim_schema_id = credential_schema.claim_schemas.as_ref().await.unwrap()[0].id;

    let result = service
        .create_credential(CreateCredentialRequestDTO {
            credential_schema_id: credential.schema.as_ref().await.unwrap().id.to_owned(),
            issuer: None,
            issuer_did: Some(issuer_identifier_did.id()),
            issuer_key: None,
            issuer_certificate: None,
            protocol: "OPENID4VCI_FINAL1".to_string(),
            claim_values: vec![CredentialRequestClaimDTO {
                claim_schema_id,
                value: "value".to_string(),
                path: credential_schema.claim_schemas.as_ref().await.unwrap()[0]
                    .key
                    .to_owned(),
            }],
            redirect_uri: None,
            profile: None,
            webhook_destination_url: None,
            subscriber_information: None,
            ecosystem: None,
        })
        .await;

    assert2::assert!(
        let Err(CredentialServiceError::MissingCredentialSchema(_)) = result
    );
}

#[tokio::test]
async fn test_create_credential_key_with_issuer_key() {
    let mut credential_repository = MockCredentialRepository::default();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut identifier_repository = MockIdentifierRepository::default();

    let credential = generic_credential().await;
    let_assert!(
        Identifier {
            data: IdentifierData::Did(issuer_identifier_did),
            ..
        } = credential
            .issuer_identifier
            .as_ref()
            .unwrap()
            .as_ref()
            .await
            .unwrap()
            .to_owned()
    );
    let issuer_did = issuer_identifier_did.clone();
    let credential_schema = credential.schema.as_ref().await.unwrap().to_owned();

    identifier_repository.expect_get_from_did_id().return_once({
        let issuer_did = issuer_did.clone();
        |_| {
            Ok(Some(Identifier {
                data: IdentifierData::Did(issuer_did),
                ..dummy_identifier()
            }))
        }
    });

    credential_schema_repository
        .expect_get_credential_schema()
        .times(1)
        .returning(move |_| Ok(credential_schema.clone()));

    credential_repository
        .expect_create_credential()
        .times(1)
        .returning({
            let credential = credential.clone();
            move |_| Ok(credential.id)
        });

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .once()
        .return_once(generic_formatter_capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .with(eq(credential
            .schema
            .as_ref()
            .await
            .unwrap()
            .format()
            .await
            .unwrap()))
        .return_once(move |_| Ok(Arc::new(formatter)));

    let mut dummy_protocol = MockIssuanceProtocol::default();
    dummy_protocol
        .expect_get_capabilities()
        .once()
        .returning(generic_capabilities);
    let mut protocol_provider = MockIssuanceProtocolProvider::default();
    protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Ok(Arc::new(dummy_protocol)));

    let service = setup_service(Repositories {
        credential_repository,
        credential_schema_repository,
        identifier_repository,
        formatter_provider,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .create_credential(CreateCredentialRequestDTO {
            credential_schema_id: credential.schema.as_ref().await.unwrap().id.to_owned(),
            issuer: None,
            issuer_did: Some(issuer_identifier_did.id()),
            issuer_key: Some(
                issuer_did
                    .as_ref()
                    .await
                    .unwrap()
                    .keys
                    .as_ref()
                    .await
                    .unwrap()[0]
                    .key
                    .id,
            ),
            issuer_certificate: None,
            protocol: "OPENID4VCI_FINAL1".to_string(),
            claim_values: vec![CredentialRequestClaimDTO {
                claim_schema_id: credential.claims.as_ref().await.unwrap()[0]
                    .schema
                    .as_ref()
                    .await
                    .unwrap()
                    .id
                    .to_owned(),
                value: credential.claims.as_ref().await.unwrap()[0]
                    .value
                    .to_owned()
                    .unwrap(),
                path: credential.claims.as_ref().await.unwrap()[0].path.to_owned(),
            }],
            redirect_uri: None,
            profile: None,
            webhook_destination_url: None,
            subscriber_information: None,
            ecosystem: None,
        })
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_create_credential_key_with_issuer_key_and_repeating_key() {
    let mut credential_repository = MockCredentialRepository::default();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut identifier_repository = MockIdentifierRepository::default();

    let credential = generic_credential().await;
    let_assert!(
        Identifier {
            data: IdentifierData::Did(issuer_identifier_did),
            ..
        } = credential
            .issuer_identifier
            .as_ref()
            .unwrap()
            .as_ref()
            .await
            .unwrap()
            .to_owned()
    );
    let key_id = Uuid::new_v4();
    let issuer_did = Did {
        keys: vec![
            RelatedKey {
                role: KeyRole::KeyAgreement,
                key: Key {
                    id: key_id.into(),
                    created_date: crate::clock::now_utc(),
                    last_modified: crate::clock::now_utc(),
                    public_key: vec![],
                    name: "key_name".to_string(),
                    key_reference: None,
                    storage_type: "INTERNAL".to_string(),
                    key_type: "EDDSA".to_string(),
                    organisation: dummy_organisation(None).into(),
                },
                reference: "1".to_string(),
            },
            RelatedKey {
                role: KeyRole::AssertionMethod,
                key: Key {
                    id: key_id.into(),
                    created_date: crate::clock::now_utc(),
                    last_modified: crate::clock::now_utc(),
                    public_key: vec![],
                    name: "key_name".to_string(),
                    key_reference: None,
                    storage_type: "INTERNAL".to_string(),
                    key_type: "EDDSA".to_string(),
                    organisation: dummy_organisation(None).into(),
                },
                reference: "1".to_string(),
            },
        ]
        .into(),
        ..issuer_identifier_did.as_ref().await.unwrap().clone()
    };
    let credential_schema = credential.schema.as_ref().await.unwrap().to_owned();

    identifier_repository
        .expect_get_from_did_id()
        .return_once(|_| {
            Ok(Some(Identifier {
                data: IdentifierData::Did((issuer_did).into()),
                ..dummy_identifier()
            }))
        });

    credential_schema_repository
        .expect_get_credential_schema()
        .times(1)
        .returning(move |_| Ok(credential_schema.clone()));

    credential_repository
        .expect_create_credential()
        .times(1)
        .returning({
            let credential = credential.clone();
            move |_| Ok(credential.id)
        });

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .once()
        .return_once(generic_formatter_capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .with(eq(credential
            .schema
            .as_ref()
            .await
            .unwrap()
            .format()
            .await
            .unwrap()))
        .return_once(move |_| Ok(Arc::new(formatter)));

    let mut dummy_protocol = MockIssuanceProtocol::default();
    dummy_protocol
        .expect_get_capabilities()
        .once()
        .returning(generic_capabilities);
    let mut protocol_provider = MockIssuanceProtocolProvider::default();
    protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Ok(Arc::new(dummy_protocol)));

    let service = setup_service(Repositories {
        credential_repository,
        credential_schema_repository,
        identifier_repository,
        formatter_provider,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .create_credential(CreateCredentialRequestDTO {
            credential_schema_id: credential.schema.as_ref().await.unwrap().id.to_owned(),
            issuer: None,
            issuer_did: Some(issuer_identifier_did.id()),
            issuer_key: Some(key_id.into()),
            issuer_certificate: None,
            protocol: "OPENID4VCI_FINAL1".to_string(),
            claim_values: vec![CredentialRequestClaimDTO {
                claim_schema_id: credential.claims.as_ref().await.unwrap()[0]
                    .schema
                    .as_ref()
                    .await
                    .unwrap()
                    .id
                    .to_owned(),
                value: credential.claims.as_ref().await.unwrap()[0]
                    .value
                    .to_owned()
                    .unwrap(),
                path: credential.claims.as_ref().await.unwrap()[0].path.to_owned(),
            }],
            redirect_uri: None,
            profile: None,
            webhook_destination_url: None,
            subscriber_information: None,
            ecosystem: None,
        })
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_fail_to_create_credential_no_assertion_key() {
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut identifier_repository = MockIdentifierRepository::default();

    let credential = generic_credential().await;
    let_assert!(
        Identifier {
            data: IdentifierData::Did(issuer_identifier_did),
            ..
        } = credential
            .issuer_identifier
            .as_ref()
            .unwrap()
            .as_ref()
            .await
            .unwrap()
            .to_owned()
    );
    let issuer_did = Did {
        keys: vec![RelatedKey {
            role: KeyRole::KeyAgreement,
            key: Key {
                id: Uuid::new_v4().into(),
                created_date: crate::clock::now_utc(),
                last_modified: crate::clock::now_utc(),
                public_key: vec![],
                name: "key_name".to_string(),
                key_reference: None,
                storage_type: "INTERNAL".to_string(),
                key_type: "EDDSA".to_string(),
                organisation: dummy_organisation(None).into(),
            },
            reference: "1".to_string(),
        }]
        .into(),
        ..issuer_identifier_did.as_ref().await.unwrap().clone()
    };

    let credential_schema = credential.schema.as_ref().await.unwrap().to_owned();

    identifier_repository
        .expect_get_from_did_id()
        .return_once(|_| {
            Ok(Some(Identifier {
                data: IdentifierData::Did((issuer_did).into()),
                ..dummy_identifier()
            }))
        });

    credential_schema_repository
        .expect_get_credential_schema()
        .times(1)
        .returning(move |_| Ok(credential_schema.clone()));

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .once()
        .return_once(generic_formatter_capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .with(eq(credential
            .schema
            .as_ref()
            .await
            .unwrap()
            .format()
            .await
            .unwrap()))
        .return_once(move |_| Ok(Arc::new(formatter)));

    let mut dummy_protocol = MockIssuanceProtocol::default();
    dummy_protocol
        .expect_get_capabilities()
        .once()
        .returning(generic_capabilities);
    let mut protocol_provider = MockIssuanceProtocolProvider::default();
    protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Ok(Arc::new(dummy_protocol)));

    let service = setup_service(Repositories {
        credential_schema_repository,
        identifier_repository,
        formatter_provider,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .create_credential(CreateCredentialRequestDTO {
            credential_schema_id: credential.schema.as_ref().await.unwrap().id.to_owned(),
            issuer: None,
            issuer_did: Some(issuer_identifier_did.id()),
            issuer_key: None,
            issuer_certificate: None,
            protocol: "OPENID4VCI_FINAL1".to_string(),
            claim_values: vec![CredentialRequestClaimDTO {
                claim_schema_id: credential.claims.as_ref().await.unwrap()[0]
                    .schema
                    .as_ref()
                    .await
                    .unwrap()
                    .id
                    .to_owned(),
                value: credential.claims.as_ref().await.unwrap()[0]
                    .value
                    .to_owned()
                    .unwrap(),
                path: credential.claims.as_ref().await.unwrap()[0].path.to_owned(),
            }],
            redirect_uri: None,
            profile: None,
            webhook_destination_url: None,
            subscriber_information: None,
            ecosystem: None,
        })
        .await;

    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0330);
}

#[tokio::test]
async fn test_fail_to_create_credential_unknown_key_id() {
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut identifier_repository = MockIdentifierRepository::default();

    let credential = generic_credential().await;
    let_assert!(
        Identifier {
            data: IdentifierData::Did(issuer_identifier_did),
            ..
        } = credential
            .issuer_identifier
            .as_ref()
            .unwrap()
            .as_ref()
            .await
            .unwrap()
            .to_owned()
    );
    let issuer_did = issuer_identifier_did.clone();
    let credential_schema = credential.schema.as_ref().await.unwrap().to_owned();

    identifier_repository
        .expect_get_from_did_id()
        .return_once(|_| {
            Ok(Some(Identifier {
                data: IdentifierData::Did(issuer_did),
                ..dummy_identifier()
            }))
        });

    credential_schema_repository
        .expect_get_credential_schema()
        .times(1)
        .returning(move |_| Ok(credential_schema.clone()));

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .once()
        .return_once(generic_formatter_capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .with(eq(credential
            .schema
            .as_ref()
            .await
            .unwrap()
            .format()
            .await
            .unwrap()))
        .return_once(move |_| Ok(Arc::new(formatter)));

    let mut dummy_protocol = MockIssuanceProtocol::default();
    dummy_protocol
        .expect_get_capabilities()
        .once()
        .returning(generic_capabilities);
    let mut protocol_provider = MockIssuanceProtocolProvider::default();
    protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Ok(Arc::new(dummy_protocol)));

    let service = setup_service(Repositories {
        credential_schema_repository,
        identifier_repository,
        formatter_provider,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .create_credential(CreateCredentialRequestDTO {
            credential_schema_id: credential.schema.as_ref().await.unwrap().id.to_owned(),
            issuer: None,
            issuer_did: Some(issuer_identifier_did.id()),
            issuer_key: Some(Uuid::new_v4().into()),
            issuer_certificate: None,
            protocol: "OPENID4VCI_FINAL1".to_string(),
            claim_values: vec![CredentialRequestClaimDTO {
                claim_schema_id: credential.claims.as_ref().await.unwrap()[0]
                    .schema
                    .as_ref()
                    .await
                    .unwrap()
                    .id
                    .to_owned(),
                value: credential.claims.as_ref().await.unwrap()[0]
                    .value
                    .to_owned()
                    .unwrap(),
                path: credential.claims.as_ref().await.unwrap()[0].path.to_owned(),
            }],
            redirect_uri: None,
            profile: None,
            webhook_destination_url: None,
            subscriber_information: None,
            ecosystem: None,
        })
        .await;

    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0330);
}

#[tokio::test]
async fn test_fail_to_create_credential_key_id_points_to_wrong_key_role() {
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut identifier_repository = MockIdentifierRepository::default();

    let credential = generic_credential().await;
    let_assert!(
        Identifier {
            data: IdentifierData::Did(issuer_identifier_did),
            ..
        } = credential
            .issuer_identifier
            .as_ref()
            .unwrap()
            .as_ref()
            .await
            .unwrap()
            .to_owned()
    );
    let key_id = Uuid::new_v4();
    let issuer_did = Did {
        keys: vec![RelatedKey {
            role: KeyRole::KeyAgreement,
            key: Key {
                id: key_id.into(),
                created_date: crate::clock::now_utc(),
                last_modified: crate::clock::now_utc(),
                public_key: vec![],
                name: "key_name".to_string(),
                key_reference: None,
                storage_type: "INTERNAL".to_string(),
                key_type: "EDDSA".to_string(),
                organisation: dummy_organisation(None).into(),
            },
            reference: "1".to_string(),
        }]
        .into(),
        ..issuer_identifier_did.as_ref().await.unwrap().clone()
    };
    let credential_schema = credential.schema.as_ref().await.unwrap().to_owned();

    identifier_repository
        .expect_get_from_did_id()
        .return_once(|_| {
            Ok(Some(Identifier {
                data: IdentifierData::Did((issuer_did).into()),
                ..dummy_identifier()
            }))
        });

    credential_schema_repository
        .expect_get_credential_schema()
        .times(1)
        .returning(move |_| Ok(credential_schema.clone()));

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .once()
        .return_once(generic_formatter_capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .with(eq(credential
            .schema
            .as_ref()
            .await
            .unwrap()
            .format()
            .await
            .unwrap()))
        .return_once(move |_| Ok(Arc::new(formatter)));

    let mut dummy_protocol = MockIssuanceProtocol::default();
    dummy_protocol
        .expect_get_capabilities()
        .once()
        .returning(generic_capabilities);
    let mut protocol_provider = MockIssuanceProtocolProvider::default();
    protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Ok(Arc::new(dummy_protocol)));

    let service = setup_service(Repositories {
        credential_schema_repository,
        identifier_repository,
        formatter_provider,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .create_credential(CreateCredentialRequestDTO {
            credential_schema_id: credential.schema.as_ref().await.unwrap().id.to_owned(),
            issuer: None,
            issuer_did: Some(issuer_identifier_did.id()),
            issuer_key: Some(key_id.into()),
            issuer_certificate: None,
            protocol: "OPENID4VCI_FINAL1".to_string(),
            claim_values: vec![CredentialRequestClaimDTO {
                claim_schema_id: credential.claims.as_ref().await.unwrap()[0]
                    .schema
                    .as_ref()
                    .await
                    .unwrap()
                    .id
                    .to_owned(),
                value: credential.claims.as_ref().await.unwrap()[0]
                    .value
                    .to_owned()
                    .unwrap(),
                path: credential.claims.as_ref().await.unwrap()[0].path.to_owned(),
            }],
            redirect_uri: None,
            profile: None,
            webhook_destination_url: None,
            subscriber_information: None,
            ecosystem: None,
        })
        .await;

    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0330);
}

#[tokio::test]
async fn test_fail_to_create_credential_key_id_points_to_unsupported_key_algorithm() {
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut identifier_repository = MockIdentifierRepository::default();

    let credential = generic_credential().await;
    let_assert!(
        Identifier {
            data: IdentifierData::Did(issuer_identifier_did),
            ..
        } = credential
            .issuer_identifier
            .as_ref()
            .unwrap()
            .as_ref()
            .await
            .unwrap()
            .to_owned()
    );
    let key_id = Uuid::new_v4();
    let issuer_did = Did {
        keys: vec![RelatedKey {
            role: KeyRole::AssertionMethod,
            key: Key {
                id: key_id.into(),
                created_date: crate::clock::now_utc(),
                last_modified: crate::clock::now_utc(),
                public_key: vec![],
                name: "key_name".to_string(),
                key_reference: None,
                storage_type: "INTERNAL".to_string(),
                key_type: "unsupported".to_string(),
                organisation: dummy_organisation(None).into(),
            },
            reference: "1".to_string(),
        }]
        .into(),
        ..issuer_identifier_did.as_ref().await.unwrap().clone()
    };
    let credential_schema = credential.schema.as_ref().await.unwrap().to_owned();

    identifier_repository
        .expect_get_from_did_id()
        .return_once(|_| {
            Ok(Some(Identifier {
                data: IdentifierData::Did((issuer_did).into()),
                ..dummy_identifier()
            }))
        });

    credential_schema_repository
        .expect_get_credential_schema()
        .times(1)
        .returning(move |_| Ok(credential_schema.clone()));

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .once()
        .return_once(generic_formatter_capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .with(eq(credential
            .schema
            .as_ref()
            .await
            .unwrap()
            .format()
            .await
            .unwrap()))
        .return_once(move |_| Ok(Arc::new(formatter)));

    let mut dummy_protocol = MockIssuanceProtocol::default();
    dummy_protocol
        .expect_get_capabilities()
        .once()
        .returning(generic_capabilities);
    let mut protocol_provider = MockIssuanceProtocolProvider::default();
    protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Ok(Arc::new(dummy_protocol)));

    let service = setup_service(Repositories {
        credential_schema_repository,
        identifier_repository,
        formatter_provider,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .create_credential(CreateCredentialRequestDTO {
            credential_schema_id: credential.schema.as_ref().await.unwrap().id.to_owned(),
            issuer: None,
            issuer_did: Some(issuer_identifier_did.id()),
            issuer_key: Some(key_id.into()),
            issuer_certificate: None,
            protocol: "OPENID4VCI_FINAL1".to_string(),
            claim_values: vec![CredentialRequestClaimDTO {
                claim_schema_id: credential.claims.as_ref().await.unwrap()[0]
                    .schema
                    .as_ref()
                    .await
                    .unwrap()
                    .id
                    .to_owned(),
                value: credential.claims.as_ref().await.unwrap()[0]
                    .value
                    .to_owned()
                    .unwrap(),
                path: credential.claims.as_ref().await.unwrap()[0].path.to_owned(),
            }],
            redirect_uri: None,
            profile: None,
            webhook_destination_url: None,
            subscriber_information: None,
            ecosystem: None,
        })
        .await;

    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0330);
}

#[tokio::test]
async fn test_create_credential_fail_incompatible_format_and_tranposrt_protocol() {
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut identifier_repository = MockIdentifierRepository::default();

    let credential = generic_credential().await;
    let_assert!(
        Identifier {
            data: IdentifierData::Did(issuer_identifier_did),
            ..
        } = credential
            .issuer_identifier
            .as_ref()
            .unwrap()
            .as_ref()
            .await
            .unwrap()
            .to_owned()
    );
    {
        let credential_schema = credential.schema.as_ref().await.unwrap().to_owned();
        credential_schema_repository
            .expect_get_credential_schema()
            .times(1)
            .returning(move |_| Ok(credential_schema.clone()));
    }

    let issuer_did = issuer_identifier_did.clone();
    identifier_repository
        .expect_get_from_did_id()
        .return_once(|_| {
            Ok(Some(Identifier {
                data: IdentifierData::Did(issuer_did),
                ..dummy_identifier()
            }))
        });

    let mut formatter_capabilities = generic_formatter_capabilities();
    formatter_capabilities.issuance_exchange_protocols = vec![];

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .once()
        .return_once(|| formatter_capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .with(eq(credential
            .schema
            .as_ref()
            .await
            .unwrap()
            .format()
            .await
            .unwrap()))
        .return_once(move |_| Ok(Arc::new(formatter)));

    let mut dummy_protocol = MockIssuanceProtocol::default();
    dummy_protocol
        .expect_get_capabilities()
        .once()
        .returning(generic_capabilities);
    let mut protocol_provider = MockIssuanceProtocolProvider::default();
    protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Ok(Arc::new(dummy_protocol)));

    let service = setup_service(Repositories {
        credential_schema_repository,
        identifier_repository,
        formatter_provider,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .create_credential(CreateCredentialRequestDTO {
            credential_schema_id: credential.schema.as_ref().await.unwrap().id.to_owned(),
            issuer: None,
            issuer_did: Some(issuer_identifier_did.id()),
            issuer_key: None,
            issuer_certificate: None,
            protocol: "OPENID4VCI_FINAL1".to_string(),
            claim_values: vec![CredentialRequestClaimDTO {
                claim_schema_id: credential.claims.as_ref().await.unwrap()[0]
                    .schema
                    .as_ref()
                    .await
                    .unwrap()
                    .id
                    .to_owned(),
                value: credential.claims.as_ref().await.unwrap()[0]
                    .value
                    .to_owned()
                    .unwrap(),
                path: credential.claims.as_ref().await.unwrap()[0].path.to_owned(),
            }],
            redirect_uri: None,
            profile: None,
            webhook_destination_url: None,
            subscriber_information: None,
            ecosystem: None,
        })
        .await;

    assert!(matches!(
        result,
        Err(CredentialServiceError::IncompatibleIssuanceExchangeProtocol)
    ));
}

#[tokio::test]
async fn test_create_credential_fail_invalid_redirect_uri() {
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut identifier_repository = MockIdentifierRepository::default();

    let credential = generic_credential().await;
    let_assert!(
        Identifier {
            data: IdentifierData::Did(issuer_identifier_did),
            ..
        } = credential
            .issuer_identifier
            .as_ref()
            .unwrap()
            .as_ref()
            .await
            .unwrap()
            .to_owned()
    );
    let issuer_did = issuer_identifier_did.clone();
    let credential_schema = credential.schema.as_ref().await.unwrap().to_owned();

    identifier_repository.expect_get_from_did_id().return_once({
        let issuer_did = issuer_did.clone();
        |_| {
            Ok(Some(Identifier {
                data: IdentifierData::Did(issuer_did),
                ..dummy_identifier()
            }))
        }
    });

    credential_schema_repository
        .expect_get_credential_schema()
        .times(1)
        .returning(move |_| Ok(credential_schema.clone()));

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .once()
        .return_once(generic_formatter_capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .with(eq(credential
            .schema
            .as_ref()
            .await
            .unwrap()
            .format()
            .await
            .unwrap()))
        .return_once(move |_| Ok(Arc::new(formatter)));

    let mut dummy_protocol = MockIssuanceProtocol::default();
    dummy_protocol
        .expect_get_capabilities()
        .once()
        .returning(generic_capabilities);
    let mut protocol_provider = MockIssuanceProtocolProvider::default();
    protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Ok(Arc::new(dummy_protocol)));

    let service = setup_service(Repositories {
        credential_schema_repository,
        identifier_repository,
        formatter_provider,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .create_credential(CreateCredentialRequestDTO {
            credential_schema_id: credential.schema.as_ref().await.unwrap().id.to_owned(),
            issuer: None,
            issuer_did: Some(issuer_identifier_did.id()),
            issuer_key: Some(
                issuer_did
                    .as_ref()
                    .await
                    .unwrap()
                    .keys
                    .as_ref()
                    .await
                    .unwrap()[0]
                    .key
                    .id,
            ),
            issuer_certificate: None,
            protocol: "OPENID4VCI_FINAL1".to_string(),
            claim_values: vec![CredentialRequestClaimDTO {
                claim_schema_id: credential.claims.as_ref().await.unwrap()[0]
                    .schema
                    .as_ref()
                    .await
                    .unwrap()
                    .id
                    .to_owned(),
                value: credential.claims.as_ref().await.unwrap()[0]
                    .value
                    .to_owned()
                    .unwrap(),
                path: credential.claims.as_ref().await.unwrap()[0].path.to_owned(),
            }],
            redirect_uri: Some("invalid://domain.com".to_string()),
            profile: None,
            webhook_destination_url: None,
            subscriber_information: None,
            ecosystem: None,
        })
        .await;

    assert!(matches!(
        result,
        Err(CredentialServiceError::InvalidRedirectUri)
    ));
}

#[tokio::test]
async fn test_create_credential_fail_webhook_not_allowed() {
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut identifier_repository = MockIdentifierRepository::default();

    let credential = generic_credential().await;
    {
        let issuer_identifier = credential
            .issuer_identifier
            .as_ref()
            .unwrap()
            .as_ref()
            .await
            .unwrap()
            .to_owned();
        let credential_schema = credential.schema.as_ref().await.unwrap().to_owned();

        identifier_repository
            .expect_get()
            .return_once(|_| Ok(issuer_identifier));

        credential_schema_repository
            .expect_get_credential_schema()
            .times(1)
            .returning(move |_| Ok(credential_schema.clone()));
    }

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .once()
        .return_once(generic_formatter_capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::default();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .with(eq(credential
            .schema
            .as_ref()
            .await
            .unwrap()
            .format()
            .await
            .unwrap()))
        .return_once(move |_| Ok(Arc::new(formatter)));

    let mut dummy_protocol = MockIssuanceProtocol::default();
    dummy_protocol
        .expect_get_capabilities()
        .once()
        .returning(generic_capabilities);
    let mut protocol_provider = MockIssuanceProtocolProvider::default();
    protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Ok(Arc::new(dummy_protocol)));

    let service = setup_service(Repositories {
        credential_schema_repository,
        identifier_repository,
        formatter_provider,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service
        .create_credential(CreateCredentialRequestDTO {
            credential_schema_id: credential.schema.as_ref().await.unwrap().id.to_owned(),
            issuer: Some(credential.issuer_identifier.as_ref().unwrap().id()),
            issuer_did: None,
            issuer_key: None,
            issuer_certificate: None,
            protocol: "OPENID4VCI_FINAL1".to_string(),
            claim_values: vec![CredentialRequestClaimDTO {
                claim_schema_id: credential.claims.as_ref().await.unwrap()[0]
                    .schema
                    .as_ref()
                    .await
                    .unwrap()
                    .id
                    .to_owned(),
                value: credential.claims.as_ref().await.unwrap()[0]
                    .value
                    .to_owned()
                    .unwrap(),
                path: credential.claims.as_ref().await.unwrap()[0].path.to_owned(),
            }],
            redirect_uri: None,
            profile: None,
            webhook_destination_url: Some("http://webhook.url".to_string()),
            subscriber_information: None,
            ecosystem: None,
        })
        .await;

    assert2::assert!(
        let CredentialServiceError::NotificationsNotAllowed {..} = result.err().unwrap()
    );
}

fn generate_credential_schema_with_claim_schemas(
    claim_schemas: Vec<ClaimSchema>,
) -> CredentialSchema {
    let now = crate::clock::now_utc();
    let credential_schema_id = Uuid::new_v4().into();
    CredentialSchema {
        expiration: None,
        ecosystem: None,
        batch_size: None,
        allow_revocation: false,
        id: credential_schema_id,
        deleted_at: None,
        imported_source_url: "CORE_URL".to_string(),
        created_date: now,
        last_modified: now,
        name: "nested".to_string(),
        key_storage_security: None,
        layout_properties: None,
        allow_suspension: true,
        requires_wallet_instance_attestation: false,
        claim_schemas: claim_schemas.into(),
        organisation: dummy_organisation(None).into(),
        formats: vec![CredentialSchemaFormat {
            id: Uuid::new_v4().into(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            credential_schema_id,
            format: "".into(),
            ecosystem_schema_id: "".to_owned(),
            claim_mappings: Default::default(),
        }]
        .into(),
        transaction_code: None,
        translations: Default::default(),
        embedded_disclosure_policy: None,
    }
}

#[tokio::test]
async fn test_validate_create_request_all_nested_claims_are_required() {
    let address_claim_id = Uuid::new_v4().into();
    let location_claim_id = Uuid::new_v4().into();
    let location_x_claim_id = Uuid::new_v4().into();
    let location_y_claim_id = Uuid::new_v4().into();

    let now = crate::clock::now_utc();
    let schema = generate_credential_schema_with_claim_schemas(vec![
        ClaimSchema {
            array: false,
            id: address_claim_id,
            key: "address".to_string(),
            data_type: "STRING".to_string(),
            created_date: now,
            last_modified: now,
            metadata: false,
            required: true,
            translations: Default::default(),
        },
        ClaimSchema {
            array: false,
            id: location_claim_id,
            key: "location".to_string(),
            data_type: "OBJECT".to_string(),
            created_date: now,
            last_modified: now,
            metadata: false,
            required: true,
            translations: Default::default(),
        },
        ClaimSchema {
            array: false,
            id: location_x_claim_id,
            key: "location/x".to_string(),
            data_type: "STRING".to_string(),
            created_date: now,
            last_modified: now,
            metadata: false,
            required: true,
            translations: Default::default(),
        },
        ClaimSchema {
            array: false,
            id: location_y_claim_id,
            key: "location/y".to_string(),
            data_type: "STRING".to_string(),
            created_date: now,
            last_modified: now,
            metadata: false,
            required: true,
            translations: Default::default(),
        },
    ]);

    validate_create_request(
        "OPENID4VCI_FINAL1",
        &mut [
            CredentialRequestClaimDTO {
                claim_schema_id: address_claim_id,
                value: "Somewhere".to_string(),
                path: "address".to_string(),
            },
            CredentialRequestClaimDTO {
                claim_schema_id: location_x_claim_id,
                value: "123".to_string(),
                path: "location/x".to_string(),
            },
            CredentialRequestClaimDTO {
                claim_schema_id: location_y_claim_id,
                value: "456".to_string(),
                path: "location/y".to_string(),
            },
        ],
        &schema,
        &generic_formatter_capabilities(),
        &generic_config().core,
    )
    .await
    .unwrap();
}

fn generic_capabilities() -> IssuanceProtocolCapabilities {
    IssuanceProtocolCapabilities {
        features: vec![crate::provider::issuance_protocol::dto::Features::SupportsRejection],
        did_methods: vec![crate::config::core_config::DidType::Key],
    }
}

#[tokio::test]
async fn test_validate_create_request_all_optional_nested_object_with_required_claims() {
    let address_claim_id = Uuid::new_v4().into();
    let location_claim_id = Uuid::new_v4().into();
    let location_x_claim_id = Uuid::new_v4().into();
    let location_y_claim_id = Uuid::new_v4().into();

    let now = crate::clock::now_utc();
    let schema = generate_credential_schema_with_claim_schemas(vec![
        ClaimSchema {
            array: false,
            id: address_claim_id,
            key: "address".to_string(),
            data_type: "STRING".to_string(),
            created_date: now,
            last_modified: now,
            metadata: false,
            required: true,
            translations: Default::default(),
        },
        ClaimSchema {
            array: false,
            id: location_claim_id,
            key: "location".to_string(),
            data_type: "OBJECT".to_string(),
            created_date: now,
            last_modified: now,
            metadata: false,
            required: false,
            translations: Default::default(),
        },
        ClaimSchema {
            array: false,
            id: location_x_claim_id,
            key: "location/x".to_string(),
            data_type: "STRING".to_string(),
            created_date: now,
            last_modified: now,
            metadata: false,
            required: true,
            translations: Default::default(),
        },
        ClaimSchema {
            array: false,
            id: location_y_claim_id,
            key: "location/y".to_string(),
            data_type: "STRING".to_string(),
            created_date: now,
            last_modified: now,
            metadata: false,
            required: true,
            translations: Default::default(),
        },
    ]);

    validate_create_request(
        "OPENID4VCI_FINAL1",
        &mut [
            CredentialRequestClaimDTO {
                claim_schema_id: address_claim_id,
                value: "Somewhere".to_string(),
                path: "address".to_string(),
            },
            CredentialRequestClaimDTO {
                claim_schema_id: location_x_claim_id,
                value: "123".to_string(),
                path: "location/x".to_string(),
            },
            CredentialRequestClaimDTO {
                claim_schema_id: location_y_claim_id,
                value: "456".to_string(),
                path: "location/y".to_string(),
            },
        ],
        &schema,
        &generic_formatter_capabilities(),
        &generic_config().core,
    )
    .await
    .unwrap();

    validate_create_request(
        "OPENID4VCI_FINAL1",
        &mut [CredentialRequestClaimDTO {
            claim_schema_id: address_claim_id,
            value: "Somewhere".to_string(),
            path: "address".to_string(),
        }],
        &schema,
        &generic_formatter_capabilities(),
        &generic_config().core,
    )
    .await
    .unwrap();

    let result = validate_create_request(
        "OPENID4VCI_FINAL1",
        &mut [
            CredentialRequestClaimDTO {
                claim_schema_id: address_claim_id,
                value: "Somewhere".to_string(),
                path: "address".to_string(),
            },
            CredentialRequestClaimDTO {
                claim_schema_id: location_x_claim_id,
                value: "123".to_string(),
                path: "location/x".to_string(),
            },
        ],
        &schema,
        &generic_formatter_capabilities(),
        &generic_config().core,
    )
    .await;
    assert!(matches!(
        result,
        Err(CredentialServiceError::MissingClaimSchema(_))
    ));
}

#[tokio::test]
async fn test_validate_create_request_all_required_nested_object_with_optional_claims() {
    let address_claim_id = Uuid::new_v4().into();
    let location_claim_id = Uuid::new_v4().into();
    let location_x_claim_id = Uuid::new_v4().into();
    let location_y_claim_id = Uuid::new_v4().into();

    let now = crate::clock::now_utc();
    let schema = generate_credential_schema_with_claim_schemas(vec![
        ClaimSchema {
            array: false,
            id: address_claim_id,
            key: "address".to_string(),
            data_type: "STRING".to_string(),
            created_date: now,
            last_modified: now,
            metadata: false,
            required: true,
            translations: Default::default(),
        },
        ClaimSchema {
            array: false,
            id: location_claim_id,
            key: "location".to_string(),
            data_type: "OBJECT".to_string(),
            created_date: now,
            last_modified: now,
            metadata: false,
            required: true,
            translations: Default::default(),
        },
        ClaimSchema {
            array: false,
            id: location_x_claim_id,
            key: "location/x".to_string(),
            data_type: "STRING".to_string(),
            created_date: now,
            last_modified: now,
            metadata: false,
            required: true,
            translations: Default::default(),
        },
        ClaimSchema {
            array: false,
            id: location_y_claim_id,
            key: "location/y".to_string(),
            data_type: "STRING".to_string(),
            created_date: now,
            last_modified: now,
            metadata: false,
            required: false,
            translations: Default::default(),
        },
    ]);

    validate_create_request(
        "OPENID4VCI_FINAL1",
        &mut [
            CredentialRequestClaimDTO {
                claim_schema_id: address_claim_id,
                value: "Somewhere".to_string(),
                path: "address".to_string(),
            },
            CredentialRequestClaimDTO {
                claim_schema_id: location_x_claim_id,
                value: "123".to_string(),
                path: "location/x".to_string(),
            },
            CredentialRequestClaimDTO {
                claim_schema_id: location_y_claim_id,
                value: "456".to_string(),
                path: "location/y".to_string(),
            },
        ],
        &schema,
        &generic_formatter_capabilities(),
        &generic_config().core,
    )
    .await
    .unwrap();

    let result = validate_create_request(
        "OPENID4VCI_FINAL1",
        &mut [CredentialRequestClaimDTO {
            claim_schema_id: address_claim_id,
            value: "Somewhere".to_string(),
            path: "address".to_string(),
        }],
        &schema,
        &generic_formatter_capabilities(),
        &generic_config().core,
    )
    .await;
    assert!(matches!(
        result,
        Err(CredentialServiceError::MissingClaimSchema(_))
    ));

    validate_create_request(
        "OPENID4VCI_FINAL1",
        &mut [
            CredentialRequestClaimDTO {
                claim_schema_id: address_claim_id,
                value: "Somewhere".to_string(),
                path: "address".to_string(),
            },
            CredentialRequestClaimDTO {
                claim_schema_id: location_x_claim_id,
                value: "123".to_string(),
                path: "location/x".to_string(),
            },
        ],
        &schema,
        &generic_formatter_capabilities(),
        &generic_config().core,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn test_get_credential_success_with_non_required_nested_object() {
    let mut credential_repository = MockCredentialRepository::default();

    let now = crate::clock::now_utc();

    let location_claim_schema = ClaimSchema {
        array: false,
        id: Uuid::new_v4().into(),
        key: "location".to_string(),
        data_type: "OBJECT".to_string(),
        created_date: now,
        last_modified: now,
        metadata: false,
        required: false,
        translations: Default::default(),
    };
    let location_x_claim_schema = ClaimSchema {
        array: false,
        id: Uuid::new_v4().into(),
        key: "location/X".to_string(),
        data_type: "STRING".to_string(),
        created_date: now,
        last_modified: now,
        metadata: false,
        required: false,
        translations: Default::default(),
    };

    let mut credential = generic_credential().await;

    credential.schema.as_mut().await.unwrap().claim_schemas =
        vec![location_claim_schema, location_x_claim_schema.to_owned()].into();

    let updated_schema = credential.schema.as_ref().await.unwrap().to_owned();
    credential.schema = backfill_default_translations(updated_schema, "en")
        .await
        .unwrap()
        .into();
    *credential.claims.as_mut().await.unwrap() = vec![Claim {
        id: Uuid::new_v4().into(),
        credential_id: credential.id,
        created_date: now,
        last_modified: now,
        value: Some("123".to_string()),
        path: location_x_claim_schema.key.clone(),
        selectively_disclosable: false,
        schema: location_x_claim_schema.clone().into(),
    }];

    {
        let clone = credential.clone();
        credential_repository
            .expect_get_credential()
            .times(1)
            .with(eq(clone.id))
            .returning(move |_| Ok(clone.clone()));
    }

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .return_once(|_| {
            let mut formatter = MockCredentialFormatter::new();
            formatter.expect_revocation_method_id().return_const(None);
            Ok(Arc::new(formatter))
        });

    let service = setup_service(Repositories {
        credential_repository,
        formatter_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.get_credential(&credential.id).await.unwrap();
    assert_eq!(credential.id, result.id);
    assert_eq!(None, result.revocation_date);
    assert_eq!(1, result.claims.len());
    assert_eq!("location", result.claims[0].schema.key);
    assert!(matches!(
        result.claims[0].value,
        DetailCredentialClaimValueResponseDTO::Nested(_)
    ));
}

fn generate_claim_schema(key: &str, datatype: &str, array: bool) -> ClaimSchema {
    let now = get_dummy_date();
    ClaimSchema {
        array,
        id: Uuid::new_v4().into(),
        key: key.to_string(),
        data_type: datatype.to_string(),
        created_date: now,
        last_modified: now,
        metadata: false,
        required: true,
        translations: Default::default(),
    }
}

fn generate_claim(
    credential_id: CredentialId,
    claim_schema: &ClaimSchema,
    value: &str,
    path: &str,
) -> Claim {
    let now = get_dummy_date();

    Claim {
        id: Uuid::new_v4().into(),
        credential_id,
        created_date: now,
        last_modified: now,
        value: Some(value.to_string()),
        path: path.to_string(),
        selectively_disclosable: false,
        schema: claim_schema.to_owned().into(),
    }
}

#[tokio::test]
async fn test_get_credential_success_array_complex_nested_all() {
    let mut credential_repository = MockCredentialRepository::default();

    let now = get_dummy_date();

    let schema_root = generate_claim_schema("root", "OBJECT", true);
    let schema_root_index_list = generate_claim_schema("root/indexlist", "NUMBER", true);
    let schema_root_name = generate_claim_schema("root/name", "STRING", false);
    let schema_root_cap = generate_claim_schema("root/cap", "STRING", true);

    let schema_other = generate_claim_schema("other", "OBJECT", false);
    let schema_other_0 = generate_claim_schema("other/0", "OBJECT", true);
    let schema_other_0_name = generate_claim_schema("other/0/name", "STRING", false);
    let schema_other_1 = generate_claim_schema("other/1", "STRING", true);

    let schema_str = generate_claim_schema("str", "STRING", true);

    let claim_schemas = vec![
        schema_root.to_owned(),
        schema_root_index_list.to_owned(),
        schema_root_name.to_owned(),
        schema_root_cap.to_owned(),
        schema_other.to_owned(),
        schema_other_0.to_owned(),
        schema_other_0_name.to_owned(),
        schema_other_1.to_owned(),
        schema_str.to_owned(),
    ];
    let organisation = dummy_organisation(None);

    let id = Uuid::new_v4().into();

    let claims = vec![
        generate_claim(id, &schema_root_index_list, "123", "root/0/indexlist/0"),
        generate_claim(id, &schema_root_index_list, "123", "root/0/indexlist/1"),
        generate_claim(id, &schema_root_name, "123", "root/0/name"),
        generate_claim(id, &schema_root_cap, "invoke", "root/0/cap/0"),
        generate_claim(id, &schema_root_cap, "revoke", "root/0/cap/1"),
        generate_claim(id, &schema_root_cap, "delete", "root/0/cap/2"),
        generate_claim(id, &schema_root_index_list, "456", "root/1/indexlist/0"),
        generate_claim(id, &schema_root_index_list, "456", "root/1/indexlist/1"),
        generate_claim(id, &schema_root_name, "456", "root/1/name"),
        generate_claim(id, &schema_root_cap, "invoke", "root/1/cap/0"),
        generate_claim(id, &schema_root_cap, "revoke", "root/1/cap/1"),
        generate_claim(id, &schema_root_cap, "delete", "root/1/cap/2"),
        generate_claim(id, &schema_other_0_name, "name1", "other/0/0/name"),
        generate_claim(id, &schema_other_0_name, "name2", "other/0/1/name"),
        generate_claim(id, &schema_other_1, "other1", "other/1/0"),
        generate_claim(id, &schema_other_1, "other2", "other/1/1"),
        generate_claim(id, &schema_other_1, "other3", "other/1/2"),
        generate_claim(id, &schema_str, "str1", "str/0"),
        generate_claim(id, &schema_str, "str1", "str/1"),
        generate_claim(id, &schema_str, "str1", "str/2"),
    ];

    let credential_schema_id = Uuid::new_v4().into();
    let format = CredentialSchemaFormat {
        id: Uuid::new_v4().into(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        credential_schema_id,
        format: "JWT".into(),
        ecosystem_schema_id: "CredentialSchemaId".to_owned(),
        claim_mappings: Default::default(),
    };
    let credential = Credential {
        expires_at: None,
        ecosystem: None,
        id,
        created_date: now,
        issuance_date: None,
        last_modified: now,
        deleted_at: None,
        consumed_at: None,
        protocol: "OPENID4VCI_FINAL1".to_string(),
        redirect_uri: None,
        role: CredentialRole::Issuer,
        r#type: CredentialType::Single,
        state: CredentialStateEnum::Created,
        suspend_end_date: None,
        claims: claims.to_owned().into(),
        issuer_identifier: Some(
            Identifier {
                id: Uuid::new_v4().into(),
                created_date: now,
                last_modified: now,
                name: "identifier".to_string(),
                data: IdentifierData::Did(
                    (Did {
                        deleted_at: None,
                        id: Uuid::new_v4().into(),
                        created_date: now,
                        last_modified: now,
                        name: "did1".to_string(),
                        organisation: organisation.clone().into(),
                        did: "did:example:1".parse().unwrap(),
                        did_type: DidType::Local,
                        did_method: "KEY".into(),
                        keys: vec![RelatedKey {
                            role: KeyRole::AssertionMethod,
                            key: Key {
                                id: Uuid::new_v4().into(),
                                created_date: crate::clock::now_utc(),
                                last_modified: crate::clock::now_utc(),
                                public_key: vec![],
                                name: "key_name".to_string(),
                                key_reference: None,
                                storage_type: "INTERNAL".to_string(),
                                key_type: "EDDSA".to_string(),
                                organisation: organisation.clone().into(),
                            },
                            reference: "1".to_string(),
                        }]
                        .into(),
                        deactivated: false,
                        log: None,
                    })
                    .into(),
                ),
                is_remote: false,
                state: IdentifierState::Active,
                deleted_at: None,
                organisation: dummy_organisation(Some(uuid::Uuid::new_v4().into())).into(),
                trust_information: Default::default(),
            }
            .into(),
        ),
        issuer_certificate: None,
        holder_identifier: None,
        schema: (backfill_default_translations(
            CredentialSchema {
                expiration: None,
                ecosystem: None,
                batch_size: None,
                allow_revocation: false,
                id: credential_schema_id,
                deleted_at: None,
                created_date: now,
                imported_source_url: "CORE_URL".to_string(),
                last_modified: now,
                name: "schema".to_string(),
                key_storage_security: None,
                formats: vec![format.clone()].into(),
                claim_schemas: claim_schemas.into(),
                organisation: organisation.into(),
                layout_properties: None,
                allow_suspension: true,
                requires_wallet_instance_attestation: false,
                transaction_code: None,
                translations: Default::default(),
                embedded_disclosure_policy: None,
            },
            "en",
        )
        .await
        .unwrap())
        .into(),
        interaction: None,
        key: None,
        profile: None,
        credential_blob_id: None,
        wallet_unit_attestation_blob_id: None,
        wallet_instance_attestation_blob_id: None,
        webhook_url: None,
        parent: None,
        embedded_disclosure_policy: None,
        subscriber_information: None,
        format: Some(format.into()),
    };

    {
        let clone = credential.clone();
        credential_repository
            .expect_get_credential()
            .times(1)
            .with(eq(clone.id))
            .returning(move |_| Ok(clone.clone()));
    }

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .return_once(|_| {
            let mut formatter = MockCredentialFormatter::new();
            formatter.expect_revocation_method_id().return_const(None);
            Ok(Arc::new(formatter))
        });

    let service = setup_service(Repositories {
        credential_repository,
        formatter_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.get_credential(&credential.id).await.unwrap();

    let expected_claims = json!([
      {
        "path": "root",
        "schema": {
          "id": schema_root.id,
          "createdDate": "2005-04-02T21:37:00+01:00",
          "lastModified": "2005-04-02T21:37:00+01:00",
          "key": "root",
          "datatype": "OBJECT",
          "required": true,
          "array": true,
          "translations": {
            "name": {
              "en": "root"
            }
          }
        },
        "value": [
          {
            "path": "root/0",
            "schema": {
              "id": schema_root.id,
              "createdDate": "2005-04-02T21:37:00+01:00",
              "lastModified": "2005-04-02T21:37:00+01:00",
              "key": "root",
              "datatype": "OBJECT",
              "required": true,
              "array": false,
              "translations": {
                "name": {
                  "en": "root"
                }
              }
            },
            "value": [
              {
                "path": "root/0/indexlist",
                "schema": {
                  "id": schema_root_index_list.id,
                  "createdDate": "2005-04-02T21:37:00+01:00",
                  "lastModified": "2005-04-02T21:37:00+01:00",
                  "key": "root/indexlist",
                  "datatype": "NUMBER",
                  "required": true,
                  "array": true,
                  "translations": {
                    "name": {
                      "en": "indexlist"
                    }
                  }
                },
                "value": [
                  {
                    "path": "root/0/indexlist/0",
                    "schema": {
                      "id": schema_root_index_list.id,
                      "createdDate": "2005-04-02T21:37:00+01:00",
                      "lastModified": "2005-04-02T21:37:00+01:00",
                      "key": "root/indexlist",
                      "datatype": "NUMBER",
                      "required": true,
                      "array": false,
                      "translations": {
                        "name": {
                          "en": "indexlist"
                        }
                      }
                    },
                    "value": 123
                  },
                  {
                    "path": "root/0/indexlist/1",
                    "schema": {
                      "id": schema_root_index_list.id,
                      "createdDate": "2005-04-02T21:37:00+01:00",
                      "lastModified": "2005-04-02T21:37:00+01:00",
                      "key": "root/indexlist",
                      "datatype": "NUMBER",
                      "required": true,
                      "array": false,
                      "translations": {
                        "name": {
                          "en": "indexlist"
                        }
                      }
                    },
                    "value": 123
                  }
                ]
              },
              {
                "path": "root/0/name",
                "schema": {
                  "id": schema_root_name.id,
                  "createdDate": "2005-04-02T21:37:00+01:00",
                  "lastModified": "2005-04-02T21:37:00+01:00",
                  "key": "root/name",
                  "datatype": "STRING",
                  "required": true,
                  "array": false,
                  "translations": {
                    "name": {
                      "en": "name"
                    }
                  }
                },
                "value": "123"
              },
              {
                "path": "root/0/cap",
                "schema": {
                  "id": schema_root_cap.id,
                  "createdDate": "2005-04-02T21:37:00+01:00",
                  "lastModified": "2005-04-02T21:37:00+01:00",
                  "key": "root/cap",
                  "datatype": "STRING",
                  "required": true,
                  "array": true,
                  "translations": {
                    "name": {
                      "en": "cap"
                    }
                  }
                },
                "value": [
                  {
                    "path": "root/0/cap/0",
                    "schema": {
                      "id": schema_root_cap.id,
                      "createdDate": "2005-04-02T21:37:00+01:00",
                      "lastModified": "2005-04-02T21:37:00+01:00",
                      "key": "root/cap",
                      "datatype": "STRING",
                      "required": true,
                      "array": false,
                      "translations": {
                        "name": {
                          "en": "cap"
                        }
                      }
                    },
                    "value": "invoke"
                  },
                  {
                    "path": "root/0/cap/1",
                    "schema": {
                      "id": schema_root_cap.id,
                      "createdDate": "2005-04-02T21:37:00+01:00",
                      "lastModified": "2005-04-02T21:37:00+01:00",
                      "key": "root/cap",
                      "datatype": "STRING",
                      "required": true,
                      "array": false,
                      "translations": {
                        "name": {
                          "en": "cap"
                        }
                      }
                    },
                    "value": "revoke"
                  },
                  {
                    "path": "root/0/cap/2",
                    "schema": {
                      "id": schema_root_cap.id,
                      "createdDate": "2005-04-02T21:37:00+01:00",
                      "lastModified": "2005-04-02T21:37:00+01:00",
                      "key": "root/cap",
                      "datatype": "STRING",
                      "required": true,
                      "array": false,
                      "translations": {
                        "name": {
                          "en": "cap"
                        }
                      }
                    },
                    "value": "delete"
                  }
                ]
              }
            ]
          },
          {
            "path": "root/1",
            "schema": {
              "id": schema_root.id,
              "createdDate": "2005-04-02T21:37:00+01:00",
              "lastModified": "2005-04-02T21:37:00+01:00",
              "key": "root",
              "datatype": "OBJECT",
              "required": true,
              "array": false,
              "translations": {
                "name": {
                  "en": "root"
                }
              }
            },
            "value": [
              {
                "path": "root/1/indexlist",
                "schema": {
                  "id": schema_root_index_list.id,
                  "createdDate": "2005-04-02T21:37:00+01:00",
                  "lastModified": "2005-04-02T21:37:00+01:00",
                  "key": "root/indexlist",
                  "datatype": "NUMBER",
                  "required": true,
                  "array": true,
                  "translations": {
                    "name": {
                      "en": "indexlist"
                    }
                  }
                },
                "value": [
                  {
                    "path": "root/1/indexlist/0",
                    "schema": {
                      "id": schema_root_index_list.id,
                      "createdDate": "2005-04-02T21:37:00+01:00",
                      "lastModified": "2005-04-02T21:37:00+01:00",
                      "key": "root/indexlist",
                      "datatype": "NUMBER",
                      "required": true,
                      "array": false,
                      "translations": {
                        "name": {
                          "en": "indexlist"
                        }
                      }
                    },
                    "value": 456
                  },
                  {
                    "path": "root/1/indexlist/1",
                    "schema": {
                      "id": schema_root_index_list.id,
                      "createdDate": "2005-04-02T21:37:00+01:00",
                      "lastModified": "2005-04-02T21:37:00+01:00",
                      "key": "root/indexlist",
                      "datatype": "NUMBER",
                      "required": true,
                      "array": false,
                      "translations": {
                        "name": {
                          "en": "indexlist"
                        }
                      }
                    },
                    "value": 456
                  }
                ]
              },
              {
                "path": "root/1/name",
                "schema": {
                  "id": schema_root_name.id,
                  "createdDate": "2005-04-02T21:37:00+01:00",
                  "lastModified": "2005-04-02T21:37:00+01:00",
                  "key": "root/name",
                  "datatype": "STRING",
                  "required": true,
                  "array": false,
                  "translations": {
                    "name": {
                      "en": "name"
                    }
                  }
                },
                "value": "456"
              },
              {
                "path": "root/1/cap",
                "schema": {
                  "id": schema_root_cap.id,
                  "createdDate": "2005-04-02T21:37:00+01:00",
                  "lastModified": "2005-04-02T21:37:00+01:00",
                  "key": "root/cap",
                  "datatype": "STRING",
                  "required": true,
                  "array": true,
                  "translations": {
                    "name": {
                      "en": "cap"
                    }
                  }
                },
                "value": [
                  {
                    "path": "root/1/cap/0",
                    "schema": {
                      "id": schema_root_cap.id,
                      "createdDate": "2005-04-02T21:37:00+01:00",
                      "lastModified": "2005-04-02T21:37:00+01:00",
                      "key": "root/cap",
                      "datatype": "STRING",
                      "required": true,
                      "array": false,
                      "translations": {
                        "name": {
                          "en": "cap"
                        }
                      }
                    },
                    "value": "invoke"
                  },
                  {
                    "path": "root/1/cap/1",
                    "schema": {
                      "id": schema_root_cap.id,
                      "createdDate": "2005-04-02T21:37:00+01:00",
                      "lastModified": "2005-04-02T21:37:00+01:00",
                      "key": "root/cap",
                      "datatype": "STRING",
                      "required": true,
                      "array": false,
                      "translations": {
                        "name": {
                          "en": "cap"
                        }
                      }
                    },
                    "value": "revoke"
                  },
                  {
                    "path": "root/1/cap/2",
                    "schema": {
                      "id": schema_root_cap.id,
                      "createdDate": "2005-04-02T21:37:00+01:00",
                      "lastModified": "2005-04-02T21:37:00+01:00",
                      "key": "root/cap",
                      "datatype": "STRING",
                      "required": true,
                      "array": false,
                      "translations": {
                        "name": {
                          "en": "cap"
                        }
                      }
                    },
                    "value": "delete"
                  }
                ]
              }
            ]
          }
        ]
      },
      {
        "path": "other",
        "schema": {
          "id": schema_other.id,
          "createdDate": "2005-04-02T21:37:00+01:00",
          "lastModified": "2005-04-02T21:37:00+01:00",
          "key": "other",
          "datatype": "OBJECT",
          "required": true,
          "array": false,
          "translations": {
            "name": {
              "en": "other"
            }
          }
        },
        "value": [
          {
            "path": "other/0",
            "schema": {
              "id": schema_other_0.id,
              "createdDate": "2005-04-02T21:37:00+01:00",
              "lastModified": "2005-04-02T21:37:00+01:00",
              "key": "other/0",
              "datatype": "OBJECT",
              "required": true,
              "array": true,
              "translations": {
                "name": {
                  "en": "0"
                }
              }
            },
            "value": [
              {
                "path": "other/0/0",
                "schema": {
                  "id": schema_other_0.id,
                  "createdDate": "2005-04-02T21:37:00+01:00",
                  "lastModified": "2005-04-02T21:37:00+01:00",
                  "key": "other/0",
                  "datatype": "OBJECT",
                  "required": true,
                  "array": false,
                  "translations": {
                    "name": {
                      "en": "0"
                    }
                  }
                },
                "value": [
                  {
                    "path": "other/0/0/name",
                    "schema": {
                      "id": schema_other_0_name.id,
                      "createdDate": "2005-04-02T21:37:00+01:00",
                      "lastModified": "2005-04-02T21:37:00+01:00",
                      "key": "other/0/name",
                      "datatype": "STRING",
                      "required": true,
                      "array": false,
                      "translations": {
                        "name": {
                          "en": "name"
                        }
                      }
                    },
                    "value": "name1"
                  }
                ]
              },
              {
                "path": "other/0/1",
                "schema": {
                  "id": schema_other_0.id,
                  "createdDate": "2005-04-02T21:37:00+01:00",
                  "lastModified": "2005-04-02T21:37:00+01:00",
                  "key": "other/0",
                  "datatype": "OBJECT",
                  "required": true,
                  "array": false,
                  "translations": {
                    "name": {
                      "en": "0"
                    }
                  }
                },
                "value": [
                  {
                    "path": "other/0/1/name",
                    "schema": {
                      "id": schema_other_0_name.id,
                      "createdDate": "2005-04-02T21:37:00+01:00",
                      "lastModified": "2005-04-02T21:37:00+01:00",
                      "key": "other/0/name",
                      "datatype": "STRING",
                      "required": true,
                      "array": false,
                      "translations": {
                        "name": {
                          "en": "name"
                        }
                      }
                    },
                    "value": "name2"
                  }
                ]
              }
            ]
          },
          {
            "path": "other/1",
            "schema": {
              "id": schema_other_1.id,
              "createdDate": "2005-04-02T21:37:00+01:00",
              "lastModified": "2005-04-02T21:37:00+01:00",
              "key": "other/1",
              "datatype": "STRING",
              "required": true,
              "array": true,
              "translations": {
                "name": {
                  "en": "1"
                }
              }
            },
            "value": [
              {
                "path": "other/1/0",
                "schema": {
                  "id": schema_other_1.id,
                  "createdDate": "2005-04-02T21:37:00+01:00",
                  "lastModified": "2005-04-02T21:37:00+01:00",
                  "key": "other/1",
                  "datatype": "STRING",
                  "required": true,
                  "array": false,
                  "translations": {
                    "name": {
                      "en": "1"
                    }
                  }
                },
                "value": "other1"
              },
              {
                "path": "other/1/1",
                "schema": {
                  "id": schema_other_1.id,
                  "createdDate": "2005-04-02T21:37:00+01:00",
                  "lastModified": "2005-04-02T21:37:00+01:00",
                  "key": "other/1",
                  "datatype": "STRING",
                  "required": true,
                  "array": false,
                  "translations": {
                    "name": {
                      "en": "1"
                    }
                  }
                },
                "value": "other2"
              },
              {
                "path": "other/1/2",
                "schema": {
                  "id": schema_other_1.id,
                  "createdDate": "2005-04-02T21:37:00+01:00",
                  "lastModified": "2005-04-02T21:37:00+01:00",
                  "key": "other/1",
                  "datatype": "STRING",
                  "required": true,
                  "array": false,
                  "translations": {
                    "name": {
                      "en": "1"
                    }
                  }
                },
                "value": "other3"
              }
            ]
          }
        ]
      },
      {
        "path": "str",
        "schema": {
          "id": schema_str.id,
          "createdDate": "2005-04-02T21:37:00+01:00",
          "lastModified": "2005-04-02T21:37:00+01:00",
          "key": "str",
          "datatype": "STRING",
          "required": true,
          "array": true,
          "translations": {
            "name": {
              "en": "str"
            }
          }
        },
        "value": [
          {
            "path": "str/0",
            "schema": {
              "id": schema_str.id,
              "createdDate": "2005-04-02T21:37:00+01:00",
              "lastModified": "2005-04-02T21:37:00+01:00",
              "key": "str",
              "datatype": "STRING",
              "required": true,
              "array": false,
              "translations": {
                "name": {
                  "en": "str"
                }
              }
            },
            "value": "str1"
          },
          {
            "path": "str/1",
            "schema": {
              "id": schema_str.id,
              "createdDate": "2005-04-02T21:37:00+01:00",
              "lastModified": "2005-04-02T21:37:00+01:00",
              "key": "str",
              "datatype": "STRING",
              "required": true,
              "array": false,
              "translations": {
                "name": {
                  "en": "str"
                }
              }
            },
            "value": "str1"
          },
          {
            "path": "str/2",
            "schema": {
              "id": schema_str.id,
              "createdDate": "2005-04-02T21:37:00+01:00",
              "lastModified": "2005-04-02T21:37:00+01:00",
              "key": "str",
              "datatype": "STRING",
              "required": true,
              "array": false,
              "translations": {
                "name": {
                  "en": "str"
                }
              }
            },
            "value": "str1"
          }
        ]
      }
    ]);
    assert_eq!(
        expected_claims,
        serde_json::to_value(result.claims).unwrap()
    );
}

#[tokio::test]
async fn test_get_credential_success_array_index_sorting() {
    let mut credential_repository = MockCredentialRepository::default();

    let now = get_dummy_date();
    let schema_str = generate_claim_schema("str", "STRING", true);

    let claim_schemas = vec![schema_str.to_owned()];
    let organisation = dummy_organisation(None);

    let id = Uuid::new_v4().into();

    let claims = vec![
        generate_claim(id, &schema_str, "str1", "str/2"),
        generate_claim(id, &schema_str, "str1", "str/0"),
        generate_claim(id, &schema_str, "str1", "str/1"),
        generate_claim(id, &schema_str, "str1", "str/6"),
        generate_claim(id, &schema_str, "str1", "str/7"),
        generate_claim(id, &schema_str, "str1", "str/3"),
        generate_claim(id, &schema_str, "str1", "str/4"),
        generate_claim(id, &schema_str, "str1", "str/10"),
        generate_claim(id, &schema_str, "str1", "str/11"),
        generate_claim(id, &schema_str, "str1", "str/5"),
        generate_claim(id, &schema_str, "str1", "str/9"),
        generate_claim(id, &schema_str, "str1", "str/8"),
        generate_claim(id, &schema_str, "str1", "str/12"),
    ];

    let credential_schema_id = Uuid::new_v4().into();
    let format = CredentialSchemaFormat {
        id: Uuid::new_v4().into(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        credential_schema_id,
        format: "JWT".into(),
        ecosystem_schema_id: "CredentialSchemaId".to_owned(),
        claim_mappings: Default::default(),
    };
    let credential = Credential {
        expires_at: None,
        ecosystem: None,
        id,
        created_date: now,
        issuance_date: None,
        last_modified: now,
        deleted_at: None,
        consumed_at: None,
        protocol: "OPENID4VCI_FINAL1".to_string(),
        redirect_uri: None,
        role: CredentialRole::Issuer,
        r#type: CredentialType::Single,
        state: CredentialStateEnum::Created,
        suspend_end_date: None,
        claims: claims.to_owned().into(),
        issuer_identifier: Some(
            Identifier {
                id: Uuid::new_v4().into(),
                created_date: now,
                last_modified: now,
                name: "identifier".to_string(),
                data: IdentifierData::Did(
                    (Did {
                        deleted_at: None,
                        id: Uuid::new_v4().into(),
                        created_date: now,
                        last_modified: now,
                        name: "did1".to_string(),
                        organisation: organisation.clone().into(),
                        did: "did:example:1".parse().unwrap(),
                        did_type: DidType::Local,
                        did_method: "KEY".into(),
                        keys: vec![RelatedKey {
                            role: KeyRole::AssertionMethod,
                            key: Key {
                                id: Uuid::new_v4().into(),
                                created_date: crate::clock::now_utc(),
                                last_modified: crate::clock::now_utc(),
                                public_key: vec![],
                                name: "key_name".to_string(),
                                key_reference: None,
                                storage_type: "INTERNAL".to_string(),
                                key_type: "EDDSA".to_string(),
                                organisation: dummy_organisation(None).into(),
                            },
                            reference: "1".to_string(),
                        }]
                        .into(),
                        deactivated: false,
                        log: None,
                    })
                    .into(),
                ),
                is_remote: false,
                state: IdentifierState::Active,
                deleted_at: None,
                organisation: dummy_organisation(Some(uuid::Uuid::new_v4().into())).into(),
                trust_information: Default::default(),
            }
            .into(),
        ),
        issuer_certificate: None,
        holder_identifier: None,
        schema: (backfill_default_translations(
            CredentialSchema {
                expiration: None,
                ecosystem: None,
                batch_size: None,
                allow_revocation: false,
                id: credential_schema_id,
                imported_source_url: "CORE_URL".to_string(),
                deleted_at: None,
                created_date: now,
                last_modified: now,
                name: "schema".to_string(),
                key_storage_security: None,
                formats: vec![format.clone()].into(),
                claim_schemas: claim_schemas.into(),
                organisation: organisation.into(),
                layout_properties: None,
                allow_suspension: true,
                requires_wallet_instance_attestation: false,
                transaction_code: None,
                translations: Default::default(),
                embedded_disclosure_policy: None,
            },
            "en",
        )
        .await
        .unwrap())
        .into(),
        interaction: None,
        key: None,
        profile: None,
        credential_blob_id: None,
        wallet_unit_attestation_blob_id: None,
        wallet_instance_attestation_blob_id: None,
        webhook_url: None,
        parent: None,
        embedded_disclosure_policy: None,
        subscriber_information: None,
        format: Some(format.into()),
    };

    {
        let clone = credential.clone();
        credential_repository
            .expect_get_credential()
            .times(1)
            .with(eq(clone.id))
            .returning(move |_| Ok(clone.clone()));
    }

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .return_once(|_| {
            let mut formatter = MockCredentialFormatter::new();
            formatter.expect_revocation_method_id().return_const(None);
            Ok(Arc::new(formatter))
        });

    let service = setup_service(Repositories {
        credential_repository,
        formatter_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.get_credential(&credential.id).await.unwrap();
    let expected_claims = json!([
      {
        "path": "str",
        "schema": {
          "id": schema_str.id,
          "createdDate": "2005-04-02T21:37:00+01:00",
          "lastModified": "2005-04-02T21:37:00+01:00",
          "key": "str",
          "datatype": "STRING",
          "required": true,
          "array": true,
          "translations": {
            "name": {
              "en": "str"
            }
          }
        },
        "value": [
          {
            "path": "str/0",
            "schema": {
              "id": schema_str.id,
              "createdDate": "2005-04-02T21:37:00+01:00",
              "lastModified": "2005-04-02T21:37:00+01:00",
              "key": "str",
              "datatype": "STRING",
              "required": true,
              "array": false,
              "translations": {
                "name": {
                  "en": "str"
                }
              }
            },
            "value": "str1"
          },
          {
            "path": "str/1",
            "schema": {
              "id": schema_str.id,
              "createdDate": "2005-04-02T21:37:00+01:00",
              "lastModified": "2005-04-02T21:37:00+01:00",
              "key": "str",
              "datatype": "STRING",
              "required": true,
              "array": false,
              "translations": {
                "name": {
                  "en": "str"
                }
              }
            },
            "value": "str1"
          },
          {
            "path": "str/2",
            "schema": {
              "id": schema_str.id,
              "createdDate": "2005-04-02T21:37:00+01:00",
              "lastModified": "2005-04-02T21:37:00+01:00",
              "key": "str",
              "datatype": "STRING",
              "required": true,
              "array": false,
              "translations": {
                "name": {
                  "en": "str"
                }
              }
            },
            "value": "str1"
          },
          {
            "path": "str/3",
            "schema": {
              "id": schema_str.id,
              "createdDate": "2005-04-02T21:37:00+01:00",
              "lastModified": "2005-04-02T21:37:00+01:00",
              "key": "str",
              "datatype": "STRING",
              "required": true,
              "array": false,
              "translations": {
                "name": {
                  "en": "str"
                }
              }
            },
            "value": "str1"
          },
          {
            "path": "str/4",
            "schema": {
              "id": schema_str.id,
              "createdDate": "2005-04-02T21:37:00+01:00",
              "lastModified": "2005-04-02T21:37:00+01:00",
              "key": "str",
              "datatype": "STRING",
              "required": true,
              "array": false,
              "translations": {
                "name": {
                  "en": "str"
                }
              }
            },
            "value": "str1"
          },
          {
            "path": "str/5",
            "schema": {
              "id": schema_str.id,
              "createdDate": "2005-04-02T21:37:00+01:00",
              "lastModified": "2005-04-02T21:37:00+01:00",
              "key": "str",
              "datatype": "STRING",
              "required": true,
              "array": false,
              "translations": {
                "name": {
                  "en": "str"
                }
              }
            },
            "value": "str1"
          },
          {
            "path": "str/6",
            "schema": {
              "id": schema_str.id,
              "createdDate": "2005-04-02T21:37:00+01:00",
              "lastModified": "2005-04-02T21:37:00+01:00",
              "key": "str",
              "datatype": "STRING",
              "required": true,
              "array": false,
              "translations": {
                "name": {
                  "en": "str"
                }
              }
            },
            "value": "str1"
          },
          {
            "path": "str/7",
            "schema": {
              "id": schema_str.id,
              "createdDate": "2005-04-02T21:37:00+01:00",
              "lastModified": "2005-04-02T21:37:00+01:00",
              "key": "str",
              "datatype": "STRING",
              "required": true,
              "array": false,
              "translations": {
                "name": {
                  "en": "str"
                }
              }
            },
            "value": "str1"
          },
          {
            "path": "str/8",
            "schema": {
              "id": schema_str.id,
              "createdDate": "2005-04-02T21:37:00+01:00",
              "lastModified": "2005-04-02T21:37:00+01:00",
              "key": "str",
              "datatype": "STRING",
              "required": true,
              "array": false,
              "translations": {
                "name": {
                  "en": "str"
                }
              }
            },
            "value": "str1"
          },
          {
            "path": "str/9",
            "schema": {
              "id": schema_str.id,
              "createdDate": "2005-04-02T21:37:00+01:00",
              "lastModified": "2005-04-02T21:37:00+01:00",
              "key": "str",
              "datatype": "STRING",
              "required": true,
              "array": false,
              "translations": {
                "name": {
                  "en": "str"
                }
              }
            },
            "value": "str1"
          },
          {
            "path": "str/10",
            "schema": {
              "id": schema_str.id,
              "createdDate": "2005-04-02T21:37:00+01:00",
              "lastModified": "2005-04-02T21:37:00+01:00",
              "key": "str",
              "datatype": "STRING",
              "required": true,
              "array": false,
              "translations": {
                "name": {
                  "en": "str"
                }
              }
            },
            "value": "str1"
          },
          {
            "path": "str/11",
            "schema": {
              "id": schema_str.id,
              "createdDate": "2005-04-02T21:37:00+01:00",
              "lastModified": "2005-04-02T21:37:00+01:00",
              "key": "str",
              "datatype": "STRING",
              "required": true,
              "array": false,
              "translations": {
                "name": {
                  "en": "str"
                }
              }
            },
            "value": "str1"
          },
          {
            "path": "str/12",
            "schema": {
              "id": schema_str.id,
              "createdDate": "2005-04-02T21:37:00+01:00",
              "lastModified": "2005-04-02T21:37:00+01:00",
              "key": "str",
              "datatype": "STRING",
              "required": true,
              "array": false,
              "translations": {
                "name": {
                  "en": "str"
                }
              }
            },
            "value": "str1"
          }
        ]
      }
    ]);

    assert_eq!(
        expected_claims,
        serde_json::to_value(result.claims).unwrap()
    );
}

#[tokio::test]
async fn test_get_credential_success_array_complex_nested_first_case() {
    let mut credential_repository = MockCredentialRepository::default();

    let now = get_dummy_date();

    let schema_root = generate_claim_schema("root", "OBJECT", true);
    let schema_root_index_list = generate_claim_schema("root/indexlist", "NUMBER", true);

    let claim_schemas = vec![schema_root.to_owned(), schema_root_index_list.to_owned()];
    let organisation = dummy_organisation(None);

    let id = Uuid::new_v4().into();

    let claims = vec![
        generate_claim(id, &schema_root_index_list, "123", "root/0/indexlist/0"),
        generate_claim(id, &schema_root_index_list, "123", "root/0/indexlist/1"),
    ];

    let credential_schema_id = Uuid::new_v4().into();
    let format = CredentialSchemaFormat {
        id: Uuid::new_v4().into(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        credential_schema_id,
        format: "MDOC".into(),
        ecosystem_schema_id: "CredentialSchemaId".to_owned(),
        claim_mappings: Default::default(),
    };
    let credential = Credential {
        expires_at: None,
        ecosystem: None,
        id,
        created_date: now,
        issuance_date: None,
        last_modified: now,
        deleted_at: None,
        consumed_at: None,
        protocol: "OPENID4VCI_FINAL1".to_string(),
        redirect_uri: None,
        role: CredentialRole::Issuer,
        r#type: CredentialType::Single,
        state: CredentialStateEnum::Accepted,
        suspend_end_date: None,
        claims: claims.to_owned().into(),
        issuer_identifier: Some(
            Identifier {
                id: Uuid::new_v4().into(),
                created_date: now,
                last_modified: now,
                name: "identifier".to_string(),
                data: IdentifierData::Did(
                    (Did {
                        deleted_at: None,
                        id: Uuid::new_v4().into(),
                        created_date: now,
                        last_modified: now,
                        name: "did1".to_string(),
                        organisation: organisation.clone().into(),
                        did: "did:example:1".parse().unwrap(),
                        did_type: DidType::Local,
                        did_method: "KEY".into(),
                        keys: vec![RelatedKey {
                            role: KeyRole::AssertionMethod,
                            key: Key {
                                id: Uuid::new_v4().into(),
                                created_date: crate::clock::now_utc(),
                                last_modified: crate::clock::now_utc(),
                                public_key: vec![],
                                name: "key_name".to_string(),
                                key_reference: None,
                                storage_type: "INTERNAL".to_string(),
                                key_type: "EDDSA".to_string(),
                                organisation: dummy_organisation(None).into(),
                            },
                            reference: "1".to_string(),
                        }]
                        .into(),
                        deactivated: false,
                        log: None,
                    })
                    .into(),
                ),
                is_remote: false,
                state: IdentifierState::Active,
                deleted_at: None,
                organisation: dummy_organisation(Some(uuid::Uuid::new_v4().into())).into(),
                trust_information: Default::default(),
            }
            .into(),
        ),
        issuer_certificate: None,
        holder_identifier: None,
        schema: (backfill_default_translations(
            CredentialSchema {
                expiration: None,
                ecosystem: None,
                batch_size: None,
                allow_revocation: false,
                id: credential_schema_id,
                deleted_at: None,
                imported_source_url: "CORE_URL".to_string(),
                created_date: now,
                last_modified: now,
                name: "schema".to_string(),
                key_storage_security: None,
                formats: vec![format.clone()].into(),
                claim_schemas: claim_schemas.into(),
                organisation: organisation.into(),
                layout_properties: None,
                allow_suspension: true,
                requires_wallet_instance_attestation: false,
                transaction_code: None,
                translations: Default::default(),
                embedded_disclosure_policy: None,
            },
            "en",
        )
        .await
        .unwrap())
        .into(),
        interaction: None,
        key: None,
        profile: None,
        credential_blob_id: None,
        wallet_unit_attestation_blob_id: None,
        wallet_instance_attestation_blob_id: None,
        webhook_url: None,
        parent: None,
        embedded_disclosure_policy: None,
        subscriber_information: None,
        format: Some(format.into()),
    };

    {
        let clone = credential.clone();
        credential_repository
            .expect_get_credential()
            .times(1)
            .with(eq(clone.id))
            .returning(move |_| Ok(clone.clone()));

        credential_repository
            .expect_get_credential_list()
            .once()
            .return_once(|_| {
                Ok(GetCredentialList {
                    values: vec![],
                    total_pages: 0,
                    total_items: 0,
                })
            });
    }

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .return_once(|_| {
            let mut formatter = MockCredentialFormatter::new();
            formatter.expect_revocation_method_id().return_const(None);
            Ok(Arc::new(formatter))
        });

    let service = setup_service(Repositories {
        credential_repository,
        formatter_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.get_credential(&credential.id).await.unwrap();
    let expected_claims = json!([
      {
        "path": "root",
        "schema": {
          "id": schema_root.id,
          "createdDate": "2005-04-02T21:37:00+01:00",
          "lastModified": "2005-04-02T21:37:00+01:00",
          "key": "root",
          "datatype": "OBJECT",
          "required": true,
          "array": true,
          "translations": {
            "name": {
              "en": "root"
            }
          }
        },
        "value": [
          {
            "path": "root/0",
            "schema": {
              "id": schema_root.id,
              "createdDate": "2005-04-02T21:37:00+01:00",
              "lastModified": "2005-04-02T21:37:00+01:00",
              "key": "root",
              "datatype": "OBJECT",
              "required": true,
              "array": false,
              "translations": {
                "name": {
                  "en": "root"
                }
              }
            },
            "value": [
              {
                "path": "root/0/indexlist",
                "schema": {
                  "id": schema_root_index_list.id,
                  "createdDate": "2005-04-02T21:37:00+01:00",
                  "lastModified": "2005-04-02T21:37:00+01:00",
                  "key": "root/indexlist",
                  "datatype": "NUMBER",
                  "required": true,
                  "array": true,
                  "translations": {
                    "name": {
                      "en": "indexlist"
                    }
                  }
                },
                "value": [
                  {
                    "path": "root/0/indexlist/0",
                    "schema": {
                      "id": schema_root_index_list.id,
                      "createdDate": "2005-04-02T21:37:00+01:00",
                      "lastModified": "2005-04-02T21:37:00+01:00",
                      "key": "root/indexlist",
                      "datatype": "NUMBER",
                      "required": true,
                      "array": false,
                      "translations": {
                        "name": {
                          "en": "indexlist"
                        }
                      }
                    },
                    "value": 123
                  },
                  {
                    "path": "root/0/indexlist/1",
                    "schema": {
                      "id": schema_root_index_list.id,
                      "createdDate": "2005-04-02T21:37:00+01:00",
                      "lastModified": "2005-04-02T21:37:00+01:00",
                      "key": "root/indexlist",
                      "datatype": "NUMBER",
                      "required": true,
                      "array": false,
                      "translations": {
                        "name": {
                          "en": "indexlist"
                        }
                      }
                    },
                    "value": 123
                  }
                ]
              }
            ]
          }
        ]
      }
    ]);

    assert!(result.mdoc_mso_validity.is_some());
    assert_eq!(now, result.mdoc_mso_validity.unwrap().last_update);
    assert_eq!(
        expected_claims,
        serde_json::to_value(result.claims).unwrap()
    );
}

#[tokio::test]
async fn test_get_credential_success_array_single_element() {
    let mut credential_repository = MockCredentialRepository::default();

    let now = get_dummy_date();

    let schema_root = generate_claim_schema("root", "OBJECT", true);
    let schema_root_index_list = generate_claim_schema("root/indexlist", "NUMBER", true);

    let claim_schemas = vec![schema_root.to_owned(), schema_root_index_list.to_owned()];
    let organisation = dummy_organisation(None);

    let id = Uuid::new_v4().into();

    let claims = vec![generate_claim(
        id,
        &schema_root_index_list,
        "123",
        "root/0/indexlist/0",
    )];

    let credential_schema_id = Uuid::new_v4().into();
    let format = CredentialSchemaFormat {
        id: Uuid::new_v4().into(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        credential_schema_id,
        format: "JWT".into(),
        ecosystem_schema_id: "CredentialSchemaId".to_owned(),
        claim_mappings: Default::default(),
    };
    let credential = Credential {
        expires_at: None,
        ecosystem: None,
        id,
        created_date: now,
        issuance_date: None,
        last_modified: now,
        deleted_at: None,
        consumed_at: None,
        protocol: "OPENID4VCI_FINAL1".to_string(),
        redirect_uri: None,
        role: CredentialRole::Issuer,
        r#type: CredentialType::Single,
        state: CredentialStateEnum::Created,
        suspend_end_date: None,
        claims: claims.to_owned().into(),
        issuer_identifier: Some(
            Identifier {
                id: Uuid::new_v4().into(),
                created_date: now,
                last_modified: now,
                name: "identifier".to_string(),
                data: IdentifierData::Did(
                    (Did {
                        deleted_at: None,
                        id: Uuid::new_v4().into(),
                        created_date: now,
                        last_modified: now,
                        name: "did1".to_string(),
                        organisation: organisation.clone().into(),
                        did: "did:example:1".parse().unwrap(),
                        did_type: DidType::Local,
                        did_method: "KEY".into(),
                        keys: vec![RelatedKey {
                            role: KeyRole::AssertionMethod,
                            key: Key {
                                id: Uuid::new_v4().into(),
                                created_date: crate::clock::now_utc(),
                                last_modified: crate::clock::now_utc(),
                                public_key: vec![],
                                name: "key_name".to_string(),
                                key_reference: None,
                                storage_type: "INTERNAL".to_string(),
                                key_type: "EDDSA".to_string(),
                                organisation: dummy_organisation(None).into(),
                            },
                            reference: "1".to_string(),
                        }]
                        .into(),
                        deactivated: false,
                        log: None,
                    })
                    .into(),
                ),
                is_remote: false,
                state: IdentifierState::Active,
                deleted_at: None,
                organisation: dummy_organisation(Some(uuid::Uuid::new_v4().into())).into(),
                trust_information: Default::default(),
            }
            .into(),
        ),
        issuer_certificate: None,
        holder_identifier: None,
        schema: (backfill_default_translations(
            CredentialSchema {
                expiration: None,
                ecosystem: None,
                batch_size: None,
                allow_revocation: false,
                id: credential_schema_id,
                deleted_at: None,
                created_date: now,
                last_modified: now,
                imported_source_url: "CORE_URL".to_string(),
                name: "schema".to_string(),
                key_storage_security: None,
                formats: vec![format.clone()].into(),
                claim_schemas: claim_schemas.into(),
                organisation: organisation.into(),
                layout_properties: None,
                allow_suspension: true,
                requires_wallet_instance_attestation: false,
                transaction_code: None,
                translations: Default::default(),
                embedded_disclosure_policy: None,
            },
            "en",
        )
        .await
        .unwrap())
        .into(),
        interaction: None,
        key: None,
        profile: None,
        credential_blob_id: None,
        wallet_unit_attestation_blob_id: None,
        wallet_instance_attestation_blob_id: None,
        webhook_url: None,
        parent: None,
        embedded_disclosure_policy: None,
        subscriber_information: None,
        format: Some(format.into()),
    };

    {
        let clone = credential.clone();
        credential_repository
            .expect_get_credential()
            .times(1)
            .with(eq(clone.id))
            .returning(move |_| Ok(clone.clone()));
    }

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .return_once(|_| {
            let mut formatter = MockCredentialFormatter::new();
            formatter.expect_revocation_method_id().return_const(None);
            Ok(Arc::new(formatter))
        });

    let service = setup_service(Repositories {
        credential_repository,
        formatter_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.get_credential(&credential.id).await.unwrap();

    let expected_claims = json!([
      {
        "path": "root",
        "schema": {
          "id": schema_root.id,
          "createdDate": "2005-04-02T21:37:00+01:00",
          "lastModified": "2005-04-02T21:37:00+01:00",
          "key": "root",
          "datatype": "OBJECT",
          "required": true,
          "array": true,
          "translations": {
            "name": {
              "en": "root"
            }
          }
        },
        "value": [
          {
            "path": "root/0",
            "schema": {
              "id": schema_root.id,
              "createdDate": "2005-04-02T21:37:00+01:00",
              "lastModified": "2005-04-02T21:37:00+01:00",
              "key": "root",
              "datatype": "OBJECT",
              "required": true,
              "array": false,
              "translations": {
                "name": {
                  "en": "root"
                }
              }
            },
            "value": [
              {
                "path": "root/0/indexlist",
                "schema": {
                  "id": schema_root_index_list.id,
                  "createdDate": "2005-04-02T21:37:00+01:00",
                  "lastModified": "2005-04-02T21:37:00+01:00",
                  "key": "root/indexlist",
                  "datatype": "NUMBER",
                  "required": true,
                  "array": true,
                  "translations": {
                    "name": {
                      "en": "indexlist"
                    }
                  }
                },
                "value": [
                  {
                    "path": "root/0/indexlist/0",
                    "schema": {
                      "id": schema_root_index_list.id,
                      "createdDate": "2005-04-02T21:37:00+01:00",
                      "lastModified": "2005-04-02T21:37:00+01:00",
                      "key": "root/indexlist",
                      "datatype": "NUMBER",
                      "required": true,
                      "array": false,
                      "translations": {
                        "name": {
                          "en": "indexlist"
                        }
                      }
                    },
                    "value": 123
                  }
                ]
              }
            ]
          }
        ]
      }
    ]);

    assert_eq!(
        expected_claims,
        serde_json::to_value(result.claims).unwrap()
    );
}

async fn test_create_credential_array(
    claim_schemas: Vec<ClaimSchema>,
    claims: Vec<Claim>,
) -> Result<CredentialId, CredentialServiceError> {
    let mut credential_repository = MockCredentialRepository::default();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut identifier_repository = MockIdentifierRepository::default();

    let organisation = dummy_organisation(None);

    let credential_schema_id = Uuid::new_v4().into();
    let credential_schema = CredentialSchema {
        expiration: None,
        ecosystem: None,
        allow_revocation: false,
        id: credential_schema_id,
        deleted_at: None,
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        imported_source_url: "CORE_URL".to_string(),
        name: "str array".to_string(),
        key_storage_security: None,
        layout_properties: None,
        allow_suspension: true,
        requires_wallet_instance_attestation: false,
        claim_schemas: claim_schemas.into(),
        organisation: organisation.into(),
        formats: vec![CredentialSchemaFormat {
            id: Uuid::new_v4().into(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            credential_schema_id,
            format: "JWT".into(),
            ecosystem_schema_id: "".to_owned(),
            claim_mappings: Default::default(),
        }]
        .into(),
        transaction_code: None,
        batch_size: None,
        translations: Default::default(),
        embedded_disclosure_policy: None,
    };

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .once()
        .return_once(generic_formatter_capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::default();

    {
        let credential_schema = credential_schema.clone();
        credential_schema_repository
            .expect_get_credential_schema()
            .return_once(move |_| Ok(credential_schema));
        formatter_provider
            .expect_get_credential_formatter()
            .once()
            .return_once(move |_| Ok(Arc::new(formatter)));
        credential_repository
            .expect_create_credential()
            .return_once(move |_| Ok(Uuid::new_v4().into()));
    }

    let did = Did {
        did_method: "KEY".into(),
        keys: vec![RelatedKey {
            role: KeyRole::AssertionMethod,
            key: dummy_key(),
            reference: "1".to_string(),
        }]
        .into(),
        ..dummy_did()
    };
    let did_clone = did.clone();
    identifier_repository
        .expect_get_from_did_id()
        .return_once(|_| {
            Ok(Some(Identifier {
                data: IdentifierData::Did((did_clone).into()),
                ..dummy_identifier()
            }))
        });

    let mut dummy_protocol = MockIssuanceProtocol::default();
    dummy_protocol
        .expect_get_capabilities()
        .once()
        .returning(generic_capabilities);
    let mut protocol_provider = MockIssuanceProtocolProvider::default();
    protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Ok(Arc::new(dummy_protocol)));

    let service = setup_service(Repositories {
        credential_repository,
        credential_schema_repository,
        identifier_repository,
        formatter_provider,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    service
        .create_credential(CreateCredentialRequestDTO {
            credential_schema_id: Uuid::new_v4().into(),
            issuer: None,
            issuer_did: Some(did.id),
            issuer_key: None,
            issuer_certificate: None,
            protocol: "OPENID4VCI_FINAL1".to_string(),
            claim_values: claims
                .iter()
                .map(|claim| CredentialRequestClaimDTO {
                    claim_schema_id: claim.schema.id(),
                    value: claim.value.to_owned().unwrap(),
                    path: claim.path.to_owned(),
                })
                .collect(),
            redirect_uri: None,
            profile: None,
            webhook_destination_url: None,
            subscriber_information: None,
            ecosystem: None,
        })
        .await
}

#[tokio::test]
async fn test_create_credential_array_simple_string() {
    let schema_str = generate_claim_schema("str", "STRING", true);

    let claim_schemas = vec![schema_str.to_owned()];
    let id = Uuid::new_v4().into();

    let claims = vec![
        generate_claim(id, &schema_str, "str1", "str/0"),
        generate_claim(id, &schema_str, "str1", "str/1"),
        generate_claim(id, &schema_str, "str1", "str/2"),
    ];

    test_create_credential_array(claim_schemas, claims)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_create_credential_array_simple_object() {
    let id = Uuid::new_v4().into();

    let schema_root = generate_claim_schema("root", "OBJECT", true);
    let schema_root_index_list = generate_claim_schema("root/indexlist", "NUMBER", true);

    let claim_schemas = vec![schema_root.to_owned(), schema_root_index_list.to_owned()];

    let claims = vec![
        generate_claim(id, &schema_root_index_list, "123", "root/0/indexlist/0"),
        generate_claim(id, &schema_root_index_list, "123", "root/0/indexlist/1"),
    ];

    test_create_credential_array(claim_schemas, claims)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_create_credential_array_complex_structure() {
    let schema_root = generate_claim_schema("root", "OBJECT", true);
    let schema_root_index_list = generate_claim_schema("root/indexlist", "NUMBER", true);
    let schema_root_name = generate_claim_schema("root/name", "STRING", false);
    let schema_root_cap = generate_claim_schema("root/cap", "STRING", true);

    let schema_other = generate_claim_schema("other", "OBJECT", false);
    let schema_other_0 = generate_claim_schema("other/0", "OBJECT", true);
    let schema_other_0_name = generate_claim_schema("other/0/name", "STRING", false);
    let schema_other_1 = generate_claim_schema("other/1", "STRING", true);

    let schema_str = generate_claim_schema("str", "STRING", true);

    let claim_schemas = vec![
        schema_root.to_owned(),
        schema_root_index_list.to_owned(),
        schema_root_name.to_owned(),
        schema_root_cap.to_owned(),
        schema_other.to_owned(),
        schema_other_0.to_owned(),
        schema_other_0_name.to_owned(),
        schema_other_1.to_owned(),
        schema_str.to_owned(),
    ];

    let id = Uuid::new_v4().into();

    let claims = vec![
        generate_claim(id, &schema_root_index_list, "123", "root/0/indexlist/0"),
        generate_claim(id, &schema_root_index_list, "123", "root/0/indexlist/1"),
        generate_claim(id, &schema_root_name, "123", "root/0/name"),
        generate_claim(id, &schema_root_cap, "invoke", "root/0/cap/0"),
        generate_claim(id, &schema_root_cap, "revoke", "root/0/cap/1"),
        generate_claim(id, &schema_root_cap, "delete", "root/0/cap/2"),
        generate_claim(id, &schema_root_index_list, "456", "root/1/indexlist/0"),
        generate_claim(id, &schema_root_index_list, "456", "root/1/indexlist/1"),
        generate_claim(id, &schema_root_name, "456", "root/1/name"),
        generate_claim(id, &schema_root_cap, "invoke", "root/1/cap/0"),
        generate_claim(id, &schema_root_cap, "revoke", "root/1/cap/1"),
        generate_claim(id, &schema_root_cap, "delete", "root/1/cap/2"),
        generate_claim(id, &schema_other_0_name, "name1", "other/0/0/name"),
        generate_claim(id, &schema_other_0_name, "name2", "other/0/1/name"),
        generate_claim(id, &schema_other_1, "other1", "other/1/0"),
        generate_claim(id, &schema_other_1, "other2", "other/1/1"),
        generate_claim(id, &schema_other_1, "other3", "other/1/2"),
        generate_claim(id, &schema_str, "str1", "str/0"),
        generate_claim(id, &schema_str, "str1", "str/1"),
        generate_claim(id, &schema_str, "str1", "str/2"),
    ];

    test_create_credential_array(claim_schemas, claims)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_create_credential_array_fail_incorrect_index() {
    let id = Uuid::new_v4().into();

    let schema_root = generate_claim_schema("root", "OBJECT", true);
    let schema_root_index_list = generate_claim_schema("root/indexlist", "NUMBER", true);

    let claim_schemas = vec![schema_root.to_owned(), schema_root_index_list.to_owned()];

    let unparsable_index = generate_claim(
        id,
        &schema_root_index_list,
        "123",
        "root/0/indexlist/not_an_index",
    );
    assert!(
        test_create_credential_array(claim_schemas.to_owned(), vec![unparsable_index])
            .await
            .is_err()
    );

    let unparsable_index_parent = generate_claim(
        id,
        &schema_root_index_list,
        "123",
        "root/not_an_index/indexlist/0",
    );
    assert!(
        test_create_credential_array(claim_schemas.to_owned(), vec![unparsable_index_parent])
            .await
            .is_err()
    );

    let missing_component = generate_claim(id, &schema_root_index_list, "123", "root/indexlist/0");
    assert!(
        test_create_credential_array(claim_schemas.to_owned(), vec![missing_component])
            .await
            .is_err()
    );

    let malformed_path = generate_claim(id, &schema_root_index_list, "123", "not_even_a_path");
    assert!(
        test_create_credential_array(claim_schemas.to_owned(), vec![malformed_path])
            .await
            .is_err()
    );

    let malformed_path = generate_claim(id, &schema_root_index_list, "123", "///////");
    assert!(
        test_create_credential_array(claim_schemas.to_owned(), vec![malformed_path])
            .await
            .is_err()
    );
}

#[tokio::test]
async fn test_create_credential_array_fail_index_incorrect_order() {
    let id = Uuid::new_v4().into();

    let schema_root = generate_claim_schema("root", "OBJECT", true);
    let schema_root_index_list = generate_claim_schema("root/indexlist", "NUMBER", true);

    let claim_schemas = vec![schema_root.to_owned(), schema_root_index_list.to_owned()];

    let claims = vec![
        generate_claim(id, &schema_root_index_list, "123", "root/0/indexlist/0"),
        generate_claim(id, &schema_root_index_list, "123", "root/0/indexlist/2"),
    ];
    assert!(
        test_create_credential_array(claim_schemas.to_owned(), claims)
            .await
            .is_err()
    );

    let claims = vec![
        generate_claim(id, &schema_root_index_list, "123", "root/0/indexlist/1"),
        generate_claim(id, &schema_root_index_list, "123", "root/0/indexlist/0"),
    ];
    assert!(
        test_create_credential_array(claim_schemas.to_owned(), claims)
            .await
            .is_err()
    );

    let claims = vec![
        generate_claim(id, &schema_root_index_list, "123", "root/0/indexlist/0"),
        generate_claim(id, &schema_root_index_list, "123", "root/2/indexlist/0"),
    ];
    assert!(
        test_create_credential_array(claim_schemas.to_owned(), claims)
            .await
            .is_err()
    );

    let claims = vec![
        generate_claim(id, &schema_root_index_list, "123", "root/1/indexlist/0"),
        generate_claim(id, &schema_root_index_list, "123", "root/0/indexlist/0"),
    ];
    assert!(
        test_create_credential_array(claim_schemas.to_owned(), claims)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn test_create_credential_number_named_claims() {
    let id = Uuid::new_v4().into();

    let schema_root = generate_claim_schema("root", "OBJECT", true);
    let schema_00 = generate_claim_schema("root/00", "STRING", false);
    let schema_1 = generate_claim_schema("root/1", "STRING", false);
    let schema_2array = generate_claim_schema("root/2-array", "STRING", true);

    let claim_schemas = vec![
        schema_root.to_owned(),
        schema_1.to_owned(),
        schema_00.to_owned(),
        schema_2array.to_owned(),
    ];

    let claims = vec![
        generate_claim(id, &schema_00, "zero", "root/0/00"),
        generate_claim(id, &schema_1, "1first", "root/0/1"),
        generate_claim(id, &schema_1, "1second", "root/1/1"),
        generate_claim(id, &schema_2array, "2first", "root/0/2-array/0"),
    ];
    test_create_credential_array(claim_schemas.to_owned(), claims)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_create_credential_session_org_mismatch() {
    let mut identifier_repository = MockIdentifierRepository::new();
    let credential = generic_credential().await;
    let issuer_identifier = credential
        .issuer_identifier
        .as_ref()
        .unwrap()
        .as_ref()
        .await
        .unwrap()
        .to_owned();
    identifier_repository
        .expect_get()
        .return_once(|_| Ok(issuer_identifier));
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let credential_schema = credential.schema.as_ref().await.unwrap().to_owned();
    credential_schema_repository
        .expect_get_credential_schema()
        .return_once(move |_| Ok(credential_schema));
    let service = setup_service(Repositories {
        credential_schema_repository,
        config: generic_config().core,
        identifier_repository,
        session_provider: Some(Arc::new(StaticSessionProvider::new_random())),
        ..Default::default()
    });

    let result = service
        .create_credential(CreateCredentialRequestDTO {
            credential_schema_id: Uuid::new_v4().into(),
            issuer: Some(Uuid::new_v4().into()),
            issuer_did: None,
            issuer_key: None,
            issuer_certificate: None,
            protocol: "OPENID4VCI_FINAL1".to_string(),
            claim_values: vec![],
            redirect_uri: None,
            profile: None,
            webhook_destination_url: None,
            subscriber_information: None,
            ecosystem: None,
        })
        .await;

    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);
}

#[tokio::test]
async fn test_create_credential_invalid_certificate_role() {
    let mut credential_repository = MockCredentialRepository::default();
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut identifier_repository = MockIdentifierRepository::default();

    let organisation = dummy_organisation(None);

    let schema_root = generate_claim_schema("root", "OBJECT", true);
    let schema_00 = generate_claim_schema("root/00", "STRING", false);
    let claim_schemas = vec![schema_root.to_owned(), schema_00.to_owned()];
    let credential_schema_id = Uuid::new_v4().into();
    let credential_schema = CredentialSchema {
        expiration: None,
        ecosystem: None,
        batch_size: None,
        allow_revocation: false,
        id: credential_schema_id,
        deleted_at: None,
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        imported_source_url: "CORE_URL".to_string(),
        name: "str array".to_string(),
        formats: vec![CredentialSchemaFormat {
            id: Uuid::new_v4().into(),
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            credential_schema_id,
            format: "JWT".into(),
            ecosystem_schema_id: "CredentialSchemaId".to_owned(),
            claim_mappings: Default::default(),
        }]
        .into(),
        key_storage_security: None,
        layout_properties: None,
        claim_schemas: claim_schemas.into(),
        organisation: organisation.clone().into(),
        allow_suspension: true,
        requires_wallet_instance_attestation: false,
        transaction_code: None,
        translations: Default::default(),
        embedded_disclosure_policy: None,
    };

    let mut formatter = MockCredentialFormatter::default();
    formatter
        .expect_get_capabilities()
        .once()
        .return_once(generic_formatter_capabilities);

    let mut formatter_provider = MockCredentialFormatterProvider::default();

    {
        let credential_schema = credential_schema.clone();
        credential_schema_repository
            .expect_get_credential_schema()
            .return_once(move |_| Ok(credential_schema));
        formatter_provider
            .expect_get_credential_formatter()
            .once()
            .return_once(move |_| Ok(Arc::new(formatter)));
        credential_repository
            .expect_create_credential()
            .return_once(move |_| Ok(Uuid::new_v4().into()));
    }

    let identifier_id = Uuid::new_v4().into();
    let certificate_id = Uuid::new_v4().into();
    let certificate = Certificate {
        id: certificate_id,
        identifier_id,
        organisation: organisation.into(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        deleted_at: None,
        expiry_date: crate::clock::now_utc().add(Duration::days(1)),
        name: "test".to_string(),
        chain: "test".to_string(),
        fingerprint: "test".to_string(),
        state: CertificateState::Active,
        roles: vec![],
        key: Some(dummy_key().into()),
    };
    identifier_repository.expect_get().return_once(move |_| {
        Ok(Identifier {
            id: identifier_id,
            data: IdentifierData::Certificate(RelatedVec::from(vec![certificate])),
            ..dummy_identifier()
        })
    });

    let mut dummy_protocol = MockIssuanceProtocol::default();
    dummy_protocol
        .expect_get_capabilities()
        .once()
        .returning(generic_capabilities);
    let mut protocol_provider = MockIssuanceProtocolProvider::default();
    protocol_provider
        .expect_get_protocol()
        .once()
        .return_once(move |_| Ok(Arc::new(dummy_protocol)));

    let service = setup_service(Repositories {
        credential_repository,
        credential_schema_repository,
        identifier_repository,
        formatter_provider,
        protocol_provider,
        config: generic_config().core,
        ..Default::default()
    });

    // when
    let result = service
        .create_credential(CreateCredentialRequestDTO {
            credential_schema_id: Uuid::new_v4().into(),
            issuer: Some(identifier_id),
            issuer_did: None,
            issuer_key: None,
            issuer_certificate: Some(certificate_id),
            protocol: "OPENID4VCI_FINAL1".to_string(),
            claim_values: vec![],
            redirect_uri: None,
            profile: None,
            webhook_destination_url: None,
            subscriber_information: None,
            ecosystem: None,
        })
        .await;

    // then
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0330);
}

#[tokio::test]
async fn test_list_credential_session_org_mismatch() {
    let service = setup_service(Repositories {
        config: generic_config().core,
        session_provider: Some(Arc::new(StaticSessionProvider::new_random())),
        ..Default::default()
    });

    let result = service
        .get_credential_list(ListQueryDTO {
            page: 0,
            page_size: 30,
            sort: None,
            sort_direction: None,
            filter: CredentialFilterParamsDTO {
                organisation_id: Uuid::new_v4().into(),
                name: None,
                search_text: None,
                search_type: None,
                exact: None,
                roles: None,
                ids: None,
                credential_schema_ids: None,
                issuers: None,
                states: None,
                profiles: None,
                created_date_after: None,
                created_date_before: None,
                last_modified_after: None,
                last_modified_before: None,
                issuance_date_after: None,
                issuance_date_before: None,
                revocation_date_after: None,
                revocation_date_before: None,
                expires_at_after: None,
                expires_at_before: None,
                parent_id: None,
                types: None,
                ecosystems: None,
            },
            include: None,
        })
        .await;

    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);
}

#[tokio::test]
async fn test_credential_ops_session_org_mismatch() {
    let mut credential_repository = MockCredentialRepository::default();
    let credential = generic_credential().await;
    credential_repository
        .expect_get_credential()
        .returning(move |_| Ok(credential.clone()));
    let service = setup_service(Repositories {
        credential_repository,
        config: generic_config().core,
        session_provider: Some(Arc::new(StaticSessionProvider::new_random())),
        ..Default::default()
    });

    let result = service.get_credential(&Uuid::new_v4().into()).await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);

    let result = service.delete_credential(&Uuid::new_v4().into()).await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);

    let result = service.share_credential(&Uuid::new_v4().into()).await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);
    // revocation related operations are checked by the credential validity manager
}

fn config_with_eaa_category() -> CoreConfig {
    use crate::config::core_config::DatatypeConfig;

    let mut config = generic_config().core;
    let category_config: DatatypeConfig = serde_yaml::from_str(
        r#"
EAA_CATEGORY:
  display: "datatype.eaaCategory"
  type: "ENUM"
  order: 500
  params:
    public:
      values:
        - value: urn:etsi:esi:eaa:eu:pub
          display: "datatype.category.public"
        - value: urn:etsi:esi:eaa:eu:qualified
          display: "datatype.category.qualified"
"#,
    )
    .unwrap();
    let category_fields = category_config.get_fields("EAA_CATEGORY").unwrap().clone();
    config
        .datatype
        .insert("EAA_CATEGORY".to_string(), category_fields);
    config
}

#[tokio::test]
async fn test_validate_create_request_valid_enum_value() {
    let category_claim_id = Uuid::new_v4().into();
    let now = crate::clock::now_utc();

    let schema = generate_credential_schema_with_claim_schemas(vec![ClaimSchema {
        array: false,
        id: category_claim_id,
        key: "category".to_string(),
        data_type: "EAA_CATEGORY".to_string(),
        created_date: now,
        last_modified: now,
        metadata: false,
        required: true,
        translations: Default::default(),
    }]);

    validate_create_request(
        "OPENID4VCI_FINAL1",
        &mut [CredentialRequestClaimDTO {
            claim_schema_id: category_claim_id,
            value: "urn:etsi:esi:eaa:eu:pub".to_string(),
            path: "category".to_string(),
        }],
        &schema,
        &generic_formatter_capabilities(),
        &config_with_eaa_category(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn test_validate_create_request_valid_enum_value_qualified() {
    let category_claim_id = Uuid::new_v4().into();
    let now = crate::clock::now_utc();

    let schema = generate_credential_schema_with_claim_schemas(vec![ClaimSchema {
        array: false,
        id: category_claim_id,
        key: "category".to_string(),
        data_type: "EAA_CATEGORY".to_string(),
        created_date: now,
        last_modified: now,
        metadata: false,
        required: true,
        translations: Default::default(),
    }]);

    validate_create_request(
        "OPENID4VCI_FINAL1",
        &mut [CredentialRequestClaimDTO {
            claim_schema_id: category_claim_id,
            value: "urn:etsi:esi:eaa:eu:qualified".to_string(),
            path: "category".to_string(),
        }],
        &schema,
        &generic_formatter_capabilities(),
        &config_with_eaa_category(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn test_validate_create_request_invalid_enum_value() {
    let category_claim_id = Uuid::new_v4().into();
    let now = crate::clock::now_utc();

    let schema = generate_credential_schema_with_claim_schemas(vec![ClaimSchema {
        array: false,
        id: category_claim_id,
        key: "category".to_string(),
        data_type: "EAA_CATEGORY".to_string(),
        created_date: now,
        last_modified: now,
        metadata: false,
        required: true,
        translations: Default::default(),
    }]);

    let result = validate_create_request(
        "OPENID4VCI_FINAL1",
        &mut [CredentialRequestClaimDTO {
            claim_schema_id: category_claim_id,
            value: "invalid_value".to_string(),
            path: "category".to_string(),
        }],
        &schema,
        &generic_formatter_capabilities(),
        &config_with_eaa_category(),
    )
    .await;

    assert!(matches!(
        result,
        Err(CredentialServiceError::InvalidDatatype { .. })
    ));
}
