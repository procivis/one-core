use std::ops::Add;
use std::sync::Arc;
use std::vec;

use assert2::let_assert;
use mockall::predicate::*;
use rstest::rstest;
use serde_json::json;
use shared_types::{CredentialId, EcosystemId, EntityId};
use similar_asserts::assert_eq;
use time::Duration;
use uuid::Uuid;

use super::CredentialService;
use super::dto::{
    CreateCredentialRequestDTO, CredentialFilterParamsDTO, CredentialRequestClaimDTO,
    DetailCredentialClaimValueResponseDTO, TrustInformation,
};
use super::error::CredentialServiceError;
use super::mapper::get_credential_trust_information;
use super::validator::validate_create_request;
use crate::config::core_config::CoreConfig;
use crate::error::{ErrorCode, ErrorCodeMixin};
use crate::mapper::credential::stored_credential_claims;
use crate::mapper::credential_schema_claim::backfill_default_translations;
use crate::model::certificate::{Certificate, CertificateState};
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::common::GetListResponse;
use crate::model::credential::{
    Credential, CredentialCommon, CredentialRole, CredentialStateEnum, CredentialType,
    GetCredentialList,
};
use crate::model::credential_schema::{CredentialSchema, KeyStorageSecurity};
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::credential_schema_format_claim_schema::CredentialSchemaFormatClaimSchema;
use crate::model::did::{Did, DidType, KeyRole, RelatedKey};
use crate::model::ecosystem::EcosystemOutcomes;
use crate::model::history::{
    History, HistoryAction, HistoryEntityType, HistoryErrorMetadata, HistoryFilterValue,
    HistoryMetadata, HistorySource, TrustResolutionResult,
};
use crate::model::identifier::{Identifier, IdentifierData, IdentifierState};
use crate::model::key::Key;
use crate::model::list_filter::ListFilterCondition;
use crate::model::relation::RelatedVec;
use crate::proto::credential_validity_manager::MockCredentialValidityManager;
use crate::proto::notification_scheduler::MockNotificationScheduler;
use crate::proto::session_provider::test::StaticSessionProvider;
use crate::proto::session_provider::{NoSessionProvider, SessionProvider};
use crate::proto::transaction_manager::NoTransactionManager;
use crate::provider::blob_storage::provider::MockBlobStorageProvider;
use crate::provider::credential_formatter::MockCredentialFormatter;
use crate::provider::credential_formatter::model::FormatterCapabilities;
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::ecosystem::MockEcosystem;
use crate::provider::ecosystem::directory::MockEcosystemDirectory;
use crate::provider::ecosystem::error::EcosystemError;
use crate::provider::issuance_protocol::MockIssuanceProtocol;
use crate::provider::issuance_protocol::dto::IssuanceProtocolCapabilities;
use crate::provider::issuance_protocol::model::ShareResponse;
use crate::provider::issuance_protocol::provider::MockIssuanceProtocolProvider;
use crate::repository::credential_repository::MockCredentialRepository;
use crate::repository::credential_schema_repository::MockCredentialSchemaRepository;
use crate::repository::error::{DataLayerError, EntityKind};
use crate::repository::history_repository::MockHistoryRepository;
use crate::repository::identifier_repository::MockIdentifierRepository;
use crate::repository::interaction_repository::MockInteractionRepository;
use crate::service::common_dto::ListQueryDTO;
use crate::service::test_utilities::{
    CredentialBuilder, claim_schema as generate_claim_schema, claim_with_schema,
    credential_with_claims, dummy_certificate, dummy_did, dummy_identifier, dummy_key,
    dummy_organisation, generic_config, generic_formatter_capabilities, get_dummy_date,
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
    pub history_repository: MockHistoryRepository,
}

fn setup_service(repositories: Repositories) -> CredentialService {
    let mut history_repository = repositories.history_repository;
    // the detail endpoints look up the recorded ecosystems. Tests that care about them set
    // their own expectation first, and mockall matches that one.
    history_repository.expect_get_history_list().returning(|_| {
        Ok(GetListResponse {
            values: vec![],
            total_pages: Some(0),
            total_items: Some(0),
        })
    });

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
        Arc::new(history_repository),
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
                autogenerated: false,
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
    CredentialBuilder {
        consumed_at: None,
        role: CredentialRole::Holder,
        r#type: CredentialType::Single,
        claims: vec![Claim {
            id: Uuid::new_v4().into(),
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
                autogenerated: false,
                organisation: dummy_organisation(Some(uuid::Uuid::new_v4().into())).into(),
                trust_information: Default::default(),
                logo: None,
                translations: Default::default(),
            }
            .into(),
        ),
        issuer_certificate: None,
        holder_identifier: None,
        key: None,
        credential_blob_id: None,
        wallet_key_attestation_blob_id: None,
        wallet_instance_attestation_blob_id: None,
        webhook_url: None,
        parent: None,
        embedded_disclosure_policy: None,
        subscriber_information: None,
        common: CredentialCommon {
            expires_at: None,
            ecosystem: None,
            id: credential_id,
            created_date: now,
            issuance_date: None,
            last_modified: now,
            deleted_at: None,
            protocol: "OPENID4VCI_FINAL1".to_string(),
            redirect_uri: None,
            state: CredentialStateEnum::Created,
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
                    wallet_attestation: Default::default(),
                    claim_schemas: vec![claim_schema].into(),
                    organisation: organisation.into(),
                    layout_properties: None,
                    allow_suspension: true,
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
            profile: None,
        },
        format: Some(format.into()),
    }
    .build()
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
    CredentialBuilder {
        common: CredentialCommon {
            expires_at: None,
            ecosystem: None,
            id: Uuid::new_v4().into(),
            created_date: now,
            issuance_date: None,
            last_modified: now,
            deleted_at: None,
            protocol: "OPENID4VCI_FINAL1".to_string(),
            redirect_uri: None,
            state: CredentialStateEnum::Created,
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
                    wallet_attestation: Default::default(),
                    formats: vec![format.clone()].into(),
                    claim_schemas: Default::default(),
                    organisation: dummy_organisation(None).into(),
                    layout_properties: None,
                    allow_suspension: true,
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
            profile: None,
        },
        consumed_at: None,
        role: CredentialRole::Issuer,
        r#type: CredentialType::Single,
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
                autogenerated: false,
                organisation: organisation.clone().into(),
                trust_information: Default::default(),
                logo: None,
                translations: Default::default(),
            }
            .into(),
        ),
        issuer_certificate: None,
        holder_identifier: None,
        key: None,
        credential_blob_id: None,
        wallet_key_attestation_blob_id: None,
        wallet_instance_attestation_blob_id: None,
        webhook_url: None,
        parent: None,
        embedded_disclosure_policy: None,
        subscriber_information: None,
        format: Some(format.into()),
    }
    .build()
}

#[tokio::test]
async fn test_delete_credential_success() {
    let mut credential_repository = MockCredentialRepository::default();
    let credential_schema_repository = MockCredentialSchemaRepository::default();

    let credential = generic_credential().await;
    let credential_id = credential.common().id;
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
                total_pages: Some(0),
                total_items: Some(0),
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
        .delete_credential(&generic_credential().await.common().id)
        .await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0001);
}

#[tokio::test]
async fn test_delete_credential_incorrect_state() {
    let mut credential_repository = MockCredentialRepository::default();

    let mut credential = generic_credential().await;
    credential
        .common_mut()
        .schema
        .as_mut()
        .await
        .unwrap()
        .allow_revocation = true;
    credential.common_mut().state = CredentialStateEnum::Accepted;
    credential = CredentialBuilder {
        role: CredentialRole::Issuer,
        ..credential.into()
    }
    .build();

    let copy = credential.clone();
    credential_repository
        .expect_get_credential()
        .returning(move |_| Ok(copy.clone()));

    let service = setup_service(Repositories {
        credential_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.delete_credential(&credential.common().id).await;
    assert!(matches!(
        result,
        Err(CredentialServiceError::InvalidState(_))
    ));
}

#[tokio::test]
async fn test_delete_credential_invalid_type() {
    let mut credential_repository = MockCredentialRepository::default();

    let mut credential = generic_credential().await;
    credential = CredentialBuilder {
        r#type: CredentialType::BatchItem,
        role: CredentialRole::Issuer,
        ..credential.into()
    }
    .build();

    let copy = credential.clone();
    credential_repository
        .expect_get_credential()
        .returning(move |_| Ok(copy.clone()));

    let service = setup_service(Repositories {
        credential_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.delete_credential(&credential.common().id).await;
    assert!(matches!(
        result,
        Err(CredentialServiceError::InvalidType(_))
    ));
}

#[tokio::test]
async fn test_get_credential_list_success() {
    let mut credential_repository = MockCredentialRepository::default();
    let mut c = generic_credential_list_entity().await;
    c.common_mut().state = CredentialStateEnum::Revoked;

    let credentials = GetCredentialList {
        values: vec![generic_credential_list_entity().await, c],
        total_pages: Some(1),
        total_items: Some(2),
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
                formats: None,
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
    assert_eq!(credentials.values[0].common().id, result.values[0].id);
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
            .with(eq(clone.common().id))
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

    let result = service.get_credential(&credential.common().id).await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(credential.common().id, result.id);
    assert_eq!(None, result.revocation_date);
}

#[rstest]
#[case::single(CredentialType::Single)]
#[case::parent(CredentialType::BatchParent)]
#[case::item(CredentialType::BatchItem)]
#[tokio::test]
async fn test_get_credential_instance_attestation_belongs_to_offer(#[case] kind: CredentialType) {
    use crate::model::blob::{Blob, BlobType};
    use crate::provider::blob_storage::MockBlobStorage;
    use crate::service::credential::dto::{WalletInstanceAttestationDTO, WalletUnitAttestationDTO};

    let wia = Blob::new(
        serde_json::to_vec(&WalletInstanceAttestationDTO {
            name: "Wallet".into(),
            link: "https://example.com/wallet".into(),
            attestation: "instance-attestation".into(),
        })
        .unwrap(),
        BlobType::WalletInstanceAttestation,
    );
    let wua = Blob::new(
        serde_json::to_vec(&WalletUnitAttestationDTO {
            attestation: "key-attestation".into(),
        })
        .unwrap(),
        BlobType::WalletUnitAttestation,
    );
    let mut offer = CredentialBuilder {
        role: CredentialRole::Issuer,
        r#type: if kind == CredentialType::Single {
            kind
        } else {
            CredentialType::BatchParent
        },
        wallet_instance_attestation_blob_id: Some(wia.id),
        wallet_key_attestation_blob_id: (kind == CredentialType::Single).then_some(wua.id),
        ..generic_credential().await.into()
    }
    .build();
    offer.common_mut().interaction = None;
    offer.common_mut().state = CredentialStateEnum::Created;
    let credential = if kind == CredentialType::BatchItem {
        let mut builder: CredentialBuilder = offer.clone().into();
        builder.common.id = Uuid::new_v4().into();
        builder.r#type = CredentialType::BatchItem;
        builder.parent = Some(offer.into());
        builder.wallet_instance_attestation_blob_id = None;
        builder.wallet_key_attestation_blob_id = Some(wua.id);
        builder.build()
    } else {
        offer
    };
    let id = credential.common().id;
    let mut repositories = Repositories {
        config: generic_config().core,
        ..Default::default()
    };
    repositories
        .credential_repository
        .expect_get_credential()
        .return_once(move |_| Ok(credential));
    let mut storage = MockBlobStorage::new();
    storage
        .expect_get()
        .once()
        .with(eq(wia.id))
        .return_once(move |_| Ok(Some(wia)));
    if kind != CredentialType::BatchParent {
        storage
            .expect_get()
            .once()
            .with(eq(wua.id))
            .return_once(move |_| Ok(Some(wua)));
    }
    repositories
        .blob_storage_provider
        .expect_get_blob_storage()
        .return_once(move |_| Ok(Arc::new(storage)));
    repositories
        .formatter_provider
        .expect_get_credential_formatter()
        .returning(|_| {
            let mut formatter = MockCredentialFormatter::new();
            formatter.expect_revocation_method_id().return_const(None);
            Ok(Arc::new(formatter))
        });

    let detail = setup_service(repositories)
        .get_credential(&id)
        .await
        .unwrap();
    assert_eq!(
        detail.wallet_instance_attestation.unwrap().attestation,
        "instance-attestation"
    );
    assert_eq!(
        detail
            .wallet_unit_attestation
            .map(|attestation| attestation.attestation),
        (kind != CredentialType::BatchParent).then(|| "key-attestation".to_string())
    );
}

#[tokio::test]
async fn test_get_credential_success_suspended_credential_with_end_date() {
    let mut credential_repository = MockCredentialRepository::default();

    let mut credential =
        crate::service::test_utilities::issuer_credential(generic_credential().await).unwrap();
    let now = crate::clock::now_utc();
    let suspend_end_date = now.add(Duration::hours(1));
    credential.common_mut().state = CredentialStateEnum::Suspended {
        suspend_end_date: Some(suspend_end_date),
    };

    {
        let clone = credential.clone();
        credential_repository
            .expect_get_credential()
            .times(1)
            .with(eq(clone.common().id))
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

    let result = service.get_credential(&credential.common().id).await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(credential.common().id, result.id);
    assert_eq!(None, result.revocation_date);
    assert_eq!(super::dto::CredentialStateEnum::Suspended, result.state);
    assert_eq!(Some(suspend_end_date), result.suspend_end_date);
}

#[tokio::test]
async fn test_get_credential_deleted() {
    let mut credential_repository = MockCredentialRepository::default();

    let credential = {
        let mut updated_credential = generic_credential().await;
        updated_credential.common_mut().deleted_at = Some(crate::clock::now_utc());
        updated_credential
    };
    {
        let clone = credential.clone();
        credential_repository
            .expect_get_credential()
            .times(1)
            .with(eq(clone.common().id))
            .returning(move |_| Ok(clone.clone()));
    }

    let service = setup_service(Repositories {
        credential_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.get_credential(&credential.common().id).await;

    assert!(result.is_err_and(|e| matches!(e, CredentialServiceError::NotFound(_))));
}

#[tokio::test]
async fn test_get_revoked_credential_success() {
    let mut credential_repository = MockCredentialRepository::default();

    let mut credential = generic_credential().await;
    credential.common_mut().state = CredentialStateEnum::Revoked;

    {
        let clone = credential.clone();
        credential_repository
            .expect_get_credential()
            .times(1)
            .with(eq(clone.common().id))
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

    let result = service.get_credential(&credential.common().id).await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(credential.common().id, result.id);
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

    let credential =
        crate::service::test_utilities::issuer_credential(generic_credential().await).unwrap();
    let credential_id = credential.common().id;
    {
        let clone = credential.clone();
        credential_repository
            .expect_get_credential()
            .times(1)
            .with(eq(clone.common().id))
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
            id == &credential_id && update.state == Some(CredentialStateEnum::Pending)
        })
        .returning(|_, _| Ok(()));

    let service = setup_service(Repositories {
        credential_repository,
        config: generic_config().core,
        protocol_provider,
        interaction_repository,
        ..Default::default()
    });

    let result = service.share_credential(&credential.common().id).await;

    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.url, expected_url);
    assert_eq!(result.expires_at.unwrap(), expires_at);
}

#[tokio::test]
async fn test_share_credential_failed_invalid_state() {
    let mut credential_repository = MockCredentialRepository::default();

    let mut credential = generic_credential().await;
    credential.common_mut().state = CredentialStateEnum::Accepted;
    {
        let clone = credential.clone();
        credential_repository
            .expect_get_credential()
            .times(1)
            .with(eq(clone.common().id))
            .returning(move |_| Ok(clone.clone()));
    }

    let service = setup_service(Repositories {
        credential_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.share_credential(&credential.common().id).await;
    assert!(result.is_err_and(|e| matches!(e, CredentialServiceError::InvalidState(_))));
}

#[tokio::test]
async fn test_share_credential_failed_invalid_type() {
    let mut credential_repository = MockCredentialRepository::default();

    let mut credential = generic_credential().await;
    credential = CredentialBuilder {
        r#type: CredentialType::BatchItem,
        ..credential.into()
    }
    .build();
    {
        let clone = credential.clone();
        credential_repository
            .expect_get_credential()
            .times(1)
            .with(eq(clone.common().id))
            .returning(move |_| Ok(clone.clone()));
    }

    let service = setup_service(Repositories {
        credential_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.share_credential(&credential.common().id).await;
    assert!(result.is_err_and(|e| matches!(e, CredentialServiceError::InvalidType(_))));
}

#[tokio::test]
async fn test_share_credential_failed_inactive_identifier() {
    let mut credential_repository = MockCredentialRepository::default();

    let mut credential =
        crate::service::test_utilities::issuer_credential(generic_credential().await).unwrap();
    credential
        .issuer_mut()
        .unwrap()
        .data
        .identifier
        .as_mut()
        .await
        .unwrap()
        .state = IdentifierState::Deactivated;
    {
        let clone = credential.clone();
        credential_repository
            .expect_get_credential()
            .times(1)
            .with(eq(clone.common().id))
            .returning(move |_| Ok(clone.clone()));
    }

    let service = setup_service(Repositories {
        credential_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = service.share_credential(&credential.common().id).await;
    assert!(result.is_err_and(|e| matches!(e, CredentialServiceError::IdentifierIsDeactivated(_))));
}

struct CredentialCreationFixture {
    request: CreateCredentialRequestDTO,
    schema: CredentialSchema,
    issuer_did: Did,
    formatter_capabilities: FormatterCapabilities,
}

impl CredentialCreationFixture {
    async fn new() -> Self {
        let credential = generic_credential().await;
        let issuer = credential
            .holder()
            .unwrap()
            .data
            .issuer
            .identifier
            .as_ref()
            .await
            .unwrap();
        let_assert!(IdentifierData::Did(issuer_did) = &issuer.data);
        let issuer_did = issuer_did.as_ref().await.unwrap().clone();
        let schema = credential.common().schema.as_ref().await.unwrap().clone();
        let claims = stored_credential_claims(&credential).await.unwrap();
        let claim = &claims[0];
        let issuer_key = issuer_did.keys.as_ref().await.unwrap()[0].key.id;

        Self {
            request: CreateCredentialRequestDTO {
                credential_schema_id: schema.id,
                issuer: None,
                issuer_did: Some(issuer_did.id),
                issuer_key: Some(issuer_key),
                issuer_certificate: None,
                protocol: "OPENID4VCI_FINAL1".to_string(),
                claim_values: vec![CredentialRequestClaimDTO {
                    claim_schema_id: claim.schema.id(),
                    value: claim.value.clone().unwrap(),
                    path: claim.path.clone(),
                }],
                redirect_uri: None,
                profile: None,
                webhook_destination_url: None,
                subscriber_information: None,
                ecosystem: None,
                formats: None,
            },
            schema,
            issuer_did,
            formatter_capabilities: generic_formatter_capabilities(),
        }
    }

    async fn into_repositories(self) -> (Repositories, CreateCredentialRequestDTO) {
        let mut repositories = Repositories {
            config: generic_config().core,
            ..Default::default()
        };
        let format = self.schema.format().await.unwrap();
        repositories
            .credential_schema_repository
            .expect_get_credential_schema()
            .once()
            .with(eq(self.schema.id))
            .return_once(move |_| Ok(self.schema));
        repositories
            .identifier_repository
            .expect_get_from_did_id()
            .once()
            .with(eq(self.issuer_did.id))
            .return_once(move |_| {
                Ok(Some(Identifier {
                    data: IdentifierData::Did(self.issuer_did.into()),
                    ..dummy_identifier()
                }))
            });

        let mut formatter = MockCredentialFormatter::default();
        formatter
            .expect_get_capabilities()
            .once()
            .return_once(move || self.formatter_capabilities);
        repositories
            .formatter_provider
            .expect_get_credential_formatter()
            .once()
            .with(eq(format))
            .return_once(move |_| Ok(Arc::new(formatter)));

        let mut protocol = MockIssuanceProtocol::default();
        protocol
            .expect_get_capabilities()
            .once()
            .return_once(generic_capabilities);
        repositories
            .protocol_provider
            .expect_get_protocol()
            .once()
            .with(eq(self.request.protocol.clone()))
            .return_once(move |_| Ok(Arc::new(protocol)));

        (repositories, self.request)
    }
}

#[rstest]
#[case::automatic_key_selection(false, false)]
#[case::explicit_issuer_key(true, false)]
#[case::same_key_with_multiple_roles(true, true)]
#[tokio::test]
async fn test_create_credential_with_issuer_key(
    #[case] explicit_key: bool,
    #[case] multiple_roles: bool,
) {
    let mut fixture = CredentialCreationFixture::new().await;
    if !explicit_key {
        fixture.request.issuer_key = None;
    }
    if multiple_roles {
        let mut keys = fixture.issuer_did.keys.as_mut().await.unwrap();
        let mut key = keys[0].clone();
        key.role = KeyRole::KeyAgreement;
        keys.insert(0, key);
    }

    let (mut repositories, request) = fixture.into_repositories().await;
    let credential_id = Uuid::new_v4().into();
    repositories
        .credential_repository
        .expect_create_credential()
        .withf(|credential| matches!(credential, Credential::IssuerSingle { .. }))
        .once()
        .return_once(move |_| Ok(credential_id));

    let result = setup_service(repositories).create_credential(request).await;

    assert_eq!(result.unwrap(), credential_id);
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
            .holder()
            .unwrap()
            .data
            .issuer
            .identifier
            .as_ref()
            .await
            .unwrap()
            .to_owned();
        let credential_schema = credential
            .common()
            .schema
            .as_ref()
            .await
            .unwrap()
            .to_owned();

        identifier_repository
            .expect_get()
            .return_once(|_| Ok(issuer_identifier));

        credential_schema_repository
            .expect_get_credential_schema()
            .times(1)
            .returning(move |_| Ok(credential_schema.clone()));

        credential_repository
            .expect_create_credential()
            .withf(|credential| matches!(credential, Credential::IssuerSingle { .. }))
            .times(1)
            .returning(move |_| Ok(clone.common().id));
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
            .common()
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

    let claims = stored_credential_claims(&credential).await.unwrap();
    let claim = &claims[0];
    let result = service
        .create_credential(CreateCredentialRequestDTO {
            credential_schema_id: credential
                .common()
                .schema
                .as_ref()
                .await
                .unwrap()
                .id
                .to_owned(),
            issuer: Some(credential.holder().unwrap().data.issuer.identifier.id()),
            issuer_did: None,
            issuer_key: None,
            issuer_certificate: None,
            protocol: "OPENID4VCI_FINAL1".to_string(),
            claim_values: vec![CredentialRequestClaimDTO {
                claim_schema_id: claim.schema.as_ref().await.unwrap().id.to_owned(),
                value: claim.value.to_owned().unwrap(),
                path: claim.path.to_owned(),
            }],
            redirect_uri: None,
            profile: None,
            webhook_destination_url: None,
            subscriber_information: None,
            ecosystem: None,
            formats: None,
        })
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_create_credential_failed_unsupported_wallet_storage_type() {
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let mut identifier_repository = MockIdentifierRepository::default();

    let credential = generic_credential().await;
    let schema = &credential.common().schema;
    let claims = stored_credential_claims(&credential).await.unwrap();
    let issuer_identifier = credential.holder().unwrap().data.issuer.identifier.clone();

    let mut schema = schema.as_ref().await.unwrap().to_owned();

    schema.wallet_attestation.key_storage_security_level = Some(KeyStorageSecurity::EnhancedBasic);
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
            formats: None,
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
            .holder()
            .unwrap()
            .data
            .issuer
            .identifier
            .as_ref()
            .await
            .unwrap()
            .to_owned()
    );
    {
        let issuer_did = issuer_identifier_did.clone();
        let credential_schema = credential
            .common()
            .schema
            .as_ref()
            .await
            .unwrap()
            .to_owned();

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
            .common()
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

    let claims = stored_credential_claims(&credential).await.unwrap();
    let claim = &claims[0];
    let result = service
        .create_credential(CreateCredentialRequestDTO {
            credential_schema_id: credential
                .common()
                .schema
                .as_ref()
                .await
                .unwrap()
                .id
                .to_owned(),
            issuer: None,
            issuer_did: Some(issuer_identifier_did.id()),
            issuer_key: None,
            issuer_certificate: None,
            protocol: "OPENID4VCI_FINAL1".to_string(),
            claim_values: vec![CredentialRequestClaimDTO {
                claim_schema_id: claim.schema.as_ref().await.unwrap().id.to_owned(),
                value: claim.value.to_owned().unwrap(),
                path: claim.path.to_owned(),
            }],
            redirect_uri: None,
            profile: None,
            webhook_destination_url: None,
            subscriber_information: None,
            ecosystem: None,
            formats: None,
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
            .holder()
            .unwrap()
            .data
            .issuer
            .identifier
            .as_ref()
            .await
            .unwrap()
            .to_owned()
    );
    {
        let issuer_did = issuer_identifier_did.clone();
        let credential_schema = credential
            .common()
            .schema
            .as_ref()
            .await
            .unwrap()
            .to_owned();

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
            .common()
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

    let claims = stored_credential_claims(&credential).await.unwrap();
    let claim = &claims[0];
    let result = service
        .create_credential(CreateCredentialRequestDTO {
            credential_schema_id: credential
                .common()
                .schema
                .as_ref()
                .await
                .unwrap()
                .id
                .to_owned(),
            issuer: None,
            issuer_did: Some(issuer_identifier_did.id()),
            issuer_key: None,
            issuer_certificate: None,
            protocol: "OPENID4VCI_FINAL1".to_string(),
            claim_values: vec![CredentialRequestClaimDTO {
                claim_schema_id: claim.schema.as_ref().await.unwrap().id.to_owned(),
                value: claim.value.to_owned().unwrap(),
                path: claim.path.to_owned(),
            }],
            redirect_uri: None,
            profile: None,
            webhook_destination_url: None,
            subscriber_information: None,
            ecosystem: None,
            formats: None,
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
    let credential_schema = credential
        .common()
        .schema
        .as_ref()
        .await
        .unwrap()
        .to_owned();
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
            .common()
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
            formats: None,
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
            .holder()
            .unwrap()
            .data
            .issuer
            .identifier
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
        ..credential
            .common()
            .schema
            .as_ref()
            .await
            .unwrap()
            .to_owned()
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
            .withf(|credential| matches!(credential, Credential::IssuerSingle { .. }))
            .times(1)
            .returning(move |_| Ok(clone.common().id));

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
        credential_schema_id: credential
            .common()
            .schema
            .as_ref()
            .await
            .unwrap()
            .id
            .to_owned(),
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
        formats: None,
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
            .holder()
            .unwrap()
            .data
            .issuer
            .identifier
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
        ..credential
            .common()
            .schema
            .as_ref()
            .await
            .unwrap()
            .to_owned()
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
        credential_schema_id: credential
            .common()
            .schema
            .as_ref()
            .await
            .unwrap()
            .id
            .to_owned(),
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
        formats: None,
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
            .holder()
            .unwrap()
            .data
            .issuer
            .identifier
            .as_ref()
            .await
            .unwrap()
            .to_owned()
    );

    let claim_schema_id = Uuid::new_v4().into();
    let credential_schema = {
        let schema = credential
            .common()
            .schema
            .as_ref()
            .await
            .unwrap()
            .to_owned();
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
            let claims = futures::executor::block_on(stored_credential_claims(request)).unwrap();
            assert_eq!(claims.len(), 1);
            let claim = &claims[0];
            assert_eq!(claim.value.as_ref().unwrap(), "value");
            assert_eq!(claim.path, "required");
            assert_eq!(claim.schema.id(), claim_schema_id);
            true
        })
        .returning(|request| Ok(request.common().id));

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
        formats: None,
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

    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0485);
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
            .holder()
            .unwrap()
            .data
            .issuer
            .identifier
            .as_ref()
            .await
            .unwrap()
            .to_owned()
    );
    let credential_schema = CredentialSchema {
        deleted_at: Some(crate::clock::now_utc()),
        ..credential
            .common()
            .schema
            .as_ref()
            .await
            .unwrap()
            .to_owned()
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
            credential_schema_id: credential
                .common()
                .schema
                .as_ref()
                .await
                .unwrap()
                .id
                .to_owned(),
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
            formats: None,
        })
        .await;

    assert2::assert!(
        let Err(CredentialServiceError::MissingCredentialSchema(_)) = result
    );
}

#[rstest]
#[case::no_assertion_key(
    |request: &mut CreateCredentialRequestDTO, key: &mut RelatedKey| {
        request.issuer_key = None;
        key.role = KeyRole::KeyAgreement;
    },
    ErrorCode::BR_0330,
)]
#[case::unknown_key_id(
    |request: &mut CreateCredentialRequestDTO, _: &mut RelatedKey| {
        request.issuer_key = Some(Uuid::new_v4().into());
    },
    ErrorCode::BR_0330,
)]
#[case::wrong_key_role(
    |_: &mut CreateCredentialRequestDTO, key: &mut RelatedKey| key.role = KeyRole::KeyAgreement,
    ErrorCode::BR_0330,
)]
#[case::unsupported_key_algorithm(
    |_: &mut CreateCredentialRequestDTO, key: &mut RelatedKey| key.key.key_type = "unsupported".to_string(),
    ErrorCode::BR_0330,
)]
#[tokio::test]
async fn test_create_credential_rejects_invalid_issuer_key(
    #[case] invalid_override: fn(&mut CreateCredentialRequestDTO, &mut RelatedKey),
    #[case] expected_error: ErrorCode,
) {
    let mut fixture = CredentialCreationFixture::new().await;
    {
        let mut keys = fixture.issuer_did.keys.as_mut().await.unwrap();
        invalid_override(&mut fixture.request, &mut keys[0]);
    }
    let (repositories, request) = fixture.into_repositories().await;

    let result = setup_service(repositories).create_credential(request).await;

    assert_eq!(result.unwrap_err().error_code(), expected_error);
}

#[tokio::test]
async fn test_create_credential_fail_incompatible_format_and_transport_protocol() {
    let mut fixture = CredentialCreationFixture::new().await;
    fixture.request.issuer_key = None;
    fixture
        .formatter_capabilities
        .issuance_exchange_protocols
        .clear();
    let (repositories, request) = fixture.into_repositories().await;

    let result = setup_service(repositories).create_credential(request).await;

    assert!(matches!(
        result,
        Err(CredentialServiceError::IncompatibleIssuanceExchangeProtocol)
    ));
}

#[tokio::test]
async fn test_create_credential_fail_invalid_redirect_uri() {
    let mut fixture = CredentialCreationFixture::new().await;
    fixture.request.redirect_uri = Some("invalid://domain.com".to_string());
    let (repositories, request) = fixture.into_repositories().await;

    let result = setup_service(repositories).create_credential(request).await;

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
            .holder()
            .unwrap()
            .data
            .issuer
            .identifier
            .as_ref()
            .await
            .unwrap()
            .to_owned();
        let credential_schema = credential
            .common()
            .schema
            .as_ref()
            .await
            .unwrap()
            .to_owned();

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
            .common()
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

    let claims = stored_credential_claims(&credential).await.unwrap();
    let claim = &claims[0];
    let result = service
        .create_credential(CreateCredentialRequestDTO {
            credential_schema_id: credential
                .common()
                .schema
                .as_ref()
                .await
                .unwrap()
                .id
                .to_owned(),
            issuer: Some(credential.holder().unwrap().data.issuer.identifier.id()),
            issuer_did: None,
            issuer_key: None,
            issuer_certificate: None,
            protocol: "OPENID4VCI_FINAL1".to_string(),
            claim_values: vec![CredentialRequestClaimDTO {
                claim_schema_id: claim.schema.as_ref().await.unwrap().id.to_owned(),
                value: claim.value.to_owned().unwrap(),
                path: claim.path.to_owned(),
            }],
            redirect_uri: None,
            profile: None,
            webhook_destination_url: Some("http://webhook.url".to_string()),
            subscriber_information: None,
            ecosystem: None,
            formats: None,
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
        wallet_attestation: Default::default(),
        layout_properties: None,
        allow_suspension: true,
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
        supported_encryption_algorithms: vec![],
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

    credential
        .common_mut()
        .schema
        .as_mut()
        .await
        .unwrap()
        .claim_schemas = vec![location_claim_schema, location_x_claim_schema.to_owned()].into();

    let updated_schema = credential
        .common()
        .schema
        .as_ref()
        .await
        .unwrap()
        .to_owned();
    credential.common_mut().schema = backfill_default_translations(updated_schema, "en")
        .await
        .unwrap()
        .into();
    credential.holder_mut().unwrap().data.claims = vec![Claim {
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
        value: Some("123".to_string()),
        path: location_x_claim_schema.key.clone(),
        selectively_disclosable: false,
        schema: location_x_claim_schema.clone().into(),
    }]
    .into();

    {
        let clone = credential.clone();
        credential_repository
            .expect_get_credential()
            .times(1)
            .with(eq(clone.common().id))
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

    let result = service
        .get_credential(&credential.common().id)
        .await
        .unwrap();
    assert_eq!(credential.common().id, result.id);
    assert_eq!(None, result.revocation_date);
    assert_eq!(1, result.claims.len());
    assert_eq!("location", result.claims[0].schema.key);
    assert!(matches!(
        result.claims[0].value,
        DetailCredentialClaimValueResponseDTO::Nested(_)
    ));
}

fn generate_claim(claim_schema: &ClaimSchema, value: &str, path: &str) -> Claim {
    claim_with_schema(claim_schema, path, Some(value))
}

async fn credential_detail_with_claims(
    format: &str,
    state: CredentialStateEnum,
    claim_schemas: Vec<ClaimSchema>,
    claims: Vec<Claim>,
) -> super::dto::CredentialDetailResponseDTO<super::dto::DetailCredentialClaimResponseDTO> {
    let mut credential = credential_with_claims(format, claim_schemas, claims).await;
    credential.common_mut().state = state;
    let id = credential.common().id;
    let mut credential_repository = MockCredentialRepository::default();
    credential_repository
        .expect_get_credential()
        .times(1)
        .with(eq(id))
        .return_once(move |_| Ok(credential));

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .return_once(|_| {
            let mut formatter = MockCredentialFormatter::new();
            formatter.expect_revocation_method_id().return_const(None);
            Ok(Arc::new(formatter))
        });

    setup_service(Repositories {
        credential_repository,
        formatter_provider,
        config: generic_config().core,
        ..Default::default()
    })
    .get_credential(&id)
    .await
    .unwrap()
}

// Keep the complete serialized schema assertion, including translations and the
// distinction between an array container and each of its non-array elements.
fn expected_claim_schema(schema: &ClaimSchema, array: bool) -> serde_json::Value {
    json!({
        "id": schema.id,
        "createdDate": "2005-04-02T21:37:00+01:00",
        "lastModified": "2005-04-02T21:37:00+01:00",
        "key": schema.key,
        "datatype": schema.data_type,
        "required": true,
        "array": array,
        "translations": { "name": { "en": schema.key.rsplit('/').next().unwrap() } },
    })
}

#[tokio::test]
async fn test_get_credential_success_array_complex_nested_all() {
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

    let claims = vec![
        generate_claim(&schema_root_index_list, "123", "root/0/indexlist/0"),
        generate_claim(&schema_root_index_list, "123", "root/0/indexlist/1"),
        generate_claim(&schema_root_name, "123", "root/0/name"),
        generate_claim(&schema_root_cap, "invoke", "root/0/cap/0"),
        generate_claim(&schema_root_cap, "revoke", "root/0/cap/1"),
        generate_claim(&schema_root_cap, "delete", "root/0/cap/2"),
        generate_claim(&schema_root_index_list, "456", "root/1/indexlist/0"),
        generate_claim(&schema_root_index_list, "456", "root/1/indexlist/1"),
        generate_claim(&schema_root_name, "456", "root/1/name"),
        generate_claim(&schema_root_cap, "invoke", "root/1/cap/0"),
        generate_claim(&schema_root_cap, "revoke", "root/1/cap/1"),
        generate_claim(&schema_root_cap, "delete", "root/1/cap/2"),
        generate_claim(&schema_other_0_name, "name1", "other/0/0/name"),
        generate_claim(&schema_other_0_name, "name2", "other/0/1/name"),
        generate_claim(&schema_other_1, "other1", "other/1/0"),
        generate_claim(&schema_other_1, "other2", "other/1/1"),
        generate_claim(&schema_other_1, "other3", "other/1/2"),
        generate_claim(&schema_str, "str1", "str/0"),
        generate_claim(&schema_str, "str1", "str/1"),
        generate_claim(&schema_str, "str1", "str/2"),
    ];

    let result =
        credential_detail_with_claims("JWT", CredentialStateEnum::Created, claim_schemas, claims)
            .await;

    let expected_claims = json!([
      {
        "path": "root",
        "schema": expected_claim_schema(&schema_root, true),
        "value": [
          {
            "path": "root/0",
            "schema": expected_claim_schema(&schema_root, false),
            "value": [
              {
                "path": "root/0/indexlist",
                "schema": expected_claim_schema(&schema_root_index_list, true),
                "value": [
                  {
                    "path": "root/0/indexlist/0",
                    "schema": expected_claim_schema(&schema_root_index_list, false),
                    "value": 123
                  },
                  {
                    "path": "root/0/indexlist/1",
                    "schema": expected_claim_schema(&schema_root_index_list, false),
                    "value": 123
                  }
                ]
              },
              {
                "path": "root/0/name",
                "schema": expected_claim_schema(&schema_root_name, false),
                "value": "123"
              },
              {
                "path": "root/0/cap",
                "schema": expected_claim_schema(&schema_root_cap, true),
                "value": [
                  {
                    "path": "root/0/cap/0",
                    "schema": expected_claim_schema(&schema_root_cap, false),
                    "value": "invoke"
                  },
                  {
                    "path": "root/0/cap/1",
                    "schema": expected_claim_schema(&schema_root_cap, false),
                    "value": "revoke"
                  },
                  {
                    "path": "root/0/cap/2",
                    "schema": expected_claim_schema(&schema_root_cap, false),
                    "value": "delete"
                  }
                ]
              }
            ]
          },
          {
            "path": "root/1",
            "schema": expected_claim_schema(&schema_root, false),
            "value": [
              {
                "path": "root/1/indexlist",
                "schema": expected_claim_schema(&schema_root_index_list, true),
                "value": [
                  {
                    "path": "root/1/indexlist/0",
                    "schema": expected_claim_schema(&schema_root_index_list, false),
                    "value": 456
                  },
                  {
                    "path": "root/1/indexlist/1",
                    "schema": expected_claim_schema(&schema_root_index_list, false),
                    "value": 456
                  }
                ]
              },
              {
                "path": "root/1/name",
                "schema": expected_claim_schema(&schema_root_name, false),
                "value": "456"
              },
              {
                "path": "root/1/cap",
                "schema": expected_claim_schema(&schema_root_cap, true),
                "value": [
                  {
                    "path": "root/1/cap/0",
                    "schema": expected_claim_schema(&schema_root_cap, false),
                    "value": "invoke"
                  },
                  {
                    "path": "root/1/cap/1",
                    "schema": expected_claim_schema(&schema_root_cap, false),
                    "value": "revoke"
                  },
                  {
                    "path": "root/1/cap/2",
                    "schema": expected_claim_schema(&schema_root_cap, false),
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
        "schema": expected_claim_schema(&schema_other, false),
        "value": [
          {
            "path": "other/0",
            "schema": expected_claim_schema(&schema_other_0, true),
            "value": [
              {
                "path": "other/0/0",
                "schema": expected_claim_schema(&schema_other_0, false),
                "value": [
                  {
                    "path": "other/0/0/name",
                    "schema": expected_claim_schema(&schema_other_0_name, false),
                    "value": "name1"
                  }
                ]
              },
              {
                "path": "other/0/1",
                "schema": expected_claim_schema(&schema_other_0, false),
                "value": [
                  {
                    "path": "other/0/1/name",
                    "schema": expected_claim_schema(&schema_other_0_name, false),
                    "value": "name2"
                  }
                ]
              }
            ]
          },
          {
            "path": "other/1",
            "schema": expected_claim_schema(&schema_other_1, true),
            "value": [
              {
                "path": "other/1/0",
                "schema": expected_claim_schema(&schema_other_1, false),
                "value": "other1"
              },
              {
                "path": "other/1/1",
                "schema": expected_claim_schema(&schema_other_1, false),
                "value": "other2"
              },
              {
                "path": "other/1/2",
                "schema": expected_claim_schema(&schema_other_1, false),
                "value": "other3"
              }
            ]
          }
        ]
      },
      {
        "path": "str",
        "schema": expected_claim_schema(&schema_str, true),
        "value": [
          {
            "path": "str/0",
            "schema": expected_claim_schema(&schema_str, false),
            "value": "str1"
          },
          {
            "path": "str/1",
            "schema": expected_claim_schema(&schema_str, false),
            "value": "str1"
          },
          {
            "path": "str/2",
            "schema": expected_claim_schema(&schema_str, false),
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
    let schema_str = generate_claim_schema("str", "STRING", true);

    let claim_schemas = vec![schema_str.to_owned()];

    let claims = [2, 0, 1, 6, 7, 3, 4, 10, 11, 5, 9, 8, 12]
        .into_iter()
        .map(|index| generate_claim(&schema_str, "str1", &format!("str/{index}")))
        .collect();

    let result =
        credential_detail_with_claims("JWT", CredentialStateEnum::Created, claim_schemas, claims)
            .await;

    let expected_elements = (0..=12)
        .map(|index| {
            json!({
                "path": format!("str/{index}"),
                "schema": expected_claim_schema(&schema_str, false),
                "value": "str1",
            })
        })
        .collect::<Vec<_>>();
    let expected_claims = json!([{
        "path": "str",
        "schema": expected_claim_schema(&schema_str, true),
        "value": expected_elements,
    }]);

    assert_eq!(
        expected_claims,
        serde_json::to_value(result.claims).unwrap()
    );
}

#[tokio::test]
async fn test_get_credential_success_array_complex_nested_first_case() {
    let schema_root = generate_claim_schema("root", "OBJECT", true);
    let schema_root_index_list = generate_claim_schema("root/indexlist", "NUMBER", true);

    let claim_schemas = vec![schema_root.to_owned(), schema_root_index_list.to_owned()];

    let claims = vec![
        generate_claim(&schema_root_index_list, "123", "root/0/indexlist/0"),
        generate_claim(&schema_root_index_list, "123", "root/0/indexlist/1"),
    ];

    let result =
        credential_detail_with_claims("MDOC", CredentialStateEnum::Accepted, claim_schemas, claims)
            .await;

    let expected_claims = json!([
      {
        "path": "root",
        "schema": expected_claim_schema(&schema_root, true),
        "value": [
          {
            "path": "root/0",
            "schema": expected_claim_schema(&schema_root, false),
            "value": [
              {
                "path": "root/0/indexlist",
                "schema": expected_claim_schema(&schema_root_index_list, true),
                "value": [
                  {
                    "path": "root/0/indexlist/0",
                    "schema": expected_claim_schema(&schema_root_index_list, false),
                    "value": 123
                  },
                  {
                    "path": "root/0/indexlist/1",
                    "schema": expected_claim_schema(&schema_root_index_list, false),
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
    assert_eq!(
        get_dummy_date(),
        result.mdoc_mso_validity.unwrap().last_update
    );
    assert_eq!(
        expected_claims,
        serde_json::to_value(result.claims).unwrap()
    );
}

#[tokio::test]
async fn test_get_credential_success_array_single_element() {
    let schema_root = generate_claim_schema("root", "OBJECT", true);
    let schema_root_index_list = generate_claim_schema("root/indexlist", "NUMBER", true);

    let claim_schemas = vec![schema_root.to_owned(), schema_root_index_list.to_owned()];

    let claims = vec![generate_claim(
        &schema_root_index_list,
        "123",
        "root/0/indexlist/0",
    )];

    let result =
        credential_detail_with_claims("JWT", CredentialStateEnum::Created, claim_schemas, claims)
            .await;

    let expected_claims = json!([
      {
        "path": "root",
        "schema": expected_claim_schema(&schema_root, true),
        "value": [
          {
            "path": "root/0",
            "schema": expected_claim_schema(&schema_root, false),
            "value": [
              {
                "path": "root/0/indexlist",
                "schema": expected_claim_schema(&schema_root_index_list, true),
                "value": [
                  {
                    "path": "root/0/indexlist/0",
                    "schema": expected_claim_schema(&schema_root_index_list, false),
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
        wallet_attestation: Default::default(),
        layout_properties: None,
        allow_suspension: true,
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
            formats: None,
        })
        .await
}

#[tokio::test]
async fn test_create_credential_array_simple_string() {
    let schema_str = generate_claim_schema("str", "STRING", true);

    let claim_schemas = vec![schema_str.to_owned()];

    let claims = vec![
        generate_claim(&schema_str, "str1", "str/0"),
        generate_claim(&schema_str, "str1", "str/1"),
        generate_claim(&schema_str, "str1", "str/2"),
    ];

    test_create_credential_array(claim_schemas, claims)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_create_credential_array_simple_object() {
    let schema_root = generate_claim_schema("root", "OBJECT", true);
    let schema_root_index_list = generate_claim_schema("root/indexlist", "NUMBER", true);

    let claim_schemas = vec![schema_root.to_owned(), schema_root_index_list.to_owned()];

    let claims = vec![
        generate_claim(&schema_root_index_list, "123", "root/0/indexlist/0"),
        generate_claim(&schema_root_index_list, "123", "root/0/indexlist/1"),
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

    let claims = vec![
        generate_claim(&schema_root_index_list, "123", "root/0/indexlist/0"),
        generate_claim(&schema_root_index_list, "123", "root/0/indexlist/1"),
        generate_claim(&schema_root_name, "123", "root/0/name"),
        generate_claim(&schema_root_cap, "invoke", "root/0/cap/0"),
        generate_claim(&schema_root_cap, "revoke", "root/0/cap/1"),
        generate_claim(&schema_root_cap, "delete", "root/0/cap/2"),
        generate_claim(&schema_root_index_list, "456", "root/1/indexlist/0"),
        generate_claim(&schema_root_index_list, "456", "root/1/indexlist/1"),
        generate_claim(&schema_root_name, "456", "root/1/name"),
        generate_claim(&schema_root_cap, "invoke", "root/1/cap/0"),
        generate_claim(&schema_root_cap, "revoke", "root/1/cap/1"),
        generate_claim(&schema_root_cap, "delete", "root/1/cap/2"),
        generate_claim(&schema_other_0_name, "name1", "other/0/0/name"),
        generate_claim(&schema_other_0_name, "name2", "other/0/1/name"),
        generate_claim(&schema_other_1, "other1", "other/1/0"),
        generate_claim(&schema_other_1, "other2", "other/1/1"),
        generate_claim(&schema_other_1, "other3", "other/1/2"),
        generate_claim(&schema_str, "str1", "str/0"),
        generate_claim(&schema_str, "str1", "str/1"),
        generate_claim(&schema_str, "str1", "str/2"),
    ];

    test_create_credential_array(claim_schemas, claims)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_create_credential_array_fail_incorrect_index() {
    let schema_root = generate_claim_schema("root", "OBJECT", true);
    let schema_root_index_list = generate_claim_schema("root/indexlist", "NUMBER", true);

    let claim_schemas = vec![schema_root.to_owned(), schema_root_index_list.to_owned()];

    let unparsable_index = generate_claim(
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
        &schema_root_index_list,
        "123",
        "root/not_an_index/indexlist/0",
    );
    assert!(
        test_create_credential_array(claim_schemas.to_owned(), vec![unparsable_index_parent])
            .await
            .is_err()
    );

    let missing_component = generate_claim(&schema_root_index_list, "123", "root/indexlist/0");
    assert!(
        test_create_credential_array(claim_schemas.to_owned(), vec![missing_component])
            .await
            .is_err()
    );

    let malformed_path = generate_claim(&schema_root_index_list, "123", "not_even_a_path");
    assert!(
        test_create_credential_array(claim_schemas.to_owned(), vec![malformed_path])
            .await
            .is_err()
    );

    let malformed_path = generate_claim(&schema_root_index_list, "123", "///////");
    assert!(
        test_create_credential_array(claim_schemas.to_owned(), vec![malformed_path])
            .await
            .is_err()
    );
}

#[tokio::test]
async fn test_create_credential_array_fail_index_incorrect_order() {
    let schema_root = generate_claim_schema("root", "OBJECT", true);
    let schema_root_index_list = generate_claim_schema("root/indexlist", "NUMBER", true);

    let claim_schemas = vec![schema_root.to_owned(), schema_root_index_list.to_owned()];

    let claims = vec![
        generate_claim(&schema_root_index_list, "123", "root/0/indexlist/0"),
        generate_claim(&schema_root_index_list, "123", "root/0/indexlist/2"),
    ];
    assert!(
        test_create_credential_array(claim_schemas.to_owned(), claims)
            .await
            .is_err()
    );

    let claims = vec![
        generate_claim(&schema_root_index_list, "123", "root/0/indexlist/1"),
        generate_claim(&schema_root_index_list, "123", "root/0/indexlist/0"),
    ];
    assert!(
        test_create_credential_array(claim_schemas.to_owned(), claims)
            .await
            .is_err()
    );

    let claims = vec![
        generate_claim(&schema_root_index_list, "123", "root/0/indexlist/0"),
        generate_claim(&schema_root_index_list, "123", "root/2/indexlist/0"),
    ];
    assert!(
        test_create_credential_array(claim_schemas.to_owned(), claims)
            .await
            .is_err()
    );

    let claims = vec![
        generate_claim(&schema_root_index_list, "123", "root/1/indexlist/0"),
        generate_claim(&schema_root_index_list, "123", "root/0/indexlist/0"),
    ];
    assert!(
        test_create_credential_array(claim_schemas.to_owned(), claims)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn test_create_credential_number_named_claims() {
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
        generate_claim(&schema_00, "zero", "root/0/00"),
        generate_claim(&schema_1, "1first", "root/0/1"),
        generate_claim(&schema_1, "1second", "root/1/1"),
        generate_claim(&schema_2array, "2first", "root/0/2-array/0"),
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
        .holder()
        .unwrap()
        .data
        .issuer
        .identifier
        .as_ref()
        .await
        .unwrap()
        .to_owned();
    identifier_repository
        .expect_get()
        .return_once(|_| Ok(issuer_identifier));
    let mut credential_schema_repository = MockCredentialSchemaRepository::default();
    let credential_schema = credential
        .common()
        .schema
        .as_ref()
        .await
        .unwrap()
        .to_owned();
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
            formats: None,
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
        wallet_attestation: Default::default(),
        layout_properties: None,
        claim_schemas: claim_schemas.into(),
        organisation: organisation.clone().into(),
        allow_suspension: true,
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
            formats: None,
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
                formats: None,
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
    let category_config: DatatypeConfig = yaml_serde::from_str(
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

/// A history repository that reports `outcomes` as the resolved ecosystems of any entity.
fn outcomes_event(outcomes: &EcosystemOutcomes) -> GetListResponse<History, Option<u64>> {
    let values = if outcomes.is_empty() {
        vec![]
    } else {
        vec![History {
            id: Uuid::new_v4().into(),
            created_date: crate::clock::now_utc(),
            action: HistoryAction::EcosystemsResolved,
            name: Default::default(),
            target: None,
            source: HistorySource::Core,
            entity_id: None,
            entity_type: HistoryEntityType::Credential,
            metadata: Some(HistoryMetadata::EcosystemsResolved(outcomes.to_owned())),
            organisation_id: None,
            user: None,
            metadata_blob_id: None,
        }]
    };
    let total_items = values.len() as u64;
    GetListResponse {
        values,
        total_pages: Some(1),
        total_items: Some(total_items),
    }
}

fn history_with_outcomes(outcomes: EcosystemOutcomes) -> MockHistoryRepository {
    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_get_history_list()
        .returning(move |_| Ok(outcomes_event(&outcomes)));
    history_repository
}

fn untrusted_by(ecosystem: &str) -> EcosystemOutcomes {
    let mut outcomes = EcosystemOutcomes::default();
    outcomes.record(
        EcosystemId::from(ecosystem),
        Err(HistoryErrorMetadata {
            error_code: ErrorCode::BR_0477,
            message: "not on the trust list".to_string(),
        }),
    );
    outcomes
}

/// The trust information of a credential in `role`, given the recorded `outcomes`.
async fn trust_information_of(
    role: CredentialRole,
    ecosystem: Option<&str>,
    outcomes: EcosystemOutcomes,
) -> Option<TrustInformation> {
    let mut credential = generic_credential().await;
    credential = CredentialBuilder {
        role,
        ..credential.into()
    }
    .build();
    let mut credential = if role == CredentialRole::Verifier {
        crate::service::test_utilities::verifier_credential(credential).unwrap()
    } else {
        credential
    };
    credential.common_mut().ecosystem = ecosystem.map(EcosystemId::from);

    get_credential_trust_information(
        &credential,
        None,
        &MockEcosystemDirectory::new(),
        &history_with_outcomes(outcomes),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn test_the_issuer_sees_why_the_wallet_provider_was_not_trusted() {
    let outcomes = untrusted_by("EUDI");

    let trust_information = trust_information_of(CredentialRole::Issuer, None, outcomes.to_owned())
        .await
        .expect("the issuer is told about the wallet provider");

    assert_eq!(TrustResolutionResult::Untrusted, trust_information.result);
    assert_eq!(outcomes, trust_information.ecosystem_errors);
}

#[tokio::test]
async fn test_the_issuer_sees_a_trusted_wallet_provider() {
    let mut outcomes = EcosystemOutcomes::default();
    outcomes.record(EcosystemId::from("EUDI"), Ok(()));

    let trust_information =
        trust_information_of(CredentialRole::Issuer, Some("EUDI"), outcomes.to_owned())
            .await
            .expect("an ecosystem was consulted, so there is something to report");

    assert_eq!(TrustResolutionResult::Trusted, trust_information.result);
    assert_eq!(outcomes, trust_information.ecosystem_errors);
}

#[tokio::test]
async fn test_an_issuer_not_using_ecosystems_is_told_nothing() {
    // unchanged behaviour: without an ecosystem in play there is no trust to report
    assert!(
        trust_information_of(CredentialRole::Issuer, None, EcosystemOutcomes::default(),)
            .await
            .is_none()
    );
}

#[tokio::test]
async fn test_the_verifier_sees_why_an_issuer_was_not_trusted() {
    let outcomes = untrusted_by("EUDI");

    let trust_information =
        trust_information_of(CredentialRole::Verifier, None, outcomes.to_owned())
            .await
            .expect("an issuer no ecosystem trusted still says why");

    assert_eq!(TrustResolutionResult::Untrusted, trust_information.result);
    assert_eq!(outcomes, trust_information.ecosystem_errors);
}

#[tokio::test]
async fn test_a_verifier_with_no_ecosystem_in_play_is_told_nothing() {
    assert!(
        trust_information_of(CredentialRole::Verifier, None, EcosystemOutcomes::default(),)
            .await
            .is_none()
    );
}

fn trusted_by(ecosystem: &str) -> EcosystemOutcomes {
    let mut outcomes = EcosystemOutcomes::default();
    outcomes.record(EcosystemId::from(ecosystem), Ok(()));
    outcomes
}

#[tokio::test]
async fn test_the_verifier_sees_the_issuer_by_name() {
    let mut credential =
        crate::service::test_utilities::verifier_credential(generic_credential().await).unwrap();
    credential.common_mut().ecosystem = Some(EcosystemId::from("EUDI"));
    credential.verifier_mut().unwrap().data.issuer.certificate =
        Some(dummy_certificate(Uuid::new_v4().into()).into());

    let trust_information = get_credential_trust_information(
        &credential,
        None,
        &MockEcosystemDirectory::new(),
        &history_with_outcomes(trusted_by("EUDI")),
    )
    .await
    .unwrap()
    .expect("the ecosystem trusted the issuer");

    assert_eq!(Some("certificate".to_string()), trust_information.name);
}

#[tokio::test]
async fn test_the_issuer_sees_the_wallet_by_name() {
    let mut credential = generic_credential().await;
    credential = CredentialBuilder {
        role: CredentialRole::Issuer,
        ..credential.into()
    }
    .build();
    credential.common_mut().ecosystem = Some(EcosystemId::from("EUDI"));

    let trust_information = get_credential_trust_information(
        &credential,
        Some("Procivis One Wallet".to_string()),
        &MockEcosystemDirectory::new(),
        &history_with_outcomes(trusted_by("EUDI")),
    )
    .await
    .unwrap()
    .expect("the ecosystem trusted the wallet provider");

    assert_eq!(
        Some("Procivis One Wallet".to_string()),
        trust_information.name
    );
}

#[tokio::test]
async fn test_a_holder_credential_stays_readable_without_its_trust_detail() {
    let mut credential = generic_credential().await;
    credential = CredentialBuilder {
        role: CredentialRole::Holder,
        ..credential.into()
    }
    .build();
    credential.common_mut().ecosystem = Some(EcosystemId::from("EUDI"));

    let mut ecosystem_provider = MockEcosystemDirectory::new();
    ecosystem_provider.expect_get().returning(|_| {
        let mut ecosystem = MockEcosystem::new();
        ecosystem.expect_issuer_trust_details().returning(|_| {
            Err(EcosystemError::MappingError(
                "Missing access certificate".to_string(),
            ))
        });
        Ok(Arc::new(ecosystem))
    });

    let trust_information = get_credential_trust_information(
        &credential,
        None,
        &ecosystem_provider,
        &history_with_outcomes(EcosystemOutcomes::default()),
    )
    .await
    .unwrap()
    .expect("the ecosystem trusted the issuer");

    assert_eq!(TrustResolutionResult::Trusted, trust_information.result);
    assert_eq!(None, trust_information.name);
}

#[tokio::test]
async fn test_a_batch_item_reads_the_ecosystem_history_of_its_batch() {
    let batch = generic_credential().await;
    let batch_id = batch.common().id;
    let mut item = generic_credential().await;
    item = CredentialBuilder {
        role: CredentialRole::Holder,
        r#type: CredentialType::BatchItem,
        parent: Some(batch.into()),
        ..item.into()
    }
    .build();
    item.common_mut().ecosystem = Some(EcosystemId::from("EUDI"));

    let mut outcomes = untrusted_by("LITHUANIA_SANDBOX");
    outcomes.record(EcosystemId::from("EUDI"), Ok(()));

    let returned = outcomes.to_owned();
    let mut history_repository = MockHistoryRepository::new();
    history_repository
        .expect_get_history_list()
        .withf(move |query| match &query.filtering {
            Some(ListFilterCondition::And(conditions)) => conditions.iter().any(|condition| {
                matches!(
                    condition,
                    ListFilterCondition::Value(HistoryFilterValue::EntityIds(ids))
                        if *ids == vec![EntityId::from(batch_id)]
                )
            }),
            _ => false,
        })
        .times(1)
        .returning(move |_| Ok(outcomes_event(&returned)));

    let mut ecosystem_provider = MockEcosystemDirectory::new();
    ecosystem_provider.expect_get().returning(move |_| {
        let mut ecosystem = MockEcosystem::new();
        ecosystem
            .expect_issuer_trust_details()
            .withf(move |credential_id| *credential_id == batch_id)
            .returning(|_| Err(EcosystemError::MappingError("no trust detail".to_string())));
        Ok(Arc::new(ecosystem))
    });

    let trust_information =
        get_credential_trust_information(&item, None, &ecosystem_provider, &history_repository)
            .await
            .unwrap()
            .expect("the ecosystem trusted the issuer");

    assert_eq!(TrustResolutionResult::Trusted, trust_information.result);
    assert_eq!(outcomes, trust_information.ecosystem_errors);
}
