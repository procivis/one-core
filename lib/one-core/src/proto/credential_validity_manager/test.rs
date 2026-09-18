use std::collections::HashMap;
use std::ops::{Add, Sub};
use std::sync::{Arc, LazyLock, Mutex};

use mockall::Sequence;
use mockall::predicate::{always, eq};
use rstest::rstest;
use shared_types::{CredentialId, RevocationMethodId};
use similar_asserts::assert_eq;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::config::core_config::CoreConfig;
use crate::error::{ErrorCode, ErrorCodeMixin};
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{
    Clearable, Credential, CredentialFilterValue, CredentialRole, CredentialStateEnum,
    CredentialType, GetCredentialList, UpdateCredentialRequest,
};
use crate::model::credential_schema::CredentialSchema;
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::did::{Did, DidType, KeyRole, RelatedKey};
use crate::model::identifier::{Identifier, IdentifierData, IdentifierState};
use crate::model::key::Key;
use crate::proto::credential_validity_manager::dto::ChangeCredentialState;
use crate::proto::credential_validity_manager::{
    CredentialValidityManager, CredentialValidityManagerImpl, Error, validate_transition,
};
use crate::proto::session_provider::test::StaticSessionProvider;
use crate::proto::session_provider::{NoSessionProvider, SessionProvider};
use crate::proto::transaction_manager::NoTransactionManager;
use crate::provider::blob_storage::MockBlobStorage;
use crate::provider::blob_storage::provider::MockBlobStorageProvider;
use crate::provider::credential_formatter::MockCredentialFormatter;
use crate::provider::credential_formatter::model::{
    CredentialStatus, DetailCredential, IdentifierDetails,
};
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::issuance_protocol::provider::MockIssuanceProtocolProvider;
use crate::provider::revocation::MockRevocationMethod;
use crate::provider::revocation::error::RevocationError;
use crate::provider::revocation::model::RevocationState;
use crate::provider::revocation::provider::MockRevocationMethodProvider;
use crate::repository::credential_repository::MockCredentialRepository;
use crate::service::test_utilities::{dummy_blob, dummy_organisation, generic_config};

#[derive(Default)]
struct Repositories {
    pub credential_repository: MockCredentialRepository,
    pub revocation_method_provider: MockRevocationMethodProvider,
    pub formatter_provider: MockCredentialFormatterProvider,
    pub issuance_protocol_provider: MockIssuanceProtocolProvider,
    pub config: CoreConfig,
    pub blob_storage_provider: MockBlobStorageProvider,
    pub session_provider: Option<Arc<dyn SessionProvider>>,
}

fn setup_validity_manager(repositories: Repositories) -> CredentialValidityManagerImpl {
    CredentialValidityManagerImpl::new(
        Arc::new(repositories.credential_repository),
        Arc::new(repositories.issuance_protocol_provider),
        Arc::new(repositories.revocation_method_provider),
        Arc::new(repositories.formatter_provider),
        Arc::new(repositories.blob_storage_provider),
        repositories
            .session_provider
            .unwrap_or(Arc::new(NoSessionProvider)),
        Arc::new(NoTransactionManager),
        Arc::new(repositories.config),
    )
}

#[tokio::test]
async fn test_check_revocation_non_revocable() {
    let mut credential_repository = MockCredentialRepository::default();
    let mut revocation_method_provider = MockRevocationMethodProvider::default();
    let mut formatter_provider = MockCredentialFormatterProvider::default();

    let mut formatter = MockCredentialFormatter::default();

    formatter
        .expect_extract_credentials_unverified()
        .returning(|_, _| {
            Ok(DetailCredential {
                issuance_date: None,
                valid_from: None,
                valid_until: None,
                update_at: None,
                invalid_before: None,
                issuer: IdentifierDetails::Did("did:example:123".parse().unwrap()),
                subject: None,
                claims: Default::default(),
                status: vec![],
            })
        });

    let formatter = Arc::new(formatter);
    formatter_provider
        .expect_get_credential_formatter()
        .returning(move |_| Ok(formatter.clone()));

    revocation_method_provider
        .expect_get_revocation_method()
        .returning(|_| Ok(Arc::new(MockRevocationMethod::default())));

    let credential_blob_id = Uuid::new_v4().into();
    let credential = Credential {
        state: CredentialStateEnum::Accepted,
        credential_blob_id: Some(credential_blob_id),
        ..generic_credential()
    };
    credential_repository.expect_get_credential().returning({
        let credential = credential.clone();
        move |_| Ok(credential.clone())
    });

    let mut blob_storage_provider = MockBlobStorageProvider::new();
    blob_storage_provider
        .expect_get_blob_storage()
        .return_once(move |_| {
            let mut blob_storage = MockBlobStorage::new();
            blob_storage
                .expect_get()
                .once()
                .with(eq(credential_blob_id))
                .return_once(|_| Ok(Some(dummy_blob())));
            Ok(Arc::new(blob_storage))
        });

    let validity_manager = setup_validity_manager(Repositories {
        credential_repository,
        revocation_method_provider,
        formatter_provider,
        blob_storage_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = validity_manager
        .check_holder_credential_validity(credential.id, false)
        .await
        .unwrap();

    assert_eq!(result.credential_id, credential.id);
    assert!(result.success);
    assert_eq!(result.status, CredentialStateEnum::Accepted);
}

#[tokio::test]
async fn test_check_revocation_already_revoked() {
    let mut credential_repository = MockCredentialRepository::default();

    let credential = Credential {
        state: CredentialStateEnum::Revoked,
        suspend_end_date: None,
        ..generic_credential()
    };

    {
        let credential_clone = credential.clone();
        credential_repository
            .expect_get_credential()
            .returning(move |_| Ok(credential_clone.clone()));
    }

    let validity_manager = setup_validity_manager(Repositories {
        credential_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = validity_manager
        .check_holder_credential_validity(credential.id, false)
        .await;
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.credential_id, credential.id);
    assert!(result.success);
    assert_eq!(result.status, CredentialStateEnum::Revoked);
}

#[tokio::test]
async fn test_check_revocation_becoming_revoked() {
    let mut credential_repository = MockCredentialRepository::default();
    let mut revocation_method_provider: MockRevocationMethodProvider =
        MockRevocationMethodProvider::default();
    let mut formatter_provider = MockCredentialFormatterProvider::default();

    let mut formatter = MockCredentialFormatter::default();

    let mut revocation_method = MockRevocationMethod::default();

    formatter
        .expect_extract_credentials_unverified()
        .returning(|_, _| {
            Ok(DetailCredential {
                issuance_date: None,
                valid_from: None,
                valid_until: None,
                update_at: None,
                invalid_before: None,
                issuer: IdentifierDetails::Did("did:example:123".parse().unwrap()),
                subject: None,
                claims: Default::default(),
                status: vec![CredentialStatus {
                    id: Some("did:status:test".parse().unwrap()),
                    r#type: "type".to_string(),
                    status_purpose: Some("purpose".to_string()),
                    additional_fields: HashMap::default(),
                }],
            })
        });

    static REVOCATION_METHOD: LazyLock<RevocationMethodId> = LazyLock::new(|| "mock".into());
    formatter
        .expect_revocation_method_id()
        .returning(|| Some(&*REVOCATION_METHOD));

    revocation_method
        .expect_check_credential_revocation_status()
        .returning(|_, _, _, _| Ok(RevocationState::Revoked));

    let formatter = Arc::new(formatter);
    formatter_provider
        .expect_get_credential_formatter()
        .returning(move |_| Ok(formatter.clone()));

    let revocation_method = Arc::new(revocation_method);
    revocation_method_provider
        .expect_get_revocation_method()
        .with(eq((*REVOCATION_METHOD).clone()))
        .returning(move |_| Ok(revocation_method.clone()));

    let credential_blob_id = Uuid::new_v4().into();
    let credential = Credential {
        state: CredentialStateEnum::Accepted,
        suspend_end_date: None,
        credential_blob_id: Some(credential_blob_id),
        ..generic_credential()
    };
    credential_repository.expect_get_credential().returning({
        let credential = credential.clone();
        move |_| Ok(credential.clone())
    });
    credential_repository
        .expect_update_credential()
        .withf(|_, request| {
            matches!(
                request,
                UpdateCredentialRequest {
                    state: Some(CredentialStateEnum::Revoked),
                    ..
                }
            )
        })
        .returning(|_, _| Ok(()));

    let mut blob_storage_provider = MockBlobStorageProvider::new();
    blob_storage_provider
        .expect_get_blob_storage()
        .return_once(move |_| {
            let mut blob_storage = MockBlobStorage::new();
            blob_storage
                .expect_get()
                .once()
                .with(eq(credential_blob_id))
                .return_once(|_| Ok(Some(dummy_blob())));
            Ok(Arc::new(blob_storage))
        });

    let validity_manager = setup_validity_manager(Repositories {
        credential_repository,
        revocation_method_provider,
        formatter_provider,
        blob_storage_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = validity_manager
        .check_holder_credential_validity(credential.id, false)
        .await
        .unwrap();

    assert_eq!(result.credential_id, credential.id);
    assert!(result.success);
    assert_eq!(result.status, CredentialStateEnum::Revoked);
}

#[tokio::test]
async fn test_check_revocation_batch_parent_becoming_revoked() {
    let mut credential_repository = MockCredentialRepository::default();
    let mut revocation_method_provider: MockRevocationMethodProvider =
        MockRevocationMethodProvider::default();
    let mut formatter_provider = MockCredentialFormatterProvider::default();

    let mut formatter = MockCredentialFormatter::default();

    let mut revocation_method = MockRevocationMethod::default();

    formatter
        .expect_extract_credentials_unverified()
        .returning(|_, _| {
            Ok(DetailCredential {
                issuance_date: None,
                valid_from: None,
                valid_until: None,
                update_at: None,
                invalid_before: None,
                issuer: IdentifierDetails::Did("did:example:123".parse().unwrap()),
                subject: None,
                claims: Default::default(),
                status: vec![CredentialStatus {
                    id: Some("did:status:test".parse().unwrap()),
                    r#type: "type".to_string(),
                    status_purpose: Some("purpose".to_string()),
                    additional_fields: HashMap::default(),
                }],
            })
        });

    static REVOCATION_METHOD: LazyLock<RevocationMethodId> = LazyLock::new(|| "mock".into());
    formatter
        .expect_revocation_method_id()
        .returning(|| Some(&*REVOCATION_METHOD));

    revocation_method
        .expect_check_credential_revocation_status()
        .returning(|_, _, _, _| Ok(RevocationState::Revoked));

    let formatter = Arc::new(formatter);
    formatter_provider
        .expect_get_credential_formatter()
        .returning(move |_| Ok(formatter.clone()));

    let revocation_method = Arc::new(revocation_method);
    revocation_method_provider
        .expect_get_revocation_method()
        .with(eq((*REVOCATION_METHOD).clone()))
        .returning(move |_| Ok(revocation_method.clone()));

    let credential_blob_id = Uuid::new_v4().into();
    let parent_credential_id = Uuid::new_v4().into();
    let item_credential_id: CredentialId = Uuid::new_v4().into();
    let credential = Credential {
        state: CredentialStateEnum::Accepted,
        suspend_end_date: None,
        ..generic_credential()
    };
    credential_repository
        .expect_get_credential()
        .with(eq(parent_credential_id))
        .once()
        .returning({
            let mut credential = credential.clone();
            credential.id = parent_credential_id;
            credential.r#type = CredentialType::BatchParent;
            move |_| Ok(credential.clone())
        });
    credential_repository
        .expect_get_credential()
        .with(eq(item_credential_id))
        .once()
        .returning({
            let mut credential = credential.clone();
            credential.id = item_credential_id;
            credential.r#type = CredentialType::BatchItem;
            credential.credential_blob_id = Some(credential_blob_id);
            move |_| Ok(credential.clone())
        });
    credential_repository
        .expect_get_credential_list()
        .once()
        .return_once({
            let mut credential = credential.clone();
            credential.id = item_credential_id;
            credential.r#type = CredentialType::BatchItem;
            credential.credential_blob_id = Some(credential_blob_id);
            move |_| {
                Ok(GetCredentialList {
                    values: vec![credential],
                    total_pages: Some(1),
                    total_items: Some(1),
                })
            }
        });
    credential_repository
        .expect_update_credential()
        .once()
        .with(eq(parent_credential_id), always())
        .withf(|_, request| {
            matches!(
                request,
                UpdateCredentialRequest {
                    state: Some(CredentialStateEnum::Revoked),
                    ..
                }
            )
        })
        .returning(|_, _| Ok(()));
    credential_repository
        .expect_update_credential()
        .once()
        .with(eq(item_credential_id), always())
        .withf(|_, request| {
            matches!(
                request,
                UpdateCredentialRequest {
                    state: Some(CredentialStateEnum::Revoked),
                    ..
                }
            )
        })
        .returning(|_, _| Ok(()));

    let mut blob_storage_provider = MockBlobStorageProvider::new();
    blob_storage_provider
        .expect_get_blob_storage()
        .return_once(move |_| {
            let mut blob_storage = MockBlobStorage::new();
            blob_storage
                .expect_get()
                .once()
                .with(eq(credential_blob_id))
                .return_once(|_| Ok(Some(dummy_blob())));
            Ok(Arc::new(blob_storage))
        });

    let validity_manager = setup_validity_manager(Repositories {
        credential_repository,
        revocation_method_provider,
        formatter_provider,
        blob_storage_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = validity_manager
        .check_holder_credential_validity(parent_credential_id, false)
        .await
        .unwrap();

    assert_eq!(result.credential_id, parent_credential_id);
    assert!(result.success);
    assert_eq!(result.status, CredentialStateEnum::Revoked);
}

#[tokio::test]
async fn test_check_revocation_batch_parent_expires_when_all_items_and_refresh_token_expired() {
    let mut credential_repository = MockCredentialRepository::default();
    let revocation_method_provider = MockRevocationMethodProvider::default();
    let formatter_provider = MockCredentialFormatterProvider::default();

    let credential_blob_id = Uuid::new_v4().into();
    let parent_credential_id = Uuid::new_v4().into();
    let item_credential_id: CredentialId = Uuid::new_v4().into();

    let refresh_token_expires_at = crate::clock::now_utc() - Duration::hours(1);
    let interaction_data = serde_json::to_vec(&serde_json::json!({
        "issuer_url": "https://issuer.example",
        "credential_endpoint": "https://issuer.example/credential",
        "credential_configuration_id": "test",
        "protocol": "OPENID4VCI_DRAFT13",
        "format": "JWT",
        "refresh_token_expires_at": refresh_token_expires_at
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap(),
    }))
    .unwrap();

    let credential = Credential {
        state: CredentialStateEnum::Accepted,
        suspend_end_date: None,
        interaction: Some(
            crate::model::interaction::Interaction {
                id: Uuid::new_v4().into(),
                created_date: crate::clock::now_utc(),
                last_modified: crate::clock::now_utc(),
                data: Some(interaction_data),
                organisation: dummy_organisation(None).into(),
                interaction_type: crate::model::interaction::InteractionType::Issuance,
                expires_at: None,
                ecosystem: None,
                ecosystem_data: Default::default(),
            }
            .into(),
        ),
        ..generic_credential()
    };
    credential_repository
        .expect_get_credential()
        .with(eq(parent_credential_id))
        .once()
        .returning({
            let mut credential = credential.clone();
            credential.id = parent_credential_id;
            credential.r#type = CredentialType::BatchParent;
            move |_| Ok(credential.clone())
        });
    credential_repository
        .expect_get_credential()
        .with(eq(item_credential_id))
        .once()
        .returning({
            let mut credential = credential.clone();
            credential.id = item_credential_id;
            credential.r#type = CredentialType::BatchItem;
            credential.credential_blob_id = Some(credential_blob_id);
            // the item is itself individually expired
            credential.expires_at = Some(crate::clock::now_utc() - Duration::days(1));
            move |_| Ok(credential.clone())
        });
    credential_repository
        .expect_get_credential_list()
        .once()
        .return_once({
            let mut credential = credential.clone();
            credential.id = item_credential_id;
            credential.r#type = CredentialType::BatchItem;
            credential.credential_blob_id = Some(credential_blob_id);
            move |_| {
                Ok(GetCredentialList {
                    values: vec![credential],
                    total_pages: Some(1),
                    total_items: Some(1),
                })
            }
        });
    // the item transitions to Expired individually (its own business `expires_at` passed), and
    // since the shared refresh token has also expired, the parent transitions to Expired too
    credential_repository
        .expect_update_credential()
        .once()
        .with(eq(item_credential_id), always())
        .withf(|_, request| {
            matches!(
                request,
                UpdateCredentialRequest {
                    state: Some(CredentialStateEnum::Expired),
                    ..
                }
            )
        })
        .returning(|_, _| Ok(()));
    credential_repository
        .expect_update_credential()
        .once()
        .with(eq(parent_credential_id), always())
        .withf(|_, request| {
            matches!(
                request,
                UpdateCredentialRequest {
                    state: Some(CredentialStateEnum::Expired),
                    ..
                }
            )
        })
        .returning(|_, _| Ok(()));

    let validity_manager = setup_validity_manager(Repositories {
        credential_repository,
        revocation_method_provider,
        formatter_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = validity_manager
        .check_holder_credential_validity(parent_credential_id, false)
        .await
        .unwrap();

    assert_eq!(result.credential_id, parent_credential_id);
    assert!(result.success);
    assert_eq!(result.status, CredentialStateEnum::Expired);
}

#[tokio::test]
async fn test_check_revocation_batch_parent_expires_when_refresh_token_expired_even_if_item_valid()
{
    let mut credential_repository = MockCredentialRepository::default();
    let mut revocation_method_provider: MockRevocationMethodProvider =
        MockRevocationMethodProvider::default();
    let mut formatter_provider = MockCredentialFormatterProvider::default();

    let mut formatter = MockCredentialFormatter::default();

    let mut revocation_method = MockRevocationMethod::default();

    formatter
        .expect_extract_credentials_unverified()
        .returning(|_, _| {
            Ok(DetailCredential {
                issuance_date: None,
                valid_from: None,
                valid_until: None,
                update_at: None,
                invalid_before: None,
                issuer: IdentifierDetails::Did("did:example:123".parse().unwrap()),
                subject: None,
                claims: Default::default(),
                status: vec![CredentialStatus {
                    id: Some("did:status:test".parse().unwrap()),
                    r#type: "type".to_string(),
                    status_purpose: Some("purpose".to_string()),
                    additional_fields: HashMap::default(),
                }],
            })
        });

    static REVOCATION_METHOD: LazyLock<RevocationMethodId> = LazyLock::new(|| "mock".into());
    formatter
        .expect_revocation_method_id()
        .returning(|| Some(&*REVOCATION_METHOD));

    // the item itself is still perfectly valid from a revocation-status point of view
    revocation_method
        .expect_check_credential_revocation_status()
        .returning(|_, _, _, _| Ok(RevocationState::Valid));

    let formatter = Arc::new(formatter);
    formatter_provider
        .expect_get_credential_formatter()
        .returning(move |_| Ok(formatter.clone()));

    let revocation_method = Arc::new(revocation_method);
    revocation_method_provider
        .expect_get_revocation_method()
        .with(eq((*REVOCATION_METHOD).clone()))
        .returning(move |_| Ok(revocation_method.clone()));

    let credential_blob_id = Uuid::new_v4().into();
    let parent_credential_id = Uuid::new_v4().into();
    let item_credential_id: CredentialId = Uuid::new_v4().into();

    let refresh_token_expires_at = crate::clock::now_utc() - Duration::hours(1);
    let interaction_data = serde_json::to_vec(&serde_json::json!({
        "issuer_url": "https://issuer.example",
        "credential_endpoint": "https://issuer.example/credential",
        "credential_configuration_id": "test",
        "protocol": "OPENID4VCI_DRAFT13",
        "format": "JWT",
        "refresh_token_expires_at": refresh_token_expires_at
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap(),
    }))
    .unwrap();

    let credential = Credential {
        state: CredentialStateEnum::Accepted,
        suspend_end_date: None,
        interaction: Some(
            crate::model::interaction::Interaction {
                id: Uuid::new_v4().into(),
                created_date: crate::clock::now_utc(),
                last_modified: crate::clock::now_utc(),
                data: Some(interaction_data),
                organisation: dummy_organisation(None).into(),
                interaction_type: crate::model::interaction::InteractionType::Issuance,
                expires_at: None,
                ecosystem: None,
                ecosystem_data: Default::default(),
            }
            .into(),
        ),
        ..generic_credential()
    };
    credential_repository
        .expect_get_credential()
        .with(eq(parent_credential_id))
        .once()
        .returning({
            let mut credential = credential.clone();
            credential.id = parent_credential_id;
            credential.r#type = CredentialType::BatchParent;
            move |_| Ok(credential.clone())
        });
    credential_repository
        .expect_get_credential()
        .with(eq(item_credential_id))
        .once()
        .returning({
            let mut credential = credential.clone();
            credential.id = item_credential_id;
            credential.r#type = CredentialType::BatchItem;
            credential.credential_blob_id = Some(credential_blob_id);
            move |_| Ok(credential.clone())
        });
    credential_repository
        .expect_get_credential_list()
        .once()
        .return_once({
            let mut credential = credential.clone();
            credential.id = item_credential_id;
            credential.r#type = CredentialType::BatchItem;
            credential.credential_blob_id = Some(credential_blob_id);
            move |_| {
                Ok(GetCredentialList {
                    values: vec![credential],
                    total_pages: Some(1),
                    total_items: Some(1),
                })
            }
        });
    // the item stays Accepted (its own revocation status is Valid), but the parent still
    // transitions to Expired: the shared refresh token has expired, and that alone is enough
    // to expire the batch "sooner", regardless of any individual item's validity
    credential_repository
        .expect_update_credential()
        .once()
        .with(eq(parent_credential_id), always())
        .withf(|_, request| {
            matches!(
                request,
                UpdateCredentialRequest {
                    state: Some(CredentialStateEnum::Expired),
                    ..
                }
            )
        })
        .returning(|_, _| Ok(()));

    let mut blob_storage_provider = MockBlobStorageProvider::new();
    blob_storage_provider
        .expect_get_blob_storage()
        .return_once(move |_| {
            let mut blob_storage = MockBlobStorage::new();
            blob_storage
                .expect_get()
                .once()
                .with(eq(credential_blob_id))
                .return_once(|_| Ok(Some(dummy_blob())));
            Ok(Arc::new(blob_storage))
        });

    let validity_manager = setup_validity_manager(Repositories {
        credential_repository,
        revocation_method_provider,
        formatter_provider,
        blob_storage_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = validity_manager
        .check_holder_credential_validity(parent_credential_id, false)
        .await
        .unwrap();

    assert_eq!(result.credential_id, parent_credential_id);
    assert!(result.success);
    assert_eq!(result.status, CredentialStateEnum::Expired);
}

#[tokio::test]
async fn test_check_revocation_batch_parent_expires_when_refresh_token_expired_with_minimal_interaction_data()
 {
    let mut credential_repository = MockCredentialRepository::default();
    let mut revocation_method_provider: MockRevocationMethodProvider =
        MockRevocationMethodProvider::default();
    let mut formatter_provider = MockCredentialFormatterProvider::default();

    let mut formatter = MockCredentialFormatter::default();

    let mut revocation_method = MockRevocationMethod::default();

    formatter
        .expect_extract_credentials_unverified()
        .returning(|_, _| {
            Ok(DetailCredential {
                issuance_date: None,
                valid_from: None,
                valid_until: None,
                update_at: None,
                invalid_before: None,
                issuer: IdentifierDetails::Did("did:example:123".parse().unwrap()),
                subject: None,
                claims: Default::default(),
                status: vec![CredentialStatus {
                    id: Some("did:status:test".parse().unwrap()),
                    r#type: "type".to_string(),
                    status_purpose: Some("purpose".to_string()),
                    additional_fields: HashMap::default(),
                }],
            })
        });

    static REVOCATION_METHOD: LazyLock<RevocationMethodId> = LazyLock::new(|| "mock".into());
    formatter
        .expect_revocation_method_id()
        .returning(|| Some(&*REVOCATION_METHOD));

    revocation_method
        .expect_check_credential_revocation_status()
        .returning(|_, _, _, _| Ok(RevocationState::Valid));

    let formatter = Arc::new(formatter);
    formatter_provider
        .expect_get_credential_formatter()
        .returning(move |_| Ok(formatter.clone()));

    let revocation_method = Arc::new(revocation_method);
    revocation_method_provider
        .expect_get_revocation_method()
        .with(eq((*REVOCATION_METHOD).clone()))
        .returning(move |_| Ok(revocation_method.clone()));

    let credential_blob_id = Uuid::new_v4().into();
    let parent_credential_id = Uuid::new_v4().into();
    let item_credential_id: CredentialId = Uuid::new_v4().into();

    let refresh_token_expires_at = crate::clock::now_utc() - Duration::hours(1);
    let interaction_data = serde_json::to_vec(&serde_json::json!({
        "refresh_token_expires_at": refresh_token_expires_at
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap(),
    }))
    .unwrap();

    let credential = Credential {
        state: CredentialStateEnum::Accepted,
        suspend_end_date: None,
        interaction: Some(
            crate::model::interaction::Interaction {
                id: Uuid::new_v4().into(),
                created_date: crate::clock::now_utc(),
                last_modified: crate::clock::now_utc(),
                data: Some(interaction_data),
                organisation: dummy_organisation(None).into(),
                interaction_type: crate::model::interaction::InteractionType::Issuance,
                expires_at: None,
                ecosystem: None,
                ecosystem_data: Default::default(),
            }
            .into(),
        ),
        ..generic_credential()
    };
    credential_repository
        .expect_get_credential()
        .with(eq(parent_credential_id))
        .once()
        .returning({
            let mut credential = credential.clone();
            credential.id = parent_credential_id;
            credential.r#type = CredentialType::BatchParent;
            move |_| Ok(credential.clone())
        });
    credential_repository
        .expect_get_credential()
        .with(eq(item_credential_id))
        .once()
        .returning({
            let mut credential = credential.clone();
            credential.id = item_credential_id;
            credential.r#type = CredentialType::BatchItem;
            credential.credential_blob_id = Some(credential_blob_id);
            move |_| Ok(credential.clone())
        });
    credential_repository
        .expect_get_credential_list()
        .once()
        .return_once({
            let mut credential = credential.clone();
            credential.id = item_credential_id;
            credential.r#type = CredentialType::BatchItem;
            credential.credential_blob_id = Some(credential_blob_id);
            move |_| {
                Ok(GetCredentialList {
                    values: vec![credential],
                    total_pages: Some(1),
                    total_items: Some(1),
                })
            }
        });
    credential_repository
        .expect_update_credential()
        .once()
        .with(eq(parent_credential_id), always())
        .withf(|_, request| {
            matches!(
                request,
                UpdateCredentialRequest {
                    state: Some(CredentialStateEnum::Expired),
                    ..
                }
            )
        })
        .returning(|_, _| Ok(()));

    let mut blob_storage_provider = MockBlobStorageProvider::new();
    blob_storage_provider
        .expect_get_blob_storage()
        .return_once(move |_| {
            let mut blob_storage = MockBlobStorage::new();
            blob_storage
                .expect_get()
                .once()
                .with(eq(credential_blob_id))
                .return_once(|_| Ok(Some(dummy_blob())));
            Ok(Arc::new(blob_storage))
        });

    let validity_manager = setup_validity_manager(Repositories {
        credential_repository,
        revocation_method_provider,
        formatter_provider,
        blob_storage_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = validity_manager
        .check_holder_credential_validity(parent_credential_id, false)
        .await
        .unwrap();

    assert_eq!(result.credential_id, parent_credential_id);
    assert!(result.success);
    assert_eq!(result.status, CredentialStateEnum::Expired);
}

#[tokio::test]
async fn test_check_revocation_batch_parent_stays_valid_when_refresh_token_and_expires_at_both_ok()
{
    let mut credential_repository = MockCredentialRepository::default();
    let mut revocation_method_provider: MockRevocationMethodProvider =
        MockRevocationMethodProvider::default();
    let mut formatter_provider = MockCredentialFormatterProvider::default();

    let mut formatter = MockCredentialFormatter::default();

    let mut revocation_method = MockRevocationMethod::default();

    formatter
        .expect_extract_credentials_unverified()
        .returning(|_, _| {
            Ok(DetailCredential {
                issuance_date: None,
                valid_from: None,
                valid_until: None,
                update_at: None,
                invalid_before: None,
                issuer: IdentifierDetails::Did("did:example:123".parse().unwrap()),
                subject: None,
                claims: Default::default(),
                status: vec![CredentialStatus {
                    id: Some("did:status:test".parse().unwrap()),
                    r#type: "type".to_string(),
                    status_purpose: Some("purpose".to_string()),
                    additional_fields: HashMap::default(),
                }],
            })
        });

    static REVOCATION_METHOD: LazyLock<RevocationMethodId> = LazyLock::new(|| "mock".into());
    formatter
        .expect_revocation_method_id()
        .returning(|| Some(&*REVOCATION_METHOD));

    revocation_method
        .expect_check_credential_revocation_status()
        .returning(|_, _, _, _| Ok(RevocationState::Valid));

    let formatter = Arc::new(formatter);
    formatter_provider
        .expect_get_credential_formatter()
        .returning(move |_| Ok(formatter.clone()));

    let revocation_method = Arc::new(revocation_method);
    revocation_method_provider
        .expect_get_revocation_method()
        .with(eq((*REVOCATION_METHOD).clone()))
        .returning(move |_| Ok(revocation_method.clone()));

    let credential_blob_id = Uuid::new_v4().into();
    let parent_credential_id = Uuid::new_v4().into();
    let item_credential_id: CredentialId = Uuid::new_v4().into();

    // refresh token is still valid, and won't expire for a while
    let refresh_token_expires_at = crate::clock::now_utc() + Duration::hours(1);
    let interaction_data = serde_json::to_vec(&serde_json::json!({
        "issuer_url": "https://issuer.example",
        "credential_endpoint": "https://issuer.example/credential",
        "credential_configuration_id": "test",
        "protocol": "OPENID4VCI_DRAFT13",
        "format": "JWT",
        "refresh_token_expires_at": refresh_token_expires_at
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap(),
    }))
    .unwrap();

    let credential = Credential {
        state: CredentialStateEnum::Accepted,
        suspend_end_date: None,
        // the parent's own business expiry is also still in the future
        expires_at: Some(crate::clock::now_utc() + Duration::days(30)),
        interaction: Some(
            crate::model::interaction::Interaction {
                id: Uuid::new_v4().into(),
                created_date: crate::clock::now_utc(),
                last_modified: crate::clock::now_utc(),
                data: Some(interaction_data),
                organisation: dummy_organisation(None).into(),
                interaction_type: crate::model::interaction::InteractionType::Issuance,
                expires_at: None,
                ecosystem: None,
                ecosystem_data: Default::default(),
            }
            .into(),
        ),
        ..generic_credential()
    };
    credential_repository
        .expect_get_credential()
        .with(eq(parent_credential_id))
        .once()
        .returning({
            let mut credential = credential.clone();
            credential.id = parent_credential_id;
            credential.r#type = CredentialType::BatchParent;
            move |_| Ok(credential.clone())
        });
    credential_repository
        .expect_get_credential()
        .with(eq(item_credential_id))
        .once()
        .returning({
            let mut credential = credential.clone();
            credential.id = item_credential_id;
            credential.r#type = CredentialType::BatchItem;
            credential.credential_blob_id = Some(credential_blob_id);
            move |_| Ok(credential.clone())
        });
    credential_repository
        .expect_get_credential_list()
        .once()
        .return_once({
            let mut credential = credential.clone();
            credential.id = item_credential_id;
            credential.r#type = CredentialType::BatchItem;
            credential.credential_blob_id = Some(credential_blob_id);
            move |_| {
                Ok(GetCredentialList {
                    values: vec![credential],
                    total_pages: Some(1),
                    total_items: Some(1),
                })
            }
        });
    // neither the item nor the parent need updating: nothing has expired
    credential_repository.expect_update_credential().never();

    let mut blob_storage_provider = MockBlobStorageProvider::new();
    blob_storage_provider
        .expect_get_blob_storage()
        .return_once(move |_| {
            let mut blob_storage = MockBlobStorage::new();
            blob_storage
                .expect_get()
                .once()
                .with(eq(credential_blob_id))
                .return_once(|_| Ok(Some(dummy_blob())));
            Ok(Arc::new(blob_storage))
        });

    let validity_manager = setup_validity_manager(Repositories {
        credential_repository,
        revocation_method_provider,
        formatter_provider,
        blob_storage_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = validity_manager
        .check_holder_credential_validity(parent_credential_id, false)
        .await
        .unwrap();

    assert_eq!(result.credential_id, parent_credential_id);
    assert!(result.success);
    assert_eq!(result.status, CredentialStateEnum::Accepted);
}

#[tokio::test]
async fn test_check_revocation_batch_item_becoming_revoked() {
    let mut credential_repository = MockCredentialRepository::default();
    let mut revocation_method_provider: MockRevocationMethodProvider =
        MockRevocationMethodProvider::default();
    let mut formatter_provider = MockCredentialFormatterProvider::default();

    let mut formatter = MockCredentialFormatter::default();

    let mut revocation_method = MockRevocationMethod::default();

    formatter
        .expect_extract_credentials_unverified()
        .returning(|_, _| {
            Ok(DetailCredential {
                issuance_date: None,
                valid_from: None,
                valid_until: None,
                update_at: None,
                invalid_before: None,
                issuer: IdentifierDetails::Did("did:example:123".parse().unwrap()),
                subject: None,
                claims: Default::default(),
                status: vec![CredentialStatus {
                    id: Some("did:status:test".parse().unwrap()),
                    r#type: "type".to_string(),
                    status_purpose: Some("purpose".to_string()),
                    additional_fields: HashMap::default(),
                }],
            })
        });

    static REVOCATION_METHOD: LazyLock<RevocationMethodId> = LazyLock::new(|| "mock".into());
    formatter
        .expect_revocation_method_id()
        .returning(|| Some(&*REVOCATION_METHOD));

    revocation_method
        .expect_check_credential_revocation_status()
        .returning(|_, _, _, _| Ok(RevocationState::Revoked));

    let formatter = Arc::new(formatter);
    formatter_provider
        .expect_get_credential_formatter()
        .returning(move |_| Ok(formatter.clone()));

    let revocation_method = Arc::new(revocation_method);
    revocation_method_provider
        .expect_get_revocation_method()
        .with(eq((*REVOCATION_METHOD).clone()))
        .returning(move |_| Ok(revocation_method.clone()));

    let credential_blob_id = Uuid::new_v4().into();
    let parent_credential_id = Uuid::new_v4().into();
    let item_credential_id = Uuid::new_v4().into();
    let credential = Credential {
        state: CredentialStateEnum::Accepted,
        suspend_end_date: None,
        ..generic_credential()
    };

    let item_credential = Credential {
        id: item_credential_id,
        r#type: CredentialType::BatchItem,
        credential_blob_id: Some(credential_blob_id),
        parent: Some(
            Credential {
                id: parent_credential_id,
                r#type: CredentialType::BatchParent,
                ..credential.clone()
            }
            .into(),
        ),
        ..credential
    };

    let mut seq = Sequence::new();
    credential_repository
        .expect_get_credential()
        .with(eq(item_credential_id))
        .once()
        .returning({
            let item_credential = item_credential.clone();
            move |_| Ok(item_credential.clone())
        })
        .in_sequence(&mut seq);
    credential_repository
        .expect_update_credential()
        .once()
        .with(eq(item_credential_id), always())
        .withf(|_, request| {
            matches!(
                request,
                UpdateCredentialRequest {
                    state: Some(CredentialStateEnum::Revoked),
                    ..
                }
            )
        })
        .returning(|_, _| Ok(()))
        .in_sequence(&mut seq);
    credential_repository
        .expect_get_credential_list()
        .once()
        .return_once({
            let mut item_credential = item_credential.clone();
            item_credential.state = CredentialStateEnum::Revoked;
            move |_| {
                Ok(GetCredentialList {
                    values: vec![item_credential],
                    total_pages: Some(1),
                    total_items: Some(1),
                })
            }
        })
        .in_sequence(&mut seq);
    credential_repository
        .expect_update_credential()
        .once()
        .with(eq(parent_credential_id), always())
        .withf(|_, request| {
            matches!(
                request,
                UpdateCredentialRequest {
                    state: Some(CredentialStateEnum::Revoked),
                    ..
                }
            )
        })
        .returning(|_, _| Ok(()))
        .in_sequence(&mut seq);

    let mut blob_storage_provider = MockBlobStorageProvider::new();
    blob_storage_provider
        .expect_get_blob_storage()
        .return_once(move |_| {
            let mut blob_storage = MockBlobStorage::new();
            blob_storage
                .expect_get()
                .once()
                .with(eq(credential_blob_id))
                .return_once(|_| Ok(Some(dummy_blob())));
            Ok(Arc::new(blob_storage))
        });

    let validity_manager = setup_validity_manager(Repositories {
        credential_repository,
        revocation_method_provider,
        formatter_provider,
        blob_storage_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = validity_manager
        .check_holder_credential_validity(item_credential_id, false)
        .await
        .unwrap();

    assert_eq!(result.credential_id, item_credential_id);
    assert!(result.success);
    assert_eq!(result.status, CredentialStateEnum::Revoked);
}

#[tokio::test]
async fn test_check_revocation_invalid_role() {
    let credential_issuer_role = Credential {
        role: CredentialRole::Issuer,
        ..generic_credential()
    };

    let credential_verifier_role = Credential {
        role: CredentialRole::Verifier,
        ..generic_credential()
    };

    let issuer_credential_id = credential_issuer_role.id;
    let verifier_credential_id = credential_verifier_role.id;

    let mut credential_repository = MockCredentialRepository::default();

    credential_repository
        .expect_get_credential()
        .with(eq(credential_issuer_role.id))
        .returning(move |_| Ok(credential_issuer_role.clone()));

    credential_repository
        .expect_get_credential()
        .with(eq(credential_verifier_role.id))
        .returning(move |_| Ok(credential_verifier_role.clone()));

    let validity_manager = setup_validity_manager(Repositories {
        credential_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let issuer_revocation_check_resp = validity_manager
        .check_holder_credential_validity(issuer_credential_id, false)
        .await;

    let verifier_revocation_check_resp = validity_manager
        .check_holder_credential_validity(verifier_credential_id, false)
        .await;

    assert!(issuer_revocation_check_resp.is_err());
    assert!(matches!(
        issuer_revocation_check_resp.unwrap_err(),
        Error::InvalidCredentialRole { .. }
    ));

    assert!(verifier_revocation_check_resp.is_err());
    assert!(matches!(
        verifier_revocation_check_resp.unwrap_err(),
        Error::InvalidCredentialRole { .. }
    ));
}

#[tokio::test]
async fn test_check_revocation_invalid_state() {
    let mut credential_repository = MockCredentialRepository::default();

    let credential = generic_credential();
    {
        let credential_clone = credential.clone();
        credential_repository
            .expect_get_credential()
            .returning(move |_| Ok(credential_clone.clone()));
    }

    let validity_manager = setup_validity_manager(Repositories {
        credential_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = validity_manager
        .check_holder_credential_validity(credential.id, false)
        .await;
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result.credential_id, credential.id);
    assert!(!result.success);
    assert_eq!(result.status, CredentialStateEnum::Created);
}

#[tokio::test]
async fn test_revoke_credential_success_with_accepted_credential() {
    let mut credential = generic_credential();
    credential.role = CredentialRole::Issuer;
    credential.state = CredentialStateEnum::Accepted;

    let mut credential_repository = MockCredentialRepository::default();
    let clone = credential.clone();
    credential_repository
        .expect_get_credential()
        .once()
        .with(eq(clone.id))
        .returning(move |_| Ok(clone.clone()));

    let mut revocation_method = MockRevocationMethod::default();
    revocation_method
        .expect_mark_credential_as()
        .once()
        .with(always(), eq(RevocationState::Revoked))
        .return_once(|_, _| Ok(()));
    revocation_method
        .expect_get_status_type()
        .return_once(|| "mock".to_string());

    credential_repository
        .expect_update_credential()
        .once()
        .returning(move |_, request| {
            assert_eq!(CredentialStateEnum::Revoked, request.state.unwrap());
            Ok(())
        });

    let mut formatter = MockCredentialFormatter::default();
    static REVOCATION_METHOD: LazyLock<RevocationMethodId> = LazyLock::new(|| "mock".into());
    formatter
        .expect_revocation_method_id()
        .returning(|| Some(&*REVOCATION_METHOD));

    let mut revocation_method_provider = MockRevocationMethodProvider::default();
    let revocation_method = Arc::new(revocation_method);
    revocation_method_provider
        .expect_get_revocation_method()
        .with(eq((*REVOCATION_METHOD).clone()))
        .times(1)
        .returning(move |_| Ok(revocation_method.clone()));

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .return_once(move |_| Ok(Arc::new(formatter)));

    let validity_manager = setup_validity_manager(Repositories {
        credential_repository,
        revocation_method_provider,
        formatter_provider,
        config: generic_config().core,
        ..Default::default()
    });

    validity_manager
        .change_credential_state(&credential.id, ChangeCredentialState::Revoked)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_revoke_credential_success_with_suspended_credential() {
    let mut credential = generic_credential();
    credential.role = CredentialRole::Issuer;
    credential.state = CredentialStateEnum::Suspended;

    let mut credential_repository = MockCredentialRepository::default();

    let mut revocation_method = MockRevocationMethod::default();
    revocation_method
        .expect_mark_credential_as()
        .once()
        .with(always(), eq(RevocationState::Revoked))
        .return_once(|_, _| Ok(()));
    revocation_method
        .expect_get_status_type()
        .return_once(|| "mock".to_string());

    credential_repository
        .expect_update_credential()
        .once()
        .returning(move |_, request| {
            assert_eq!(CredentialStateEnum::Revoked, request.state.unwrap());
            Ok(())
        });

    let clone = credential.clone();
    credential_repository
        .expect_get_credential()
        .once()
        .with(eq(clone.id))
        .returning(move |_| Ok(clone.clone()));

    let mut formatter = MockCredentialFormatter::default();
    static REVOCATION_METHOD: LazyLock<RevocationMethodId> = LazyLock::new(|| "mock".into());
    formatter
        .expect_revocation_method_id()
        .returning(|| Some(&*REVOCATION_METHOD));

    let mut revocation_method_provider = MockRevocationMethodProvider::default();
    let revocation_method = Arc::new(revocation_method);
    revocation_method_provider
        .expect_get_revocation_method()
        .with(eq((*REVOCATION_METHOD).clone()))
        .times(1)
        .returning(move |_| Ok(revocation_method.clone()));

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .return_once(move |_| Ok(Arc::new(formatter)));

    let validity_manager = setup_validity_manager(Repositories {
        credential_repository,
        revocation_method_provider,
        formatter_provider,
        config: generic_config().core,
        ..Default::default()
    });

    validity_manager
        .change_credential_state(&credential.id, ChangeCredentialState::Revoked)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_suspend_credential_failed_cannot_suspend_revoked_credential() {
    let mut credential = generic_credential();
    credential.role = CredentialRole::Issuer;
    credential.state = CredentialStateEnum::Revoked;

    let mut credential_repository = MockCredentialRepository::default();
    {
        let clone = credential.clone();
        credential_repository
            .expect_get_credential()
            .times(1)
            .with(eq(clone.id))
            .returning(move |_| Ok(clone.clone()));
    }
    let validity_manager = setup_validity_manager(Repositories {
        credential_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = validity_manager
        .change_credential_state(
            &credential.id,
            ChangeCredentialState::Suspended {
                suspend_end_date: None,
            },
        )
        .await
        .unwrap_err();

    assert!(matches!(
        result,
        Error::InvalidCredentialStateTransition { .. }
    ));
}

#[tokio::test]
async fn test_suspend_credential_success() {
    let now = crate::clock::now_utc();

    let mut credential = generic_credential();
    credential.role = CredentialRole::Issuer;
    credential.state = CredentialStateEnum::Accepted;

    let suspend_end_date = now.add(Duration::days(1));

    let mut credential_repository = MockCredentialRepository::default();
    {
        let clone = credential.clone();
        credential_repository
            .expect_get_credential()
            .once()
            .with(eq(clone.id))
            .returning(move |_| Ok(clone.clone()));
    }

    let mut revocation_method = MockRevocationMethod::default();
    revocation_method
        .expect_mark_credential_as()
        .once()
        .with(
            always(),
            eq(RevocationState::Suspended {
                suspend_end_date: Some(suspend_end_date),
            }),
        )
        .return_once(|_, _| Ok(()));
    revocation_method
        .expect_get_status_type()
        .return_once(|| "mock".to_string());

    credential_repository
        .expect_update_credential()
        .once()
        .returning(move |_, request| {
            assert_eq!(CredentialStateEnum::Suspended, request.state.unwrap());
            Ok(())
        });

    let mut formatter = MockCredentialFormatter::default();
    static REVOCATION_METHOD: LazyLock<RevocationMethodId> = LazyLock::new(|| "mock".into());
    formatter
        .expect_revocation_method_id()
        .returning(|| Some(&*REVOCATION_METHOD));

    let mut revocation_method_provider = MockRevocationMethodProvider::default();
    let revocation_method = Arc::new(revocation_method);
    revocation_method_provider
        .expect_get_revocation_method()
        .with(eq((*REVOCATION_METHOD).clone()))
        .times(1)
        .returning(move |_| Ok(revocation_method.clone()));

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .return_once(move |_| Ok(Arc::new(formatter)));

    let validity_manager = setup_validity_manager(Repositories {
        credential_repository,
        revocation_method_provider,
        formatter_provider,
        config: generic_config().core,
        ..Default::default()
    });

    validity_manager
        .change_credential_state(
            &credential.id,
            ChangeCredentialState::Suspended {
                suspend_end_date: Some(suspend_end_date),
            },
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn test_reactivate_credential_success() {
    let mut credential = generic_credential();
    credential.role = CredentialRole::Issuer;
    credential.state = CredentialStateEnum::Suspended;

    let mut credential_repository = MockCredentialRepository::default();
    let cred_clone = credential.clone();
    credential_repository
        .expect_get_credential()
        .once()
        .returning(move |_| Ok(cred_clone.clone()));

    let mut formatter = MockCredentialFormatter::default();
    static REVOCATION_METHOD: LazyLock<RevocationMethodId> = LazyLock::new(|| "mock".into());
    formatter
        .expect_revocation_method_id()
        .returning(|| Some(&*REVOCATION_METHOD));

    let mut revocation_method = MockRevocationMethod::default();
    revocation_method
        .expect_mark_credential_as()
        .once()
        .with(always(), eq(RevocationState::Valid))
        .return_once(|_, _| Ok(()));
    revocation_method
        .expect_get_status_type()
        .return_once(|| "mock".to_string());

    credential_repository
        .expect_update_credential()
        .once()
        .withf(|_, request| {
            assert_eq!(CredentialStateEnum::Accepted, request.state.unwrap());
            true
        })
        .returning(|_, _| Ok(()));

    let mut revocation_method_provider = MockRevocationMethodProvider::default();
    let revocation_method = Arc::new(revocation_method);
    revocation_method_provider
        .expect_get_revocation_method()
        .with(eq((*REVOCATION_METHOD).clone()))
        .times(1)
        .returning(move |_| Ok(revocation_method.clone()));

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .return_once(move |_| Ok(Arc::new(formatter)));

    let validity_manager = setup_validity_manager(Repositories {
        credential_repository,
        revocation_method_provider,
        formatter_provider,
        config: generic_config().core,
        ..Default::default()
    });

    validity_manager
        .change_credential_state(&credential.id, ChangeCredentialState::Accepted)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_reactivate_credential_failed_cannot_reactivate_revoked_credential() {
    let mut credential = generic_credential();
    credential.role = CredentialRole::Issuer;
    credential.state = CredentialStateEnum::Revoked;

    let mut credential_repository = MockCredentialRepository::default();
    let clone = credential.clone();
    credential_repository
        .expect_get_credential()
        .times(1)
        .with(eq(clone.id))
        .returning(move |_| Ok(clone.clone()));

    let validity_manager = setup_validity_manager(Repositories {
        credential_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = validity_manager
        .change_credential_state(&credential.id, ChangeCredentialState::Accepted)
        .await
        .unwrap_err();

    assert!(matches!(
        result,
        Error::InvalidCredentialStateTransition { .. }
    ));
}

#[tokio::test]
async fn test_revoke_credential_invalid_role() {
    let mut credential = generic_credential();
    credential.role = CredentialRole::Holder;
    credential.state = CredentialStateEnum::Accepted;

    let mut credential_repository = MockCredentialRepository::default();
    let clone = credential.clone();
    credential_repository
        .expect_get_credential()
        .times(1)
        .with(eq(clone.id))
        .returning(move |_| Ok(clone.clone()));

    let validity_manager = setup_validity_manager(Repositories {
        credential_repository,
        config: generic_config().core,
        ..Default::default()
    });

    let result = validity_manager
        .change_credential_state(&credential.id, ChangeCredentialState::Revoked)
        .await
        .unwrap_err();

    assert!(matches!(result, Error::InvalidCredentialRole { .. }));
}

#[tokio::test]
async fn test_revoke_credential_batch_parent() {
    let mut parent_credential = generic_credential();
    parent_credential.role = CredentialRole::Issuer;
    parent_credential.state = CredentialStateEnum::Accepted;
    parent_credential.r#type = CredentialType::BatchParent;

    let mut child_credential = generic_credential();
    child_credential.role = CredentialRole::Issuer;
    child_credential.state = CredentialStateEnum::Accepted;
    child_credential.r#type = CredentialType::BatchItem;
    child_credential.parent = Some(parent_credential.clone().into());

    let mut credential_repository = MockCredentialRepository::default();
    {
        let clone = parent_credential.clone();
        credential_repository
            .expect_get_credential()
            .once()
            .with(eq(parent_credential.id))
            .returning(move |_| Ok(clone.clone()));

        let clone = child_credential.clone();
        let _parent_credential_id = parent_credential.id;
        credential_repository
            .expect_get_credential_list()
            .once()
            .returning(move |query| {
                assert!(query.filtering.unwrap().contains(&|fv| matches!(
                    fv,
                    CredentialFilterValue::ParentCredential(_parent_credential_id)
                )));
                Ok(GetCredentialList {
                    total_items: Some(1),
                    total_pages: Some(1),
                    values: vec![clone.clone()],
                })
            });

        credential_repository
            .expect_update_credential()
            .once()
            .with(eq(parent_credential.id), always())
            .returning(move |_, request| {
                assert_eq!(CredentialStateEnum::Revoked, request.state.unwrap());
                Ok(())
            });
        credential_repository
            .expect_update_credential()
            .once()
            .with(eq(child_credential.id), always())
            .returning(move |_, request| {
                assert_eq!(CredentialStateEnum::Revoked, request.state.unwrap());
                Ok(())
            });
    }

    let mut revocation_method = MockRevocationMethod::default();
    revocation_method
        .expect_mark_credential_as()
        .once()
        .with(always(), eq(RevocationState::Revoked))
        .return_once({
            let child_credential_id = child_credential.id;
            move |credential, _| {
                assert_eq!(credential.id, child_credential_id);
                Ok(())
            }
        });

    let mut formatter = MockCredentialFormatter::default();
    static REVOCATION_METHOD: LazyLock<RevocationMethodId> = LazyLock::new(|| "mock".into());
    formatter
        .expect_revocation_method_id()
        .returning(|| Some(&*REVOCATION_METHOD));

    let mut revocation_method_provider = MockRevocationMethodProvider::default();
    let revocation_method = Arc::new(revocation_method);
    revocation_method_provider
        .expect_get_revocation_method()
        .with(eq((*REVOCATION_METHOD).clone()))
        .once()
        .returning(move |_| Ok(revocation_method.clone()));

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .return_once(move |_| Ok(Arc::new(formatter)));

    let validity_manager = setup_validity_manager(Repositories {
        credential_repository,
        revocation_method_provider,
        formatter_provider,
        config: generic_config().core,
        ..Default::default()
    });

    validity_manager
        .change_credential_state(&parent_credential.id, ChangeCredentialState::Revoked)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_revoke_credential_batch_item() {
    let mut parent_credential = generic_credential();
    parent_credential.role = CredentialRole::Issuer;
    parent_credential.state = CredentialStateEnum::Accepted;
    parent_credential.r#type = CredentialType::BatchParent;

    let mut child_credential = generic_credential();
    child_credential.role = CredentialRole::Issuer;
    child_credential.state = CredentialStateEnum::Accepted;
    child_credential.r#type = CredentialType::BatchItem;
    child_credential.parent = Some(parent_credential.clone().into());

    let mut credential_repository = MockCredentialRepository::default();

    credential_repository
        .expect_get_credential()
        .once()
        .with(eq(child_credential.id))
        .returning({
            let clone = child_credential.clone();
            move |_| Ok(clone.clone())
        });

    let mut seq = Sequence::new();
    credential_repository
        .expect_update_credential()
        .once()
        .with(eq(child_credential.id), always())
        .returning(move |_, request| {
            assert_eq!(CredentialStateEnum::Revoked, request.state.unwrap());
            Ok(())
        })
        .in_sequence(&mut seq);

    credential_repository
        .expect_get_credential_list()
        .once()
        .returning({
            let _parent_credential_id = parent_credential.id;
            let child_credential = Credential {
                state: CredentialStateEnum::Revoked,
                ..child_credential.clone()
            };
            move |query| {
                assert!(query.filtering.unwrap().contains(&|fv| matches!(
                    fv,
                    CredentialFilterValue::ParentCredential(_parent_credential_id)
                )));
                Ok(GetCredentialList {
                    total_items: Some(1),
                    total_pages: Some(1),
                    values: vec![child_credential.clone()],
                })
            }
        })
        .in_sequence(&mut seq);

    credential_repository
        .expect_update_credential()
        .once()
        .with(eq(parent_credential.id), always())
        .returning(move |_, request| {
            assert_eq!(CredentialStateEnum::Revoked, request.state.unwrap());
            Ok(())
        })
        .in_sequence(&mut seq);

    let mut revocation_method = MockRevocationMethod::default();
    revocation_method
        .expect_mark_credential_as()
        .once()
        .with(always(), eq(RevocationState::Revoked))
        .return_once({
            let child_credential_id = child_credential.id;
            move |credential, _| {
                assert_eq!(credential.id, child_credential_id);
                Ok(())
            }
        });

    let mut formatter = MockCredentialFormatter::default();
    static REVOCATION_METHOD: LazyLock<RevocationMethodId> = LazyLock::new(|| "mock".into());
    formatter
        .expect_revocation_method_id()
        .returning(|| Some(&*REVOCATION_METHOD));

    let mut revocation_method_provider = MockRevocationMethodProvider::default();
    let revocation_method = Arc::new(revocation_method);
    revocation_method_provider
        .expect_get_revocation_method()
        .with(eq((*REVOCATION_METHOD).clone()))
        .once()
        .returning(move |_| Ok(revocation_method.clone()));

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .return_once(move |_| Ok(Arc::new(formatter)));

    let validity_manager = setup_validity_manager(Repositories {
        credential_repository,
        revocation_method_provider,
        formatter_provider,
        config: generic_config().core,
        ..Default::default()
    });

    validity_manager
        .change_credential_state(&child_credential.id, ChangeCredentialState::Revoked)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_reactivate_credential_batch_item_with_expiring_parent() {
    reactivate_batch_item_leaves_parent_untouched(CredentialStateEnum::Expiring).await;
}

#[tokio::test]
async fn test_reactivate_credential_batch_item_with_expired_parent() {
    reactivate_batch_item_leaves_parent_untouched(CredentialStateEnum::Expired).await;
}

/// `Expiring`/`Expired` have no revocation equivalent, so the parent is not an aggregation of its
/// items and must be left alone - it must neither fail the mapping nor get overwritten.
async fn reactivate_batch_item_leaves_parent_untouched(parent_state: CredentialStateEnum) {
    let mut parent_credential = generic_credential();
    parent_credential.role = CredentialRole::Issuer;
    parent_credential.state = parent_state;
    parent_credential.r#type = CredentialType::BatchParent;

    let mut child_credential = generic_credential();
    child_credential.role = CredentialRole::Issuer;
    child_credential.state = CredentialStateEnum::Suspended;
    child_credential.suspend_end_date = Some(crate::clock::now_utc().sub(Duration::hours(1)));
    child_credential.r#type = CredentialType::BatchItem;
    child_credential.parent = Some(parent_credential.clone().into());

    let mut credential_repository = MockCredentialRepository::default();

    credential_repository
        .expect_get_credential()
        .once()
        .with(eq(child_credential.id))
        .returning({
            let clone = child_credential.clone();
            move |_| Ok(clone.clone())
        });

    // only the item is updated - no expectation is registered for the parent id, so any attempt
    // to recompute or overwrite the parent's state fails the test
    credential_repository
        .expect_update_credential()
        .once()
        .with(eq(child_credential.id), always())
        .returning(move |_, request| {
            assert_eq!(CredentialStateEnum::Accepted, request.state.unwrap());
            Ok(())
        });

    let mut revocation_method = MockRevocationMethod::default();
    revocation_method
        .expect_mark_credential_as()
        .once()
        .with(always(), eq(RevocationState::Valid))
        .return_once({
            let child_credential_id = child_credential.id;
            move |credential, _| {
                assert_eq!(credential.id, child_credential_id);
                Ok(())
            }
        });

    let mut formatter = MockCredentialFormatter::default();
    static REVOCATION_METHOD: LazyLock<RevocationMethodId> = LazyLock::new(|| "mock".into());
    formatter
        .expect_revocation_method_id()
        .returning(|| Some(&*REVOCATION_METHOD));

    let mut revocation_method_provider = MockRevocationMethodProvider::default();
    let revocation_method = Arc::new(revocation_method);
    revocation_method_provider
        .expect_get_revocation_method()
        .with(eq((*REVOCATION_METHOD).clone()))
        .once()
        .returning(move |_| Ok(revocation_method.clone()));

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .return_once(move |_| Ok(Arc::new(formatter)));

    let validity_manager = setup_validity_manager(Repositories {
        credential_repository,
        revocation_method_provider,
        formatter_provider,
        config: generic_config().core,
        ..Default::default()
    });

    validity_manager
        .change_credential_state(&child_credential.id, ChangeCredentialState::Accepted)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_suspend_multiformat_credential_one_format_unsupported() {
    let mut base_credential = generic_credential();
    base_credential.role = CredentialRole::Issuer;
    base_credential.state = CredentialStateEnum::Accepted;

    let sdjwtvc_format = CredentialSchemaFormat {
        id: Uuid::new_v4().into(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        credential_schema_id: base_credential.schema.id(),
        format: "SD_JWT_VC".into(),
        ecosystem_schema_id: "sdjwtvc".to_owned(),
        claim_mappings: Default::default(),
    };
    let mdoc_format = CredentialSchemaFormat {
        id: Uuid::new_v4().into(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        credential_schema_id: base_credential.schema.id(),
        format: "MDOC".into(),
        ecosystem_schema_id: "mdoc".to_owned(),
        claim_mappings: Default::default(),
    };
    base_credential.schema.as_mut().await.unwrap().formats =
        vec![sdjwtvc_format.clone(), mdoc_format.clone()].into();

    let mut parent_credential = base_credential.clone();
    parent_credential.r#type = CredentialType::BatchParent;

    let mut sdjwtvc_credential = base_credential.clone();
    sdjwtvc_credential.r#type = CredentialType::BatchItem;
    sdjwtvc_credential.parent = Some(parent_credential.clone().into());
    sdjwtvc_credential.format = Some(sdjwtvc_format.clone().into());

    let mut mdoc_credential = base_credential.clone();
    mdoc_credential.r#type = CredentialType::BatchItem;
    mdoc_credential.parent = Some(parent_credential.clone().into());
    mdoc_credential.format = Some(mdoc_format.clone().into());

    let mut credential_repository = MockCredentialRepository::default();

    credential_repository
        .expect_get_credential()
        .once()
        .with(eq(parent_credential.id))
        .returning({
            let clone = parent_credential.clone();
            move |_| Ok(clone.clone())
        });

    credential_repository
        .expect_get_credential_list()
        .once()
        .returning({
            let _parent_credential_id = parent_credential.id;
            let values = vec![sdjwtvc_credential.clone(), mdoc_credential.clone()];
            move |query| {
                assert!(query.filtering.unwrap().contains(&|fv| matches!(
                    fv,
                    CredentialFilterValue::ParentCredential(_parent_credential_id)
                )));
                Ok(GetCredentialList {
                    total_items: Some(2),
                    total_pages: Some(1),
                    values: values.clone(),
                })
            }
        });

    credential_repository
        .expect_update_credential()
        .once()
        .with(eq(parent_credential.id), always())
        .returning(move |_, request| {
            assert_eq!(CredentialStateEnum::Suspended, request.state.unwrap());
            Ok(())
        });
    credential_repository
        .expect_update_credential()
        .once()
        .with(eq(sdjwtvc_credential.id), always())
        .returning(move |_, request| {
            assert_eq!(CredentialStateEnum::Suspended, request.state.unwrap());
            Ok(())
        });

    static REVOCATION_METHOD_WITH_SUSPENSION: LazyLock<RevocationMethodId> =
        LazyLock::new(|| "WITH_SUSPENSION".into());
    let mut revocation_method_with_suspension = MockRevocationMethod::default();
    revocation_method_with_suspension
        .expect_mark_credential_as()
        .once()
        .with(
            always(),
            eq(RevocationState::Suspended {
                suspend_end_date: None,
            }),
        )
        .return_once({
            let credential_id = sdjwtvc_credential.id;
            move |credential, _| {
                assert_eq!(credential.id, credential_id);
                Ok(())
            }
        });
    let revocation_method_with_suspension = Arc::new(revocation_method_with_suspension);

    static REVOCATION_METHOD_WITHOUT_SUSPENSION: LazyLock<RevocationMethodId> =
        LazyLock::new(|| "WITHOUT_SUSPENSION".into());
    let mut revocation_method_without_suspension = MockRevocationMethod::default();
    revocation_method_without_suspension
        .expect_mark_credential_as()
        .once()
        .with(
            always(),
            eq(RevocationState::Suspended {
                suspend_end_date: None,
            }),
        )
        .return_once({
            let credential_id = mdoc_credential.id;
            move |credential, _| {
                assert_eq!(credential.id, credential_id);
                Err(RevocationError::OperationNotSupported("test".to_string()))
            }
        });
    let revocation_method_without_suspension = Arc::new(revocation_method_without_suspension);

    let mut revocation_method_provider = MockRevocationMethodProvider::default();
    revocation_method_provider
        .expect_get_revocation_method()
        .with(eq((*REVOCATION_METHOD_WITH_SUSPENSION).clone()))
        .once()
        .returning(move |_| Ok(revocation_method_with_suspension.clone()));
    revocation_method_provider
        .expect_get_revocation_method()
        .with(eq((*REVOCATION_METHOD_WITHOUT_SUSPENSION).clone()))
        .once()
        .returning(move |_| Ok(revocation_method_without_suspension.clone()));

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .with(eq(sdjwtvc_format.format))
        .return_once(move |_| {
            let mut formatter = MockCredentialFormatter::default();
            formatter
                .expect_revocation_method_id()
                .returning(|| Some(&*REVOCATION_METHOD_WITH_SUSPENSION));
            Ok(Arc::new(formatter))
        });
    formatter_provider
        .expect_get_credential_formatter()
        .once()
        .with(eq(mdoc_format.format))
        .return_once(move |_| {
            let mut formatter = MockCredentialFormatter::default();
            formatter
                .expect_revocation_method_id()
                .returning(|| Some(&*REVOCATION_METHOD_WITHOUT_SUSPENSION));
            Ok(Arc::new(formatter))
        });

    let validity_manager = setup_validity_manager(Repositories {
        credential_repository,
        revocation_method_provider,
        formatter_provider,
        config: generic_config().core,
        ..Default::default()
    });

    validity_manager
        .change_credential_state(
            &parent_credential.id,
            ChangeCredentialState::Suspended {
                suspend_end_date: None,
            },
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn test_suspend_multiformat_credential_all_formats_unsupported() {
    let mut base_credential = generic_credential();
    base_credential.role = CredentialRole::Issuer;
    base_credential.state = CredentialStateEnum::Accepted;

    let sdjwtvc_format = CredentialSchemaFormat {
        id: Uuid::new_v4().into(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        credential_schema_id: base_credential.schema.id(),
        format: "SD_JWT_VC".into(),
        ecosystem_schema_id: "sdjwtvc".to_owned(),
        claim_mappings: Default::default(),
    };
    let mdoc_format = CredentialSchemaFormat {
        id: Uuid::new_v4().into(),
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        credential_schema_id: base_credential.schema.id(),
        format: "MDOC".into(),
        ecosystem_schema_id: "mdoc".to_owned(),
        claim_mappings: Default::default(),
    };
    base_credential.schema.as_mut().await.unwrap().formats =
        vec![sdjwtvc_format.clone(), mdoc_format.clone()].into();

    let mut parent_credential = base_credential.clone();
    parent_credential.r#type = CredentialType::BatchParent;

    let mut sdjwtvc_credential = base_credential.clone();
    sdjwtvc_credential.r#type = CredentialType::BatchItem;
    sdjwtvc_credential.parent = Some(parent_credential.clone().into());
    sdjwtvc_credential.format = Some(sdjwtvc_format.clone().into());

    let mut mdoc_credential = base_credential.clone();
    mdoc_credential.r#type = CredentialType::BatchItem;
    mdoc_credential.parent = Some(parent_credential.clone().into());
    mdoc_credential.format = Some(mdoc_format.clone().into());

    let mut credential_repository = MockCredentialRepository::default();
    credential_repository
        .expect_get_credential()
        .once()
        .with(eq(parent_credential.id))
        .returning({
            let clone = parent_credential.clone();
            move |_| Ok(clone.clone())
        });

    credential_repository
        .expect_get_credential_list()
        .once()
        .returning({
            let _parent_credential_id = parent_credential.id;
            let values = vec![sdjwtvc_credential.clone(), mdoc_credential.clone()];
            move |query| {
                assert!(query.filtering.unwrap().contains(&|fv| matches!(
                    fv,
                    CredentialFilterValue::ParentCredential(_parent_credential_id)
                )));
                Ok(GetCredentialList {
                    total_items: Some(2),
                    total_pages: Some(1),
                    values: values.clone(),
                })
            }
        });

    static REVOCATION_METHOD_WITHOUT_SUSPENSION: LazyLock<RevocationMethodId> =
        LazyLock::new(|| "WITHOUT_SUSPENSION".into());
    let mut revocation_method_without_suspension = MockRevocationMethod::default();
    revocation_method_without_suspension
        .expect_mark_credential_as()
        .times(2)
        .with(
            always(),
            eq(RevocationState::Suspended {
                suspend_end_date: None,
            }),
        )
        .returning(|_, _| Err(RevocationError::OperationNotSupported("test".to_string())));
    let revocation_method_without_suspension = Arc::new(revocation_method_without_suspension);

    let mut revocation_method_provider = MockRevocationMethodProvider::default();
    revocation_method_provider
        .expect_get_revocation_method()
        .with(eq((*REVOCATION_METHOD_WITHOUT_SUSPENSION).clone()))
        .times(2)
        .returning(move |_| Ok(revocation_method_without_suspension.clone()));

    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .times(2)
        .returning(move |_| {
            let mut formatter = MockCredentialFormatter::default();
            formatter
                .expect_revocation_method_id()
                .returning(|| Some(&*REVOCATION_METHOD_WITHOUT_SUSPENSION));
            Ok(Arc::new(formatter))
        });

    let validity_manager = setup_validity_manager(Repositories {
        credential_repository,
        revocation_method_provider,
        formatter_provider,
        config: generic_config().core,
        ..Default::default()
    });

    let result = validity_manager
        .change_credential_state(
            &parent_credential.id,
            ChangeCredentialState::Suspended {
                suspend_end_date: None,
            },
        )
        .await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0098);
}

#[tokio::test]
async fn test_credential_ops_session_org_mismatch() {
    let mut credential_repository = MockCredentialRepository::default();
    credential_repository
        .expect_get_credential()
        .returning(|_| {
            Ok(Credential {
                role: CredentialRole::Issuer,
                ..generic_credential()
            })
        });
    let validity_manager = setup_validity_manager(Repositories {
        credential_repository,
        config: generic_config().core,
        session_provider: Some(Arc::new(StaticSessionProvider::new_random())),
        ..Default::default()
    });

    let result = validity_manager
        .change_credential_state(&Uuid::new_v4().into(), ChangeCredentialState::Accepted)
        .await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);
    let result = validity_manager
        .check_holder_credential_validity(Uuid::new_v4().into(), false)
        .await;
    assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0178);
}

fn generic_credential() -> Credential {
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
    Credential {
        expires_at: None,
        ecosystem: None,
        id: credential_id,
        created_date: now,
        issuance_date: None,
        last_modified: now,
        deleted_at: None,
        consumed_at: None,
        protocol: "OPENID4VCI_DRAFT13".to_string(),
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
        schema: CredentialSchema {
            expiration: None,
            ecosystem: None,
            batch_size: None,
            allow_revocation: true,
            id: credential_schema_id,
            deleted_at: None,
            imported_source_url: "CORE_URL".to_string(),
            created_date: now,
            last_modified: now,
            name: "schema".to_string(),
            wallet_attestation: Default::default(),
            formats: vec![format.clone()].into(),
            claim_schemas: vec![claim_schema].into(),
            organisation: organisation.into(),
            layout_properties: None,
            allow_suspension: true,
            transaction_code: None,
            translations: Default::default(),
            embedded_disclosure_policy: None,
        }
        .into(),
        interaction: None,
        key: None,
        profile: None,
        credential_blob_id: None,
        wallet_key_attestation_blob_id: None,
        wallet_instance_attestation_blob_id: None,
        webhook_url: None,
        parent: None,
        embedded_disclosure_policy: None,
        subscriber_information: None,
        format: Some(format.into()),
    }
}

// ---------------------------------------------------------------------------------------------
// Issuer state changes
// ---------------------------------------------------------------------------------------------

/// Every transition the issuer may perform, as `(current state, target state)` data. A target of
/// `Expiring` is additionally restricted to batch parents.
///
/// Anything not listed here has to be rejected: `test_transition_matrix` walks the full
/// cross-product of states, credential types and targets and asserts exactly that, so the allowed
/// and the forbidden set cannot drift apart.
const ALLOWED_TRANSITIONS: &[(CredentialStateEnum, CredentialStateEnum)] = &[
    // reactivating a suspension, clearing the `Expiring` flag, re-applying `Accepted`
    (
        CredentialStateEnum::Suspended,
        CredentialStateEnum::Accepted,
    ),
    (CredentialStateEnum::Expiring, CredentialStateEnum::Accepted),
    (CredentialStateEnum::Accepted, CredentialStateEnum::Accepted),
    // suspending, including re-suspending to update `suspend_end_date`
    (
        CredentialStateEnum::Accepted,
        CredentialStateEnum::Suspended,
    ),
    (
        CredentialStateEnum::Expiring,
        CredentialStateEnum::Suspended,
    ),
    (
        CredentialStateEnum::Suspended,
        CredentialStateEnum::Suspended,
    ),
    // revoking, including an expiring batch and an already revoked credential
    (CredentialStateEnum::Accepted, CredentialStateEnum::Revoked),
    (CredentialStateEnum::Suspended, CredentialStateEnum::Revoked),
    (CredentialStateEnum::Expiring, CredentialStateEnum::Revoked),
    (CredentialStateEnum::Revoked, CredentialStateEnum::Revoked),
    // flagging a batch as expiring
    (CredentialStateEnum::Accepted, CredentialStateEnum::Expiring),
    (
        CredentialStateEnum::Suspended,
        CredentialStateEnum::Expiring,
    ),
    (CredentialStateEnum::Expiring, CredentialStateEnum::Expiring),
];

/// Compile-time reminder: a new `CredentialStateEnum` variant breaks this match and has to be
/// added to the `#[values(..)]` list of `test_transition_matrix` - and to `ALLOWED_TRANSITIONS`
/// if the issuer may move to or from it.
fn _every_state_is_in_the_matrix(state: CredentialStateEnum) {
    match state {
        CredentialStateEnum::Created
        | CredentialStateEnum::Pending
        | CredentialStateEnum::Offered
        | CredentialStateEnum::Accepted
        | CredentialStateEnum::Rejected
        | CredentialStateEnum::Revoked
        | CredentialStateEnum::Suspended
        | CredentialStateEnum::Error
        | CredentialStateEnum::InteractionExpired
        | CredentialStateEnum::Expiring
        | CredentialStateEnum::Expired => (),
    }
}

#[rstest]
fn test_transition_matrix(
    #[values(
        CredentialStateEnum::Created,
        CredentialStateEnum::Pending,
        CredentialStateEnum::Offered,
        CredentialStateEnum::Accepted,
        CredentialStateEnum::Rejected,
        CredentialStateEnum::Revoked,
        CredentialStateEnum::Suspended,
        CredentialStateEnum::Error,
        CredentialStateEnum::InteractionExpired,
        CredentialStateEnum::Expiring,
        CredentialStateEnum::Expired
    )]
    current_state: CredentialStateEnum,
    #[values(
        CredentialType::Single,
        CredentialType::BatchItem,
        CredentialType::BatchParent
    )]
    current_type: CredentialType,
    #[values(
        ChangeCredentialState::Accepted,
        ChangeCredentialState::Suspended {
            suspend_end_date: None
        },
        ChangeCredentialState::Revoked,
        ChangeCredentialState::Expiring
    )]
    change: ChangeCredentialState,
) {
    let target_state = CredentialStateEnum::from(change);
    let result = validate_transition(current_state, current_type, change);

    if !ALLOWED_TRANSITIONS.contains(&(current_state, target_state)) {
        assert_eq!(
            ErrorCode::BR_0366,
            result.unwrap_err().error_code(),
            "{current_type}: {current_state} -> {target_state} must be rejected"
        );
    } else if target_state == CredentialStateEnum::Expiring
        && current_type != CredentialType::BatchParent
    {
        // the transition itself is fine, but only a batch parent can carry the flag
        assert_eq!(
            ErrorCode::BR_0442,
            result.unwrap_err().error_code(),
            "{current_type}: {current_state} -> {target_state} must be rejected as an unsupported type"
        );
    } else {
        assert!(
            result.is_ok(),
            "{current_type}: {current_state} -> {target_state} must be allowed, got {:?}",
            result.err()
        );
    }
}

/// Collects what the mocks below were asked to do, so a test can assert on the whole interaction
/// instead of on per-call expectations.
struct Recorder<T>(Arc<Mutex<Vec<T>>>);

impl<T> Recorder<T> {
    fn push(&self, value: T) {
        self.0.lock().unwrap().push(value);
    }

    fn take(&self) -> Vec<T> {
        std::mem::take(&mut self.0.lock().unwrap())
    }
}

impl<T> Clone for Recorder<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> Default for Recorder<T> {
    fn default() -> Self {
        Self(Default::default())
    }
}

/// `(credential id, new state, new suspend end date)` of every `update_credential` call.
type StateUpdates = Recorder<(CredentialId, CredentialStateEnum, Option<OffsetDateTime>)>;
/// `(credential id, state)` of every state published to a revocation method.
type MarkedStates = Recorder<(CredentialId, RevocationState)>;

static MOCK_REVOCATION_METHOD: LazyLock<RevocationMethodId> = LazyLock::new(|| "mock".into());

/// An issuer-role batch parent in `parent_state`, with one item per entry in `item_states`.
fn issuer_batch(
    parent_state: CredentialStateEnum,
    item_states: &[CredentialStateEnum],
) -> (Credential, Vec<Credential>) {
    let parent = Credential {
        role: CredentialRole::Issuer,
        state: parent_state,
        r#type: CredentialType::BatchParent,
        ..generic_credential()
    };

    let items = item_states
        .iter()
        .map(|state| Credential {
            role: CredentialRole::Issuer,
            state: *state,
            r#type: CredentialType::BatchItem,
            parent: Some(parent.clone().into()),
            ..generic_credential()
        })
        .collect();

    (parent, items)
}

/// Serves `parent` and its `items`, recording every state update.
fn batch_repository(
    parent: &Credential,
    items: &[Credential],
    updates: StateUpdates,
) -> MockCredentialRepository {
    let mut credential_repository = MockCredentialRepository::default();

    credential_repository
        .expect_get_credential()
        .with(eq(parent.id))
        .returning({
            let parent = parent.clone();
            move |_| Ok(parent.clone())
        });

    credential_repository
        .expect_get_credential_list()
        .returning({
            let items = items.to_vec();
            let parent_id = parent.id;
            move |query| {
                assert!(
                    query
                        .filtering
                        .unwrap()
                        .contains(&|filter: &CredentialFilterValue| *filter
                            == CredentialFilterValue::ParentCredential(parent_id))
                );
                Ok(GetCredentialList {
                    total_items: Some(items.len() as u64),
                    total_pages: Some(1),
                    values: items.clone(),
                })
            }
        });

    record_updates(&mut credential_repository, updates);
    credential_repository
}

/// Serves `credential` alone, recording every state update - loading batch items fails the test.
fn single_credential_repository(
    credential: &Credential,
    updates: StateUpdates,
) -> MockCredentialRepository {
    let mut credential_repository = MockCredentialRepository::default();

    credential_repository
        .expect_get_credential()
        .with(eq(credential.id))
        .returning({
            let credential = credential.clone();
            move |_| Ok(credential.clone())
        });

    credential_repository.expect_get_credential_list().never();

    record_updates(&mut credential_repository, updates);
    credential_repository
}

fn record_updates(credential_repository: &mut MockCredentialRepository, updates: StateUpdates) {
    credential_repository
        .expect_update_credential()
        .returning(move |credential_id, request| {
            updates.push((
                credential_id,
                request.state.unwrap(),
                match request.suspend_end_date {
                    Clearable::ForceSet(suspend_end_date) => suspend_end_date,
                    Clearable::DontTouch => None,
                },
            ));
            Ok(())
        });
}

/// Every credential resolves to a formatter carrying `MOCK_REVOCATION_METHOD`.
fn any_formatter_provider() -> MockCredentialFormatterProvider {
    let mut formatter_provider = MockCredentialFormatterProvider::new();
    formatter_provider
        .expect_get_credential_formatter()
        .returning(|_| {
            let mut formatter = MockCredentialFormatter::default();
            formatter
                .expect_revocation_method_id()
                .returning(|| Some(&*MOCK_REVOCATION_METHOD));
            Ok(Arc::new(formatter))
        });
    formatter_provider
}

/// A revocation method that supports every state and records what it published.
fn recording_revocation_method_provider(marked: MarkedStates) -> MockRevocationMethodProvider {
    let mut revocation_method = MockRevocationMethod::default();
    revocation_method
        .expect_mark_credential_as()
        .returning(move |credential, state| {
            marked.push((credential.id, state));
            Ok(())
        });

    let revocation_method = Arc::new(revocation_method);
    let mut revocation_method_provider = MockRevocationMethodProvider::default();
    revocation_method_provider
        .expect_get_revocation_method()
        .returning(move |_| Ok(revocation_method.clone()));
    revocation_method_provider
}

fn batch_validity_manager(
    credential_repository: MockCredentialRepository,
    marked: MarkedStates,
) -> CredentialValidityManagerImpl {
    setup_validity_manager(Repositories {
        credential_repository,
        formatter_provider: any_formatter_provider(),
        revocation_method_provider: recording_revocation_method_provider(marked),
        config: generic_config().core,
        ..Default::default()
    })
}

#[tokio::test]
async fn test_revoke_expiring_batch_parent() {
    // `Expiring` is not terminal - the batch can still be revoked, and the items follow
    let (parent, items) = issuer_batch(
        CredentialStateEnum::Expiring,
        &[CredentialStateEnum::Accepted],
    );
    let updates = StateUpdates::default();
    let marked = MarkedStates::default();
    let validity_manager = batch_validity_manager(
        batch_repository(&parent, &items, updates.clone()),
        marked.clone(),
    );

    validity_manager
        .change_credential_state(&parent.id, ChangeCredentialState::Revoked)
        .await
        .unwrap();

    assert_eq!(vec![(items[0].id, RevocationState::Revoked)], marked.take());
    assert_eq!(
        vec![
            (items[0].id, CredentialStateEnum::Revoked, None),
            (parent.id, CredentialStateEnum::Revoked, None),
        ],
        updates.take()
    );
}

#[tokio::test]
async fn test_suspend_batch_parent_with_already_suspended_item() {
    // re-suspending an item is how its `suspend_end_date` gets updated, so an item that already
    // carries the target state must not make the parent's change fail
    let (parent, mut items) = issuer_batch(
        CredentialStateEnum::Accepted,
        &[
            CredentialStateEnum::Accepted,
            CredentialStateEnum::Suspended,
        ],
    );
    let previous_end_date = crate::clock::now_utc().add(Duration::days(1));
    items[1].suspend_end_date = Some(previous_end_date);

    let new_end_date = crate::clock::now_utc().add(Duration::days(7));
    let updates = StateUpdates::default();
    let marked = MarkedStates::default();
    let validity_manager = batch_validity_manager(
        batch_repository(&parent, &items, updates.clone()),
        marked.clone(),
    );

    validity_manager
        .change_credential_state(
            &parent.id,
            ChangeCredentialState::Suspended {
                suspend_end_date: Some(new_end_date),
            },
        )
        .await
        .unwrap();

    let suspended = RevocationState::Suspended {
        suspend_end_date: Some(new_end_date),
    };
    assert_eq!(
        vec![(items[0].id, suspended), (items[1].id, suspended)],
        marked.take()
    );
    assert_eq!(
        vec![
            (
                items[0].id,
                CredentialStateEnum::Suspended,
                Some(new_end_date)
            ),
            (
                items[1].id,
                CredentialStateEnum::Suspended,
                Some(new_end_date)
            ),
            (
                parent.id,
                CredentialStateEnum::Suspended,
                Some(new_end_date)
            ),
        ],
        updates.take()
    );
}

#[tokio::test]
async fn test_suspend_batch_parent_skips_items_that_cannot_follow() {
    // terminal items keep their state, and they do not block the items that can still follow
    let (parent, items) = issuer_batch(
        CredentialStateEnum::Accepted,
        &[
            CredentialStateEnum::Accepted,
            CredentialStateEnum::Revoked,
            CredentialStateEnum::Expired,
            CredentialStateEnum::Pending,
        ],
    );
    let updates = StateUpdates::default();
    let marked = MarkedStates::default();
    let validity_manager = batch_validity_manager(
        batch_repository(&parent, &items, updates.clone()),
        marked.clone(),
    );

    validity_manager
        .change_credential_state(
            &parent.id,
            ChangeCredentialState::Suspended {
                suspend_end_date: None,
            },
        )
        .await
        .unwrap();

    assert_eq!(
        vec![(
            items[0].id,
            RevocationState::Suspended {
                suspend_end_date: None
            }
        )],
        marked.take()
    );
    assert_eq!(
        vec![
            (items[0].id, CredentialStateEnum::Suspended, None),
            (parent.id, CredentialStateEnum::Suspended, None),
        ],
        updates.take()
    );
}

#[tokio::test]
async fn test_suspend_batch_parent_with_only_terminal_items() {
    // the parent's state is the issuer's decision, not an aggregation of its items: it moves even
    // when no item can follow it
    let (parent, items) = issuer_batch(
        CredentialStateEnum::Accepted,
        &[CredentialStateEnum::Revoked],
    );
    let updates = StateUpdates::default();
    let marked = MarkedStates::default();
    let validity_manager = batch_validity_manager(
        batch_repository(&parent, &items, updates.clone()),
        marked.clone(),
    );

    validity_manager
        .change_credential_state(
            &parent.id,
            ChangeCredentialState::Suspended {
                suspend_end_date: None,
            },
        )
        .await
        .unwrap();

    assert!(marked.take().is_empty());
    assert_eq!(
        vec![(parent.id, CredentialStateEnum::Suspended, None)],
        updates.take()
    );
}

#[tokio::test]
async fn test_flagging_a_batch_parent_as_expiring_leaves_items_untouched() {
    // no revocation list can express `Expiring`, so it is a flag on the parent alone
    let parent = Credential {
        role: CredentialRole::Issuer,
        state: CredentialStateEnum::Accepted,
        r#type: CredentialType::BatchParent,
        ..generic_credential()
    };
    let updates = StateUpdates::default();
    let marked = MarkedStates::default();
    let validity_manager = batch_validity_manager(
        single_credential_repository(&parent, updates.clone()),
        marked.clone(),
    );

    validity_manager
        .change_credential_state(&parent.id, ChangeCredentialState::Expiring)
        .await
        .unwrap();

    assert!(marked.take().is_empty());
    assert_eq!(
        vec![(parent.id, CredentialStateEnum::Expiring, None)],
        updates.take()
    );
}

#[tokio::test]
async fn test_clearing_the_expiring_flag_leaves_items_untouched() {
    // the items were never marked when the flag was raised, so there is nothing to restore
    let parent = Credential {
        role: CredentialRole::Issuer,
        state: CredentialStateEnum::Expiring,
        r#type: CredentialType::BatchParent,
        ..generic_credential()
    };
    let updates = StateUpdates::default();
    let marked = MarkedStates::default();
    let validity_manager = batch_validity_manager(
        single_credential_repository(&parent, updates.clone()),
        marked.clone(),
    );

    validity_manager
        .change_credential_state(&parent.id, ChangeCredentialState::Accepted)
        .await
        .unwrap();

    assert!(marked.take().is_empty());
    assert_eq!(
        vec![(parent.id, CredentialStateEnum::Accepted, None)],
        updates.take()
    );
}

#[tokio::test]
async fn test_reapplying_the_current_state_is_a_noop() {
    let credential = Credential {
        role: CredentialRole::Issuer,
        state: CredentialStateEnum::Revoked,
        ..generic_credential()
    };
    let updates = StateUpdates::default();
    let marked = MarkedStates::default();
    let validity_manager = batch_validity_manager(
        single_credential_repository(&credential, updates.clone()),
        marked.clone(),
    );

    validity_manager
        .change_credential_state(&credential.id, ChangeCredentialState::Revoked)
        .await
        .unwrap();

    assert!(marked.take().is_empty());
    assert!(updates.take().is_empty());
}

#[tokio::test]
async fn test_expiring_is_not_supported_for_single_credentials() {
    let credential = Credential {
        role: CredentialRole::Issuer,
        state: CredentialStateEnum::Accepted,
        ..generic_credential()
    };
    let updates = StateUpdates::default();
    let validity_manager = batch_validity_manager(
        single_credential_repository(&credential, updates.clone()),
        MarkedStates::default(),
    );

    let error = validity_manager
        .change_credential_state(&credential.id, ChangeCredentialState::Expiring)
        .await
        .unwrap_err();

    assert_eq!(ErrorCode::BR_0442, error.error_code());
    assert!(updates.take().is_empty());
}
