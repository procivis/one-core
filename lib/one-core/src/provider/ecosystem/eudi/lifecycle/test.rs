use std::sync::Arc;

use mockall::predicate::eq;
use serde_json::json;
use shared_types::{BlobId, CredentialId};
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::config::core_config::CoreConfig;
use crate::model::blob::{Blob, BlobType};
use crate::model::common::GetListResponse;
use crate::model::credential::{
    Credential, CredentialStateEnum, CredentialType, GetCredentialList,
};
use crate::model::wallet_attestation::AttestationType;
use crate::proto::credential_validity_manager::dto::ChangeCredentialState;
use crate::proto::credential_validity_manager::{
    Error as CredentialValidityManagerError, MockCredentialValidityManager,
};
use crate::proto::session_provider::NoSessionProvider;
use crate::proto::wallet_instance::{
    AttestationCheckResult, Error as WalletInstanceError, MockHolderWalletUnitProto,
    WalletUnitStatusCheckResponse,
};
use crate::proto::wrp_validator::MockWRPValidator;
use crate::provider::blob_storage::MockBlobStorage;
use crate::provider::blob_storage::provider::MockBlobStorageProvider;
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::provider::ecosystem::eudi::EudiEcosystem;
use crate::repository::credential_repository::MockCredentialRepository;
use crate::repository::credential_schema_repository::MockCredentialSchemaRepository;
use crate::repository::history_repository::MockHistoryRepository;
use crate::repository::proof_schema_repository::MockProofSchemaRepository;
use crate::service::credential::dto::{WalletInstanceAttestationDTO, WalletUnitAttestationDTO};
use crate::service::test_utilities::{CredentialBuilder, dummy_credential};

const WUA_TOKEN: &str = "wua.token";
const OTHER_WUA_TOKEN: &str = "other.wua.token";
const WIA_TOKEN: &str = "wia.token";

#[derive(Default)]
struct Mocks {
    credential_repository: MockCredentialRepository,
    blob_storage_provider: MockBlobStorageProvider,
    wallet_unit_proto: MockHolderWalletUnitProto,
    credential_validity_manager: MockCredentialValidityManager,
}

/// No PID is expected to be revoked - the mock panics on any revocation.
fn no_revocations() -> MockCredentialValidityManager {
    MockCredentialValidityManager::new()
}

/// Every reported PID is revoked successfully through its revocation method.
fn revokes_successfully() -> MockCredentialValidityManager {
    let mut credential_validity_manager = MockCredentialValidityManager::new();
    credential_validity_manager
        .expect_change_credential_state()
        .withf(|_, state| matches!(state, ChangeCredentialState::Revoked))
        .returning(|_, _| Ok(()));
    credential_validity_manager
}

fn setup(mocks: Mocks) -> EudiEcosystem {
    EudiEcosystem::new(
        "EUDI".into(),
        json!({
            "credentialSchemas": [
                { "format": "SD_JWT_VC", "pidSchemaIds": ["urn:eudi:pid:1"] }
            ]
        }),
        CoreConfig::default(),
        Arc::new(MockHistoryRepository::new()),
        Arc::new(MockWRPValidator::new()),
        Arc::new(mocks.blob_storage_provider),
        Arc::new(NoSessionProvider),
        Arc::new(MockCredentialFormatterProvider::new()),
        Arc::new(mocks.credential_repository),
        Arc::new(MockCredentialSchemaRepository::new()),
        Arc::new(MockProofSchemaRepository::new()),
        Arc::new(mocks.wallet_unit_proto),
        Arc::new(mocks.credential_validity_manager),
    )
    .unwrap()
}

/// The result of a run in which nothing had to be revoked.
fn empty_result(total_checks: u64) -> serde_json::Value {
    json!({
        "totalChecks": total_checks,
        "revokedCredentialIds": [],
        "failedCredentialIds": [],
    })
}

/// The single credential revoked through its revocation method.
fn revoked_id(result: &serde_json::Value) -> CredentialId {
    let ids: Vec<CredentialId> =
        serde_json::from_value(result["revokedCredentialIds"].clone()).unwrap();
    assert_eq!(json!([]), result["failedCredentialIds"]);
    assert_eq!(1, ids.len());
    ids[0]
}

fn credential_list(values: Vec<Credential>) -> GetCredentialList {
    GetListResponse {
        total_items: Some(values.len() as u64),
        total_pages: Some(1),
        values,
    }
}

/// Serves `pages[n]` for page `n` and an empty page beyond, so the paging loop terminates.
fn credential_repository_serving(pages: Vec<Vec<Credential>>) -> MockCredentialRepository {
    let mut credential_repository = MockCredentialRepository::new();
    credential_repository
        .expect_get_credential_list()
        .times(pages.len() + 1)
        .returning(move |query| {
            let page = query
                .pagination
                .as_ref()
                .expect("the PID query must be paginated")
                .page as usize;
            Ok(credential_list(
                pages.get(page).cloned().unwrap_or_default(),
            ))
        });
    credential_repository
}

fn attestation_blob(id: BlobId, value: Vec<u8>, r#type: BlobType) -> Blob {
    Blob {
        id,
        created_date: crate::clock::now_utc(),
        last_modified: crate::clock::now_utc(),
        value,
        r#type,
    }
}

fn wua_blob(id: BlobId) -> Blob {
    wua_blob_with_token(id, WUA_TOKEN)
}

fn wua_blob_with_token(id: BlobId, token: &str) -> Blob {
    attestation_blob(
        id,
        serde_json::to_vec(&WalletUnitAttestationDTO {
            attestation: token.to_string(),
        })
        .unwrap(),
        BlobType::WalletUnitAttestation,
    )
}

fn wia_blob(id: BlobId) -> Blob {
    attestation_blob(
        id,
        serde_json::to_vec(&WalletInstanceAttestationDTO {
            name: "wallet".to_string(),
            link: "https://wallet.example".to_string(),
            attestation: WIA_TOKEN.to_string(),
        })
        .unwrap(),
        BlobType::WalletInstanceAttestation,
    )
}

/// Serves each requested blob id from the given list.
fn blob_storage_provider(blobs: Vec<Blob>) -> MockBlobStorageProvider {
    let mut provider = MockBlobStorageProvider::new();
    provider.expect_get_blob_storage().return_once(move |_| {
        let mut blob_storage = MockBlobStorage::new();
        blob_storage.expect_get().returning(move |id| {
            Ok(blobs
                .iter()
                .find(|blob| blob.id == *id)
                .map(ToOwned::to_owned))
        });
        Ok(Arc::new(blob_storage))
    });
    provider
}

fn accepted_pid(wua_blob_id: Option<BlobId>, wia_blob_id: Option<BlobId>) -> Credential {
    {
        let mut updated_credential = dummy_credential();
        let issuer = updated_credential.issuer_credential_mut().unwrap();
        issuer.common.id = Uuid::new_v4().into();
        issuer.common.state = CredentialStateEnum::Accepted;
        issuer.data.wallet_key_attestation_blob_id = wua_blob_id;
        issuer.data.wallet_instance_attestation_blob_id = wia_blob_id;
        updated_credential
    }
}

fn batch_item(
    parent: &Credential,
    wua_blob_id: Option<BlobId>,
    wia_blob_id: Option<BlobId>,
) -> Credential {
    {
        let mut updated_credential = accepted_pid(wua_blob_id, wia_blob_id);
        updated_credential = CredentialBuilder {
            r#type: CredentialType::BatchItem,
            parent: Some(parent.clone().into()),
            ..updated_credential.into()
        }
        .build();
        updated_credential
    }
}

fn batch_parent() -> Credential {
    {
        let mut updated_credential = dummy_credential();
        updated_credential.common_mut().id = Uuid::new_v4().into();
        updated_credential = CredentialBuilder {
            r#type: CredentialType::BatchParent,
            ..updated_credential.into()
        }
        .build();
        updated_credential
    }
}

#[tokio::test]
async fn test_no_pid_schemas_configured_skips_the_check() {
    let ecosystem = EudiEcosystem::new(
        "EUDI".into(),
        json!({}),
        CoreConfig::default(),
        Arc::new(MockHistoryRepository::new()),
        Arc::new(MockWRPValidator::new()),
        Arc::new(MockBlobStorageProvider::new()),
        Arc::new(NoSessionProvider),
        Arc::new(MockCredentialFormatterProvider::new()),
        // no repository call expected
        Arc::new(MockCredentialRepository::new()),
        Arc::new(MockCredentialSchemaRepository::new()),
        Arc::new(MockProofSchemaRepository::new()),
        Arc::new(MockHolderWalletUnitProto::new()),
        Arc::new(MockCredentialValidityManager::new()),
    )
    .unwrap();

    let result = ecosystem.run_lifecycle_check().await.unwrap();
    assert_eq!(empty_result(0), result);
}

#[tokio::test]
async fn test_credential_with_valid_attestations_is_not_revoked() {
    let wua_blob_id: BlobId = Uuid::new_v4().into();
    let credential = accepted_pid(Some(wua_blob_id), None);

    let mut credential_repository = MockCredentialRepository::new();
    credential_repository
        .expect_get_credential_list()
        .times(2)
        .withf(|query| {
            let filter = format!("{:?}", query.filtering);
            [
                "Roles([Issuer])",
                "States([Accepted, Suspended])",
                "Types([Single, BatchItem])",
                "Deleted(false)",
                r#"Ecosystems([EcosystemId("EUDI")])"#,
                r#"SchemaId("urn:eudi:pid:1")"#,
            ]
            .iter()
            .all(|expected| filter.contains(expected))
        })
        .returning(move |query| {
            let page = query.pagination.as_ref().unwrap().page;
            Ok(credential_list(if page == 0 {
                vec![credential.clone()]
            } else {
                vec![]
            }))
        });

    let mut wallet_unit_proto = MockHolderWalletUnitProto::new();
    wallet_unit_proto
        .expect_check_attestation_status()
        .once()
        .returning(|_, _| {
            Ok(AttestationCheckResult {
                status: WalletUnitStatusCheckResponse::Active,
                expiration_date: None,
            })
        });

    let ecosystem = setup(Mocks {
        credential_validity_manager: no_revocations(),
        credential_repository,
        blob_storage_provider: blob_storage_provider(vec![wua_blob(wua_blob_id)]),
        wallet_unit_proto,
    });

    let result = ecosystem.run_lifecycle_check().await.unwrap();
    assert_eq!(empty_result(1), result);
}

#[tokio::test]
async fn test_revoked_wallet_unit_attestation_revokes_the_pid() {
    let wua_blob_id: BlobId = Uuid::new_v4().into();
    let credential = accepted_pid(Some(wua_blob_id), None);
    let credential_id = credential.common().id;

    let credential_repository = credential_repository_serving(vec![vec![credential]]);

    let mut wallet_unit_proto = MockHolderWalletUnitProto::new();
    wallet_unit_proto
        .expect_check_attestation_status()
        .once()
        .with(eq(WUA_TOKEN), eq(AttestationType::KeyAttestation))
        .returning(|_, _| {
            Ok(AttestationCheckResult {
                status: WalletUnitStatusCheckResponse::Revoked,
                expiration_date: None,
            })
        });

    let ecosystem = setup(Mocks {
        credential_validity_manager: revokes_successfully(),
        credential_repository,
        blob_storage_provider: blob_storage_provider(vec![wua_blob(wua_blob_id)]),
        wallet_unit_proto,
    });

    let result = ecosystem.run_lifecycle_check().await.unwrap();
    assert_eq!(credential_id, revoked_id(&result));
}

#[tokio::test]
async fn test_revoked_wallet_instance_attestation_revokes_the_pid() {
    let wia_blob_id: BlobId = Uuid::new_v4().into();
    let credential = accepted_pid(None, Some(wia_blob_id));
    let credential_id = credential.common().id;

    let credential_repository = credential_repository_serving(vec![vec![credential]]);

    let mut wallet_unit_proto = MockHolderWalletUnitProto::new();
    wallet_unit_proto
        .expect_check_attestation_status()
        .once()
        .with(
            eq(WIA_TOKEN),
            eq(AttestationType::WalletInstanceAttestation),
        )
        .returning(|_, _| {
            Ok(AttestationCheckResult {
                status: WalletUnitStatusCheckResponse::Revoked,
                expiration_date: None,
            })
        });

    let ecosystem = setup(Mocks {
        credential_validity_manager: revokes_successfully(),
        credential_repository,
        blob_storage_provider: blob_storage_provider(vec![wia_blob(wia_blob_id)]),
        wallet_unit_proto,
    });

    let result = ecosystem.run_lifecycle_check().await.unwrap();
    assert_eq!(credential_id, revoked_id(&result));
}

#[tokio::test]
async fn test_revoked_wia_revokes_the_whole_batch_once() {
    let parent = batch_parent();
    let parent_id = parent.common().id;

    // the WIA is copied from the parent onto every item, so both items carry the same one
    let wia_blob_id: BlobId = Uuid::new_v4().into();
    let items = vec![
        batch_item(&parent, None, Some(wia_blob_id)),
        batch_item(&parent, None, Some(wia_blob_id)),
    ];

    let credential_repository = credential_repository_serving(vec![items]);

    let mut wallet_unit_proto = MockHolderWalletUnitProto::new();
    // only the first item is checked - once the batch is marked, its siblings are skipped
    wallet_unit_proto
        .expect_check_attestation_status()
        .once()
        .with(
            eq(WIA_TOKEN),
            eq(AttestationType::WalletInstanceAttestation),
        )
        .returning(|_, _| {
            Ok(AttestationCheckResult {
                status: WalletUnitStatusCheckResponse::Revoked,
                expiration_date: None,
            })
        });

    let ecosystem = setup(Mocks {
        credential_validity_manager: revokes_successfully(),
        credential_repository,
        blob_storage_provider: blob_storage_provider(vec![wia_blob(wia_blob_id)]),
        wallet_unit_proto,
    });

    let result = ecosystem.run_lifecycle_check().await.unwrap();
    // one revocation for the whole batch, published through the parent
    assert_eq!(parent_id, revoked_id(&result));
}

#[tokio::test]
async fn test_revoked_wua_revokes_only_the_batch_item() {
    let parent = {
        let mut updated_credential = dummy_credential();
        updated_credential.common_mut().id = Uuid::new_v4().into();
        updated_credential
    };

    // every item of a batch has its own WUA
    let revoked_wua_blob_id: BlobId = Uuid::new_v4().into();
    let active_wua_blob_id: BlobId = Uuid::new_v4().into();
    let revoked_item = batch_item(&parent, Some(revoked_wua_blob_id), None);
    let revoked_item_id = revoked_item.common().id;
    let items = vec![
        revoked_item,
        batch_item(&parent, Some(active_wua_blob_id), None),
    ];

    let credential_repository = credential_repository_serving(vec![items]);

    let mut wallet_unit_proto = MockHolderWalletUnitProto::new();
    // both items are checked, the batch is not skipped after the first revocation
    wallet_unit_proto
        .expect_check_attestation_status()
        .times(2)
        .returning(|attestation, _| {
            Ok(AttestationCheckResult {
                status: if attestation == WUA_TOKEN {
                    WalletUnitStatusCheckResponse::Revoked
                } else {
                    WalletUnitStatusCheckResponse::Active
                },
                expiration_date: None,
            })
        });

    let ecosystem = setup(Mocks {
        credential_validity_manager: revokes_successfully(),
        credential_repository,
        blob_storage_provider: blob_storage_provider(vec![
            wua_blob(revoked_wua_blob_id),
            wua_blob_with_token(active_wua_blob_id, OTHER_WUA_TOKEN),
        ]),
        wallet_unit_proto,
    });

    let result = ecosystem.run_lifecycle_check().await.unwrap();
    // the item itself is revoked, not the batch parent
    assert_eq!(revoked_item_id, revoked_id(&result));
}

#[tokio::test]
async fn test_revoked_wia_skips_the_wua_check() {
    let wua_blob_id: BlobId = Uuid::new_v4().into();
    let wia_blob_id: BlobId = Uuid::new_v4().into();
    let credential = accepted_pid(Some(wua_blob_id), Some(wia_blob_id));
    let credential_id = credential.common().id;

    let credential_repository = credential_repository_serving(vec![vec![credential]]);

    let mut wallet_unit_proto = MockHolderWalletUnitProto::new();
    wallet_unit_proto
        .expect_check_attestation_status()
        .once()
        .with(
            eq(WIA_TOKEN),
            eq(AttestationType::WalletInstanceAttestation),
        )
        .returning(|_, _| {
            Ok(AttestationCheckResult {
                status: WalletUnitStatusCheckResponse::Revoked,
                expiration_date: None,
            })
        });

    let ecosystem = setup(Mocks {
        credential_validity_manager: revokes_successfully(),
        credential_repository,
        blob_storage_provider: blob_storage_provider(vec![
            wua_blob(wua_blob_id),
            wia_blob(wia_blob_id),
        ]),
        wallet_unit_proto,
    });

    let result = ecosystem.run_lifecycle_check().await.unwrap();
    assert_eq!(credential_id, revoked_id(&result));
}

#[tokio::test]
async fn test_inconclusive_status_check_does_not_revoke() {
    let wua_blob_id: BlobId = Uuid::new_v4().into();
    let credential = accepted_pid(Some(wua_blob_id), None);

    let credential_repository = credential_repository_serving(vec![vec![credential]]);

    let mut wallet_unit_proto = MockHolderWalletUnitProto::new();
    wallet_unit_proto
        .expect_check_attestation_status()
        .once()
        .returning(|_, _| {
            Err(WalletInstanceError::MappingError(
                "status list unreachable".to_string(),
            ))
        });

    let ecosystem = setup(Mocks {
        credential_validity_manager: no_revocations(),
        credential_repository,
        blob_storage_provider: blob_storage_provider(vec![wua_blob(wua_blob_id)]),
        wallet_unit_proto,
    });

    let result = ecosystem.run_lifecycle_check().await.unwrap();
    assert_eq!(json!([]), result["revokedCredentialIds"]);
}

#[tokio::test]
async fn test_credential_without_attestations_is_not_revoked() {
    let credential = accepted_pid(None, None);

    let credential_repository = credential_repository_serving(vec![vec![credential]]);

    let ecosystem = setup(Mocks {
        credential_validity_manager: no_revocations(),
        credential_repository,
        blob_storage_provider: blob_storage_provider(vec![]),
        wallet_unit_proto: MockHolderWalletUnitProto::new(),
    });

    let result = ecosystem.run_lifecycle_check().await.unwrap();
    assert_eq!(json!([]), result["revokedCredentialIds"]);
}

#[tokio::test]
async fn test_all_pages_are_checked() {
    let wua_blob_id: BlobId = Uuid::new_v4().into();
    let first_page = accepted_pid(Some(wua_blob_id), None);
    let second_page = accepted_pid(Some(wua_blob_id), None);
    let second_page_id = second_page.common().id;

    let credential_repository =
        credential_repository_serving(vec![vec![first_page], vec![second_page]]);

    let mut wallet_unit_proto = MockHolderWalletUnitProto::new();
    let mut checked = 0;
    wallet_unit_proto
        .expect_check_attestation_status()
        .times(2)
        .returning(move |_, _| {
            checked += 1;
            Ok(AttestationCheckResult {
                status: if checked == 1 {
                    WalletUnitStatusCheckResponse::Active
                } else {
                    WalletUnitStatusCheckResponse::Revoked
                },
                expiration_date: None,
            })
        });

    let ecosystem = setup(Mocks {
        credential_validity_manager: revokes_successfully(),
        credential_repository,
        blob_storage_provider: blob_storage_provider(vec![wua_blob(wua_blob_id)]),
        wallet_unit_proto,
    });

    let result = ecosystem.run_lifecycle_check().await.unwrap();
    assert_eq!(2, result["totalChecks"]);
    assert_eq!(second_page_id, revoked_id(&result));
}

#[tokio::test]
async fn test_pid_that_cannot_be_revoked_is_reported() {
    let wua_blob_id: BlobId = Uuid::new_v4().into();
    let credential = accepted_pid(Some(wua_blob_id), None);
    let credential_id = credential.common().id;

    let mut wallet_unit_proto = MockHolderWalletUnitProto::new();
    wallet_unit_proto
        .expect_check_attestation_status()
        .once()
        .returning(|_, _| {
            Ok(AttestationCheckResult {
                status: WalletUnitStatusCheckResponse::Revoked,
                expiration_date: None,
            })
        });

    let mut credential_validity_manager = MockCredentialValidityManager::new();
    credential_validity_manager
        .expect_change_credential_state()
        .once()
        .returning(|_, _| {
            Err(CredentialValidityManagerError::MappingError(
                "no revocation method".to_string(),
            ))
        });

    let ecosystem = setup(Mocks {
        credential_repository: credential_repository_serving(vec![vec![credential]]),
        blob_storage_provider: blob_storage_provider(vec![wua_blob(wua_blob_id)]),
        wallet_unit_proto,
        credential_validity_manager,
    });

    let result = ecosystem.run_lifecycle_check().await.unwrap();

    assert_eq!(json!([credential_id]), result["failedCredentialIds"]);
}

/// A schema without a revocation method cannot express revocation, so the batch is flagged as
/// `Expiring` instead - it stays valid, but can never be refreshed.
#[tokio::test]
async fn test_batch_parent_that_cannot_be_revoked_is_flagged_expiring() {
    let parent = batch_parent();
    let parent_id = parent.common().id;

    let wia_blob_id: BlobId = Uuid::new_v4().into();
    let items = vec![batch_item(&parent, None, Some(wia_blob_id))];

    let mut wallet_unit_proto = MockHolderWalletUnitProto::new();
    wallet_unit_proto
        .expect_check_attestation_status()
        .once()
        .returning(|_, _| {
            Ok(AttestationCheckResult {
                status: WalletUnitStatusCheckResponse::Revoked,
                expiration_date: None,
            })
        });

    let mut credential_validity_manager = MockCredentialValidityManager::new();
    credential_validity_manager
        .expect_change_credential_state()
        .once()
        .withf(move |id, state| *id == parent_id && matches!(state, ChangeCredentialState::Revoked))
        .returning(|_, _| {
            Err(CredentialValidityManagerError::NoRevocationMethod(
                Uuid::new_v4().into(),
            ))
        });
    credential_validity_manager
        .expect_change_credential_state()
        .once()
        .withf(move |id, state| {
            *id == parent_id && matches!(state, ChangeCredentialState::Expiring)
        })
        .returning(|_, _| Ok(()));

    let ecosystem = setup(Mocks {
        credential_repository: credential_repository_serving(vec![items]),
        blob_storage_provider: blob_storage_provider(vec![wia_blob(wia_blob_id)]),
        wallet_unit_proto,
        credential_validity_manager,
    });

    let result = ecosystem.run_lifecycle_check().await.unwrap();

    assert_eq!(json!([parent_id]), result["failedCredentialIds"]);
}

/// `Expiring` is a batch-parent-only flag, so an item revoked through its own WUA has no
/// fallback - it is reported as failed and left alone. The mock panics on any second state change.
#[tokio::test]
async fn test_batch_item_that_cannot_be_revoked_is_not_flagged_expiring() {
    let parent = batch_parent();

    let wua_blob_id: BlobId = Uuid::new_v4().into();
    let item = batch_item(&parent, Some(wua_blob_id), None);
    let item_id = item.common().id;

    let mut wallet_unit_proto = MockHolderWalletUnitProto::new();
    wallet_unit_proto
        .expect_check_attestation_status()
        .once()
        .returning(|_, _| {
            Ok(AttestationCheckResult {
                status: WalletUnitStatusCheckResponse::Revoked,
                expiration_date: None,
            })
        });

    let mut credential_validity_manager = MockCredentialValidityManager::new();
    credential_validity_manager
        .expect_change_credential_state()
        .once()
        .withf(move |id, state| *id == item_id && matches!(state, ChangeCredentialState::Revoked))
        .returning(|_, _| {
            Err(CredentialValidityManagerError::NoRevocationMethod(
                Uuid::new_v4().into(),
            ))
        });

    let ecosystem = setup(Mocks {
        credential_repository: credential_repository_serving(vec![vec![item]]),
        blob_storage_provider: blob_storage_provider(vec![wua_blob(wua_blob_id)]),
        wallet_unit_proto,
        credential_validity_manager,
    });

    let result = ecosystem.run_lifecycle_check().await.unwrap();

    assert_eq!(json!([item_id]), result["failedCredentialIds"]);
}
