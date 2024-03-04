use std::sync::Arc;

use tempfile::NamedTempFile;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::credential_schema::WalletStorageTypeEnum;
use crate::{
    model::{
        backup::{Metadata, UnexportableEntities},
        credential::{Credential, CredentialRole, CredentialState, CredentialStateEnum},
        credential_schema::CredentialSchema,
        history::{HistoryAction, HistoryEntityType},
        organisation::Organisation,
    },
    repository::{
        backup_repository::MockBackupRepository, history_repository::MockHistoryRepository,
        mock::organisation_repository::MockOrganisationRepository,
    },
    service::test_utilities::{dummy_did, dummy_key, dummy_organisation},
};

use super::BackupService;

#[derive(Default)]
struct Repositories {
    pub backup_repository: MockBackupRepository,
    pub history_repository: MockHistoryRepository,
    pub organisation_repository: MockOrganisationRepository,
}

fn setup_service(repositories: Repositories) -> BackupService {
    BackupService::new(
        Arc::new(repositories.backup_repository),
        Arc::new(repositories.history_repository),
        Arc::new(repositories.organisation_repository),
    )
}

fn dummy_unexportable_entities() -> UnexportableEntities {
    UnexportableEntities {
        credentials: vec![Credential {
            id: Uuid::new_v4().into(),
            created_date: OffsetDateTime::now_utc(),
            issuance_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            deleted_at: None,
            credential: vec![],
            transport: "foo".into(),
            redirect_uri: None,
            role: CredentialRole::Holder,
            state: Some(vec![CredentialState {
                created_date: OffsetDateTime::now_utc(),
                state: CredentialStateEnum::Created,
            }]),
            claims: Some(vec![]),
            issuer_did: None,
            holder_did: None,
            schema: Some(CredentialSchema {
                id: Uuid::new_v4(),
                deleted_at: None,
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                wallet_storage_type: Some(WalletStorageTypeEnum::Software),
                name: "name".into(),
                format: "format".into(),
                revocation_method: "revocation_method".into(),
                claim_schemas: None,
                organisation: Some(Organisation {
                    id: Uuid::new_v4(),
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                }),
            }),
            interaction: None,
            revocation_list: None,
            key: None,
        }],
        keys: vec![dummy_key()],
        dids: vec![dummy_did()],
        total_credentials: 5,
        total_keys: 5,
        total_dids: 5,
    }
}

#[tokio::test]
async fn test_fetch_unexportable() {
    let mut repositories = Repositories::default();

    repositories
        .backup_repository
        .expect_fetch_unexportable()
        .once()
        .return_once(|_| Ok(dummy_unexportable_entities()));

    let service = setup_service(repositories);
    assert!(service.backup_info().await.is_ok());
}

#[tokio::test]
async fn test_backup_flow() {
    let mut repositories = Repositories::default();
    let organisation = dummy_organisation();
    let db_version = "10".into();

    repositories
        .backup_repository
        .expect_copy_db_to()
        .once()
        .return_once(|_| {
            Ok(Metadata {
                version: db_version,
            })
        });

    repositories
        .backup_repository
        .expect_fetch_unexportable()
        .once()
        .return_once(|_| Ok(dummy_unexportable_entities()));

    repositories
        .backup_repository
        .expect_delete_unexportable()
        .once()
        .return_once(|_| Ok(()));

    repositories
        .organisation_repository
        .expect_get_organisation_list()
        .once()
        .return_once({
            let organisation = organisation.clone();
            || Ok(vec![organisation])
        });

    repositories
        .history_repository
        .expect_create_history()
        .once()
        .return_once(|event| {
            assert_eq!(event.action, HistoryAction::Created);
            assert_eq!(event.entity_id, None);
            assert_eq!(event.entity_type, HistoryEntityType::Backup);
            assert_eq!(event.organisation, Some(organisation));
            Ok(Uuid::new_v4().into())
        });

    let service = setup_service(repositories);

    let temp = NamedTempFile::new().unwrap();
    assert!(service
        .create_backup("foo".into(), temp.path().to_string_lossy().into())
        .await
        .is_ok());
}
