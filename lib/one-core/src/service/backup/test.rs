use std::sync::Arc;

use tempfile::NamedTempFile;
use time::OffsetDateTime;
use uuid::Uuid;

use super::BackupService;
use crate::model::backup::{Metadata, UnexportableEntities};
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{Credential, CredentialRole, CredentialStateEnum};
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaClaim, CredentialSchemaType, LayoutType,
    WalletStorageTypeEnum,
};
use crate::model::history::{HistoryAction, HistoryEntityType};
use crate::model::organisation::Organisation;
use crate::repository::backup_repository::MockBackupRepository;
use crate::repository::history_repository::MockHistoryRepository;
use crate::repository::organisation_repository::MockOrganisationRepository;
use crate::service::test_utilities::{dummy_did, dummy_key, dummy_organisation, generic_config};

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
        Arc::new(generic_config().core),
    )
}

fn dummy_unexportable_entities() -> UnexportableEntities {
    let claim_schema_id = Uuid::new_v4().into();

    UnexportableEntities {
        credentials: vec![Credential {
            id: Uuid::new_v4().into(),
            created_date: OffsetDateTime::now_utc(),
            issuance_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            deleted_at: None,
            credential: vec![],
            exchange: "foo".into(),
            redirect_uri: None,
            role: CredentialRole::Holder,
            state: CredentialStateEnum::Created,
            suspend_end_date: None,
            claims: Some(vec![Claim {
                id: Uuid::new_v4(),
                credential_id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                value: "value".into(),
                path: "key".into(),
                schema: Some(ClaimSchema {
                    id: claim_schema_id,
                    key: "key".into(),
                    data_type: "STRING".into(),
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    array: false,
                }),
            }]),
            issuer_did: None,
            holder_did: None,
            schema: Some(CredentialSchema {
                id: Uuid::new_v4().into(),
                deleted_at: None,
                imported_source_url: "CORE_URL".to_string(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                wallet_storage_type: Some(WalletStorageTypeEnum::Software),
                name: "name".into(),
                format: "format".into(),
                revocation_method: "revocation_method".into(),
                claim_schemas: Some(vec![CredentialSchemaClaim {
                    schema: ClaimSchema {
                        id: claim_schema_id,
                        key: "key".into(),
                        data_type: "STRING".into(),
                        created_date: OffsetDateTime::now_utc(),
                        last_modified: OffsetDateTime::now_utc(),
                        array: false,
                    },
                    required: false,
                }]),
                organisation: Some(Organisation {
                    id: Uuid::new_v4().into(),
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                }),
                layout_type: LayoutType::Card,
                layout_properties: None,
                schema_type: CredentialSchemaType::ProcivisOneSchema2024,
                schema_id: "CredentialSchemaId".to_owned(),
                allow_suspension: true,
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
    service.backup_info().await.unwrap();
}

#[tokio::test]
async fn test_finalize_import() {
    let mut repositories = Repositories::default();
    let organisation = dummy_organisation();

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
            assert_eq!(event.action, HistoryAction::Restored);
            assert_eq!(event.entity_id, None);
            assert_eq!(event.entity_type, HistoryEntityType::Backup);
            assert_eq!(event.organisation, Some(organisation));
            Ok(Uuid::new_v4().into())
        });

    let service = setup_service(repositories);
    service.finalize_import().await;
}

#[tokio::test]
async fn test_backup_flow() {
    let mut repositories = Repositories::default();
    let organisation = dummy_organisation();
    let db_version = "10".into();
    let history_id = Uuid::new_v4().into();

    repositories
        .backup_repository
        .expect_copy_db_to()
        .once()
        .return_once(|path| {
            std::fs::write(path, "content").unwrap();
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
        .backup_repository
        .expect_add_history_event()
        .once()
        .return_once(|_, _| Ok(()));

    repositories
        .history_repository
        .expect_create_history()
        .once()
        .return_once(move |event| {
            assert_eq!(event.action, HistoryAction::Created);
            assert_eq!(event.entity_id, None);
            assert_eq!(event.entity_type, HistoryEntityType::Backup);
            assert_eq!(event.organisation, Some(organisation));
            Ok(history_id)
        });

    let service = setup_service(repositories);

    let zip = NamedTempFile::new().unwrap();
    let zip_path: String = zip.path().to_string_lossy().into();

    let db = NamedTempFile::new().unwrap();
    let db_path: String = db.path().to_string_lossy().into();

    let unexportable = service
        .create_backup("foo".into(), zip_path.clone())
        .await
        .unwrap();

    assert_eq!(unexportable.history_id, history_id);

    let metadata = service
        .unpack_backup("foo".into(), zip_path, db_path)
        .await
        .unwrap();

    assert_eq!(metadata.db_version, "10");
    assert_eq!(std::io::read_to_string(db).unwrap(), "content");
}
