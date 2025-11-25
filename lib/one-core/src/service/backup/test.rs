use std::path::PathBuf;
use std::sync::Arc;

use secrecy::SecretString;
use similar_asserts::assert_eq;
use tempfile::NamedTempFile;
use time::OffsetDateTime;
use uuid::Uuid;

use super::BackupService;
use crate::model::backup::{Metadata, UnexportableEntities};
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{Credential, CredentialRole, CredentialStateEnum};
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaClaim, KeyStorageSecurity, LayoutType,
};
use crate::model::history::{History, HistoryAction, HistoryEntityType, HistorySource};
use crate::model::organisation::{GetOrganisationList, OrganisationListQuery};
use crate::repository::backup_repository::MockBackupRepository;
use crate::repository::history_repository::MockHistoryRepository;
use crate::repository::organisation_repository::MockOrganisationRepository;
use crate::service::test_utilities::{
    dummy_did, dummy_identifier, dummy_key, dummy_organisation, generic_config, get_dummy_date,
};

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
            issuance_date: None,
            last_modified: OffsetDateTime::now_utc(),
            deleted_at: None,
            protocol: "foo".into(),
            redirect_uri: None,
            role: CredentialRole::Holder,
            state: CredentialStateEnum::Created,
            suspend_end_date: None,
            profile: None,
            claims: Some(vec![Claim {
                id: Uuid::new_v4(),
                credential_id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                value: Some("value".to_string()),
                path: "key".into(),
                selectively_disclosable: false,
                schema: Some(ClaimSchema {
                    id: claim_schema_id,
                    key: "key".into(),
                    data_type: "STRING".into(),
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    array: false,
                    metadata: false,
                }),
            }]),
            issuer_identifier: None,
            issuer_certificate: None,
            holder_identifier: None,
            schema: Some(CredentialSchema {
                id: Uuid::new_v4().into(),
                deleted_at: None,
                imported_source_url: "CORE_URL".to_string(),
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                key_storage_security: Some(KeyStorageSecurity::Basic),
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
                        metadata: false,
                    },
                    required: false,
                }]),
                organisation: Some(dummy_organisation(None)),
                layout_type: LayoutType::Card,
                layout_properties: None,
                schema_id: "CredentialSchemaId".to_owned(),
                allow_suspension: true,
                requires_app_attestation: false,
            }),
            interaction: None,
            key: None,
            credential_blob_id: None,
            wallet_unit_attestation_blob_id: None,
            wallet_app_attestation_blob_id: None,
        }],
        keys: vec![dummy_key()],
        dids: vec![dummy_did()],
        identifiers: vec![dummy_identifier()],
        histories: vec![History {
            id: Uuid::new_v4().into(),
            created_date: get_dummy_date(),
            action: HistoryAction::Accepted,
            name: "test".to_string(),
            source: HistorySource::Core,
            target: None,
            entity_id: Some(Uuid::new_v4().into()),
            entity_type: HistoryEntityType::WalletUnit,
            metadata: None,
            organisation_id: None,
            user: None,
        }],
        total_credentials: 5,
        total_keys: 5,
        total_dids: 5,
        total_identifiers: 5,
        total_histories: 1,
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
    let organisation = dummy_organisation(None);

    repositories
        .organisation_repository
        .expect_get_organisation_list()
        .once()
        .return_once({
            let organisation = organisation.clone();
            |_: OrganisationListQuery| {
                Ok(GetOrganisationList {
                    values: vec![organisation],
                    total_items: 1,
                    total_pages: 1,
                })
            }
        });

    repositories
        .history_repository
        .expect_create_history()
        .once()
        .return_once(move |event| {
            assert_eq!(event.action, HistoryAction::Restored);
            assert_eq!(event.entity_id, None);
            assert_eq!(event.entity_type, HistoryEntityType::Backup);
            assert_eq!(event.organisation_id, Some(organisation.id));
            Ok(Uuid::new_v4().into())
        });

    let service = setup_service(repositories);
    service.finalize_import("fname").await.unwrap();
}

#[tokio::test]
async fn test_backup_flow() {
    let mut repositories = Repositories::default();
    let organisation = dummy_organisation(None);
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
            |_: OrganisationListQuery| {
                Ok(GetOrganisationList {
                    values: vec![organisation],
                    total_items: 1,
                    total_pages: 1,
                })
            }
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
            assert_eq!(event.organisation_id, Some(organisation.id));
            Ok(history_id)
        });

    let service = setup_service(repositories);

    let zip = NamedTempFile::new().unwrap();
    let zip_path: String = zip.path().to_string_lossy().into();

    let db = NamedTempFile::new().unwrap();
    let db_path: String = db.path().to_string_lossy().into();

    let unexportable = service
        .create_backup(SecretString::from("foo"), zip_path.clone())
        .await
        .unwrap();

    assert_eq!(unexportable.history_id, history_id);

    let metadata = BackupService::unpack_backup(
        SecretString::from("foo"),
        PathBuf::from(zip_path),
        PathBuf::from(db_path),
    )
    .unwrap();

    assert_eq!(metadata.db_version, "10");
    assert_eq!(std::io::read_to_string(db).unwrap(), "content");
}
