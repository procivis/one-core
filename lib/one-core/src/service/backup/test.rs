use std::path::PathBuf;
use std::sync::Arc;

use secrecy::SecretString;
use similar_asserts::assert_eq;
use tempfile::NamedTempFile;
use uuid::Uuid;

use super::BackupService;
use crate::mapper::credential_schema_claim::backfill_default_translations;
use crate::model::backup::{Metadata, UnexportableEntities};
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{Credential, CredentialRole, CredentialStateEnum, CredentialType};
use crate::model::credential_schema::{CredentialSchema, KeyStorageSecurity, WalletAttestation};
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::history::{History, HistoryAction, HistoryEntityType, HistorySource};
use crate::model::organisation::{GetOrganisationList, OrganisationListQuery};
use crate::provider::credential_formatter::MockCredentialFormatter;
use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
use crate::repository::backup_repository::MockBackupRepository;
use crate::repository::credential_repository::MockCredentialRepository;
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
    pub credential_repository: MockCredentialRepository,
    pub formatter_provider: MockCredentialFormatterProvider,
}

fn setup_service(repositories: Repositories) -> BackupService {
    BackupService::new(
        Arc::new(repositories.backup_repository),
        Arc::new(repositories.history_repository),
        Arc::new(repositories.organisation_repository),
        Arc::new(repositories.credential_repository),
        Arc::new(repositories.formatter_provider),
        Arc::new(generic_config().core),
    )
}

async fn dummy_unexportable_entities() -> UnexportableEntities {
    let claim_schema_id = Uuid::new_v4().into();

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
    UnexportableEntities {
        credentials: vec![Credential {
            expires_at: None,
            ecosystem: None,
            id: Uuid::new_v4().into(),
            created_date: crate::clock::now_utc(),
            issuance_date: None,
            last_modified: crate::clock::now_utc(),
            deleted_at: None,
            consumed_at: None,
            protocol: "foo".into(),
            redirect_uri: None,
            role: CredentialRole::Holder,
            r#type: CredentialType::Single,
            state: CredentialStateEnum::Created,
            suspend_end_date: None,
            profile: None,
            claims: vec![Claim {
                id: Uuid::new_v4().into(),
                credential_id: Uuid::new_v4().into(),
                created_date: crate::clock::now_utc(),
                last_modified: crate::clock::now_utc(),
                value: Some("value".to_string()),
                path: "key".into(),
                selectively_disclosable: false,
                schema: ClaimSchema {
                    id: claim_schema_id,
                    key: "key".into(),
                    data_type: "STRING".into(),
                    created_date: crate::clock::now_utc(),
                    last_modified: crate::clock::now_utc(),
                    array: false,
                    metadata: false,
                    required: false,
                    translations: Default::default(),
                }
                .into(),
            }]
            .into(),
            issuer_identifier: None,
            issuer_certificate: None,
            holder_identifier: None,
            schema: backfill_default_translations(
                CredentialSchema {
                    expiration: None,
                    ecosystem: None,
                    batch_size: None,
                    allow_revocation: true,
                    id: credential_schema_id,
                    deleted_at: None,
                    imported_source_url: "CORE_URL".to_string(),
                    created_date: crate::clock::now_utc(),
                    last_modified: crate::clock::now_utc(),
                    wallet_attestation: WalletAttestation {
                        require_instance_attestation: false,
                        key_storage_security_level: Some(KeyStorageSecurity::Basic),
                        preferred_key_storage_attestation_lifetime: None,
                        preferred_instance_attestation_lifetime: None,
                    },
                    name: "name".into(),
                    formats: vec![format.clone()].into(),
                    claim_schemas: vec![ClaimSchema {
                        id: claim_schema_id,
                        key: "key".into(),
                        data_type: "STRING".into(),
                        created_date: crate::clock::now_utc(),
                        last_modified: crate::clock::now_utc(),
                        array: false,
                        metadata: false,
                        required: false,
                        translations: Default::default(),
                    }]
                    .into(),
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
            .unwrap()
            .into(),
            interaction: None,
            key: None,
            credential_blob_id: None,
            wallet_key_attestation_blob_id: None,
            wallet_instance_attestation_blob_id: None,
            webhook_url: None,
            parent: None,
            embedded_disclosure_policy: None,
            subscriber_information: None,
            format: Some(format.into()),
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
            entity_type: HistoryEntityType::Instance,
            metadata: None,
            organisation_id: None,
            user: None,
            metadata_blob_id: None,
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

    let entities = dummy_unexportable_entities().await;
    repositories
        .backup_repository
        .expect_fetch_unexportable()
        .once()
        .return_once(move |_| Ok(entities));

    repositories
        .formatter_provider
        .expect_get_credential_formatter()
        .return_once(|_| {
            let mut formatter = MockCredentialFormatter::new();
            formatter.expect_revocation_method_id().return_const(None);
            Ok(Arc::new(formatter))
        });

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

    let entities = dummy_unexportable_entities().await;
    repositories
        .backup_repository
        .expect_fetch_unexportable()
        .once()
        .return_once(move |_| Ok(entities));

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

    repositories
        .formatter_provider
        .expect_get_credential_formatter()
        .return_once(|_| {
            let mut formatter = MockCredentialFormatter::new();
            formatter.expect_revocation_method_id().return_const(None);
            Ok(Arc::new(formatter))
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
