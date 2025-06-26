use futures::StreamExt;
use one_core::repository::backup_repository::BackupRepository;
use sea_orm::ActiveValue::NotSet;
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait, Iterable, Set};
use shared_types::{
    CertificateId, CredentialId, CredentialSchemaId, DidId, IdentifierId, KeyId, OrganisationId,
};
use similar_asserts::assert_eq;
use tempfile::NamedTempFile;
use uuid::Uuid;

use super::BackupProvider;
use crate::db_conn;
use crate::entity::certificate::{self, CertificateState};
use crate::entity::credential::{self, CredentialRole, CredentialState};
use crate::entity::did::{self, DidType};
use crate::entity::identifier::{self, IdentifierState, IdentifierType};
use crate::entity::key;
use crate::entity::key_did::KeyRole;
use crate::test_utilities::{
    ClaimInsertInfo, ProofInput, assert_eq_unordered, get_dummy_date,
    insert_credential_schema_to_database, insert_key_did, insert_many_claims_schema_to_database,
    insert_many_claims_to_database, insert_organisation_to_database,
};

async fn insert_key_to_database(
    database: &DatabaseConnection,
    organisation_id: OrganisationId,
    storage_type: &str,
    deleted: bool,
) -> KeyId {
    key::ActiveModel {
        id: Set(Uuid::new_v4().into()),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        name: Set(Uuid::new_v4().to_string()),
        public_key: Set(vec![]),
        key_reference: Set(vec![]),
        storage_type: Set(storage_type.into()),
        key_type: Set("".into()),
        organisation_id: Set(organisation_id),
        deleted_at: if deleted {
            Set(Some(get_dummy_date()))
        } else {
            NotSet
        },
    }
    .insert(database)
    .await
    .unwrap()
    .id
}

async fn insert_credential_to_database(
    database: &DatabaseConnection,
    schema_id: CredentialSchemaId,
    key_id: KeyId,
    deleted: bool,
) -> CredentialId {
    let credential_id = credential::ActiveModel {
        id: Set(Uuid::new_v4().into()),
        credential_schema_id: Set(schema_id),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        issuance_date: Set(get_dummy_date()),
        state: Set(CredentialState::Created),
        suspend_end_date: Set(None),
        deleted_at: if deleted {
            Set(Some(get_dummy_date()))
        } else {
            NotSet
        },
        protocol: Set("protocol".to_owned()),
        redirect_uri: Set(None),
        credential: Set(vec![]),
        role: Set(CredentialRole::Holder),
        issuer_identifier_id: Set(None),
        issuer_certificate_id: Set(None),
        holder_identifier_id: Set(None),
        interaction_id: Set(None),
        revocation_list_id: Set(None),
        key_id: Set(Some(key_id)),
    }
    .insert(database)
    .await
    .unwrap()
    .id;

    let claim_schema_id = Uuid::new_v4().into();
    let claim = ClaimInsertInfo {
        id: claim_schema_id,
        key: "name",
        required: false,
        order: 0,
        datatype: "STRING",
        array: false,
    };

    let proof_input = ProofInput {
        credential_schema_id: schema_id,
        claims: &vec![claim],
    };

    insert_many_claims_schema_to_database(database, &proof_input)
        .await
        .unwrap();
    insert_many_claims_to_database(
        database,
        &[(
            Uuid::new_v4().into(),
            claim_schema_id,
            credential_id,
            vec![255],
            "name".to_owned(),
        )],
    )
    .await
    .unwrap();

    credential_id
}

async fn insert_did_to_database(
    database: &DatabaseConnection,
    organisation_id: OrganisationId,
    deleted: bool,
    key_id: Uuid,
) -> DidId {
    let did_id = did::ActiveModel {
        id: Set(Uuid::new_v4().into()),
        did: Set(format!("did:example:{}", Uuid::new_v4()).parse().unwrap()),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        name: Set(Uuid::new_v4().to_string()),
        type_field: Set(DidType::Local),
        method: Set("method".into()),
        organisation_id: Set(Some(organisation_id)),
        deactivated: Set(false),
        deleted_at: if deleted {
            Set(Some(get_dummy_date()))
        } else {
            NotSet
        },
        log: NotSet,
    }
    .insert(database)
    .await
    .unwrap()
    .id;

    insert_key_did(database, did_id, key_id.into(), KeyRole::AssertionMethod)
        .await
        .unwrap();

    did_id
}

async fn insert_certificate_to_database(
    database: &DatabaseConnection,
    identifier_id: IdentifierId,
    organisation_id: Option<OrganisationId>,
    key_id: Option<KeyId>,
) -> CertificateId {
    certificate::ActiveModel {
        id: Set(Uuid::new_v4().into()),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        expiry_date: Set(get_dummy_date()),
        name: Set(Uuid::new_v4().to_string()),
        key_id: Set(key_id),
        state: Set(CertificateState::Active),
        chain: Set("chain".into()),
        fingerprint: Set(format!("fingerprint:{identifier_id}").parse().unwrap()),
        identifier_id: Set(identifier_id),
        organisation_id: Set(organisation_id),
    }
    .insert(database)
    .await
    .unwrap()
    .id
}

async fn insert_identifier_to_database(
    database: &DatabaseConnection,
    organisation_id: OrganisationId,
    deleted: bool,
    did_id: Option<DidId>,
    key_id: Option<KeyId>,
    r#type: IdentifierType,
) -> IdentifierId {
    identifier::ActiveModel {
        id: Set(Uuid::new_v4().into()),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        name: Set(Uuid::new_v4().to_string()),
        key_id: if r#type == IdentifierType::Key {
            Set(key_id)
        } else {
            NotSet
        },
        r#type: Set(r#type),
        is_remote: Set(false),
        state: Set(IdentifierState::Active),
        organisation_id: Set(Some(organisation_id)),
        did_id: Set(did_id),
        deleted_at: if deleted {
            Set(Some(get_dummy_date()))
        } else {
            NotSet
        },
    }
    .insert(database)
    .await
    .unwrap()
    .id
}

struct TestSetup {
    pub db: DatabaseConnection,
    pub provider: BackupProvider,
    pub organisation_id: OrganisationId,
    pub _db_holder: NamedTempFile,
}

async fn setup_empty() -> TestSetup {
    let _db_holder = NamedTempFile::new().unwrap();

    let db = db_conn(
        format!("sqlite:{}?mode=rw", _db_holder.path().to_string_lossy()),
        true,
    )
    .await
    .unwrap();

    let organisation_id = insert_organisation_to_database(&db, None, None)
        .await
        .unwrap();

    TestSetup {
        db: db.clone(),
        provider: BackupProvider {
            db,
            exportable_storages: vec!["INTERNAL".into()],
        },
        organisation_id,
        _db_holder,
    }
}

struct UnexportableSetup {
    pub exportable_ids: Vec<Uuid>,
    pub unexportable_ids: Vec<Uuid>,
    pub deleted_ids: Vec<Uuid>,
}

impl UnexportableSetup {
    fn total(&self) -> u64 {
        (self.exportable_ids.len() + self.unexportable_ids.len()) as _
    }

    fn join(&mut self, other: UnexportableSetup) {
        self.unexportable_ids.extend(other.unexportable_ids);
        self.exportable_ids.extend(other.exportable_ids);
        self.deleted_ids.extend(other.deleted_ids);
    }
}

async fn add_unexportable_keys(
    db: &DatabaseConnection,
    organisation_id: OrganisationId,
) -> UnexportableSetup {
    let exportable_key_id = insert_key_to_database(db, organisation_id, "INTERNAL", false).await;
    let unexportable_key_id = insert_key_to_database(db, organisation_id, "FOO", false).await;
    let deleted_exportable_key_id =
        insert_key_to_database(db, organisation_id, "INTERNAL", true).await;
    let deleted_unexportable_key_id =
        insert_key_to_database(db, organisation_id, "FOO", true).await;

    UnexportableSetup {
        exportable_ids: vec![exportable_key_id.into()],
        unexportable_ids: vec![unexportable_key_id.into()],
        deleted_ids: vec![
            deleted_exportable_key_id.into(),
            deleted_unexportable_key_id.into(),
        ],
    }
}

async fn add_unexportable_credentials(
    db: &DatabaseConnection,
    organisation_id: OrganisationId,
    keys_setup: &UnexportableSetup,
) -> UnexportableSetup {
    let schema_id = insert_credential_schema_to_database(
        db,
        None,
        organisation_id,
        "credential schema 1",
        "JWT",
        "NONE",
    )
    .await
    .unwrap();

    let exportable_ids = futures::stream::iter(keys_setup.exportable_ids.iter())
        .chain(futures::stream::iter(keys_setup.deleted_ids.iter()))
        .then(|key_id| insert_credential_to_database(db, schema_id, (*key_id).into(), false))
        .map(Uuid::from)
        .collect::<Vec<_>>()
        .await;

    let unexportable_ids = futures::stream::iter(keys_setup.unexportable_ids.iter())
        .then(|key_id| insert_credential_to_database(db, schema_id, (*key_id).into(), false))
        .map(Uuid::from)
        .collect::<Vec<_>>()
        .await;

    let deleted_ids = futures::stream::iter(keys_setup.exportable_ids.iter())
        .chain(futures::stream::iter(keys_setup.unexportable_ids.iter()))
        .chain(futures::stream::iter(keys_setup.deleted_ids.iter()))
        .then(|key_id| insert_credential_to_database(db, schema_id, (*key_id).into(), true))
        .map(Uuid::from)
        .collect::<Vec<_>>()
        .await;

    UnexportableSetup {
        exportable_ids,
        unexportable_ids,
        deleted_ids,
    }
}

async fn add_unexportable_dids(
    db: &DatabaseConnection,
    organisation_id: OrganisationId,
    keys_setup: &UnexportableSetup,
) -> UnexportableSetup {
    let exportable_ids = futures::stream::iter(keys_setup.exportable_ids.iter())
        .chain(futures::stream::iter(keys_setup.deleted_ids.iter()))
        .then(|key_id| insert_did_to_database(db, organisation_id, false, *key_id))
        .map(Uuid::from)
        .collect::<Vec<_>>()
        .await;

    let unexportable_ids = futures::stream::iter(keys_setup.unexportable_ids.iter())
        .then(|key_id| insert_did_to_database(db, organisation_id, false, *key_id))
        .map(Uuid::from)
        .collect::<Vec<_>>()
        .await;

    let deleted_ids = futures::stream::iter(keys_setup.exportable_ids.iter())
        .chain(futures::stream::iter(keys_setup.unexportable_ids.iter()))
        .chain(futures::stream::iter(keys_setup.deleted_ids.iter()))
        .then(|key_id| insert_did_to_database(db, organisation_id, true, *key_id))
        .map(Uuid::from)
        .collect::<Vec<_>>()
        .await;

    UnexportableSetup {
        exportable_ids,
        unexportable_ids,
        deleted_ids,
    }
}

async fn add_unexportable_identifiers(
    db: &DatabaseConnection,
    organisation_id: OrganisationId,
    keys_setup: &UnexportableSetup,
) -> UnexportableSetup {
    let mut exportable_ids = vec![];
    let mut unexportable_ids = vec![];
    let mut deleted_ids = vec![];
    for (identifier_type, key_id) in IdentifierType::iter()
        .cycle()
        .zip(keys_setup.exportable_ids.iter())
    {
        let exportable_identifier =
            add_identifier_with_type(db, organisation_id, false, identifier_type, *key_id).await;
        exportable_ids.push(exportable_identifier.into());
    }
    for (identifier_type, key_id) in IdentifierType::iter()
        .cycle()
        .zip(keys_setup.unexportable_ids.iter())
    {
        let unexportable_identifier =
            add_identifier_with_type(db, organisation_id, false, identifier_type, *key_id).await;
        unexportable_ids.push(unexportable_identifier.into());
    }
    for (identifier_type, key_id) in IdentifierType::iter()
        .cycle()
        .zip(keys_setup.deleted_ids.iter())
    {
        let deleted_identifier =
            add_identifier_with_type(db, organisation_id, true, identifier_type, *key_id).await;
        deleted_ids.push(deleted_identifier.into());
    }
    UnexportableSetup {
        exportable_ids,
        unexportable_ids,
        deleted_ids,
    }
}

async fn add_identifier_with_type(
    db: &DatabaseConnection,
    organisation_id: OrganisationId,
    deleted: bool,
    identifier_type: IdentifierType,
    key_id: Uuid,
) -> IdentifierId {
    match identifier_type {
        IdentifierType::Did => {
            let exportable_did = insert_did_to_database(db, organisation_id, false, key_id).await;
            insert_identifier_to_database(
                db,
                organisation_id,
                deleted,
                Some(exportable_did),
                None,
                IdentifierType::Did,
            )
            .await
        }
        IdentifierType::Certificate => {
            let exportable_identifier = insert_identifier_to_database(
                db,
                organisation_id,
                deleted,
                None,
                None,
                IdentifierType::Certificate,
            )
            .await;
            insert_certificate_to_database(
                db,
                exportable_identifier,
                Some(organisation_id),
                Some(key_id.into()),
            )
            .await;
            exportable_identifier
        }
        IdentifierType::Key => {
            insert_identifier_to_database(
                db,
                organisation_id,
                deleted,
                None,
                Some(key_id.into()),
                IdentifierType::Key,
            )
            .await
        }
    }
}

#[tokio::test]
async fn test_fetch_unexportable_local_no_records() {
    let setup = setup_empty().await;

    let unexportable = setup.provider.fetch_unexportable(None).await.unwrap();

    assert_eq!(unexportable.credentials, vec![]);
    assert_eq!(unexportable.keys, vec![]);
    assert_eq!(unexportable.dids, vec![]);
    assert_eq!(unexportable.identifiers, vec![]);
    assert_eq!(unexportable.total_credentials, 0);
    assert_eq!(unexportable.total_keys, 0);
    assert_eq!(unexportable.total_dids, 0);
    assert_eq!(unexportable.total_identifiers, 0);
}

#[tokio::test]
async fn test_fetch_unexportable_keys_local() {
    let setup = setup_empty().await;
    let unexportable_keys_setup = add_unexportable_keys(&setup.db, setup.organisation_id).await;

    let unexportable = setup.provider.fetch_unexportable(None).await.unwrap();

    assert_eq!(unexportable.total_keys, unexportable_keys_setup.total());
    assert_eq!(
        unexportable.keys.len(),
        unexportable_keys_setup.unexportable_ids.len()
    );
    assert_eq_unordered(
        unexportable.keys.into_iter().map(|item| item.id),
        unexportable_keys_setup.unexportable_ids,
    );
}

#[tokio::test]
async fn test_fetch_unexportable_credentials_local() {
    let setup = setup_empty().await;
    let unexportable_keys_setup = add_unexportable_keys(&setup.db, setup.organisation_id).await;
    let unexportable_credentials_setup =
        add_unexportable_credentials(&setup.db, setup.organisation_id, &unexportable_keys_setup)
            .await;

    let unexportable = setup.provider.fetch_unexportable(None).await.unwrap();

    assert_eq!(
        unexportable.total_credentials,
        unexportable_credentials_setup.total()
    );
    assert_eq!(
        unexportable.credentials.len(),
        unexportable_credentials_setup.unexportable_ids.len()
    );
    assert_eq_unordered(
        unexportable.credentials.into_iter().map(|item| item.id),
        unexportable_credentials_setup.unexportable_ids,
    );
}

#[tokio::test]
async fn test_fetch_unexportable_dids_local() {
    let setup = setup_empty().await;
    let unexportable_keys_setup = add_unexportable_keys(&setup.db, setup.organisation_id).await;
    let unexportable_dids_setup =
        add_unexportable_dids(&setup.db, setup.organisation_id, &unexportable_keys_setup).await;

    let unexportable = setup.provider.fetch_unexportable(None).await.unwrap();

    assert_eq!(unexportable.total_dids, unexportable_dids_setup.total());
    assert_eq!(
        unexportable.dids.len(),
        unexportable_dids_setup.unexportable_ids.len()
    );
    assert_eq_unordered(
        unexportable.dids.into_iter().map(|item| item.id),
        unexportable_dids_setup.unexportable_ids,
    );
}

#[tokio::test]
async fn test_fetch_unexportable_identifiers_local() {
    let setup = setup_empty().await;
    let mut unexportable_keys_setup = add_unexportable_keys(&setup.db, setup.organisation_id).await;
    // add two more sets of unexportable keys for each of the 3 types of identifier
    for _ in 0..2 {
        unexportable_keys_setup.join(add_unexportable_keys(&setup.db, setup.organisation_id).await);
    }
    let unexportable_identifiers_setup =
        add_unexportable_identifiers(&setup.db, setup.organisation_id, &unexportable_keys_setup)
            .await;

    let unexportable = setup.provider.fetch_unexportable(None).await.unwrap();

    assert_eq!(
        unexportable.total_identifiers,
        unexportable_identifiers_setup.total()
    );
    assert_eq!(
        unexportable.identifiers.len(),
        unexportable_identifiers_setup.unexportable_ids.len()
    );
    assert_eq_unordered(
        unexportable.identifiers.into_iter().map(|item| item.id),
        unexportable_identifiers_setup.unexportable_ids,
    );
}

#[tokio::test]
async fn test_fetch_unexportable_identifiers_certs_remote() {
    let setup = setup_empty().await;
    let exportable_identifier = insert_identifier_to_database(
        &setup.db,
        setup.organisation_id,
        false,
        None,
        None,
        IdentifierType::Certificate,
    )
    .await;
    insert_certificate_to_database(&setup.db, exportable_identifier, None, None).await;

    let unexportable = setup.provider.fetch_unexportable(None).await.unwrap();

    // identifier with cert that has no key should be exportable
    assert_eq!(unexportable.total_identifiers, 1);
    assert_eq!(unexportable.identifiers.len(), 0);
}

#[tokio::test]
async fn test_fetch_unexportable_dump_no_records() {
    let setup = setup_empty().await;

    let temp = NamedTempFile::new().unwrap();
    setup.provider.copy_db_to(temp.path()).await.unwrap();
    let unexportable = setup
        .provider
        .fetch_unexportable(Some(temp.path()))
        .await
        .unwrap();

    assert_eq!(unexportable.credentials, vec![]);
    assert_eq!(unexportable.keys, vec![]);
    assert_eq!(unexportable.dids, vec![]);
    assert_eq!(unexportable.total_credentials, 0);
    assert_eq!(unexportable.total_keys, 0);
    assert_eq!(unexportable.total_dids, 0);
}

#[tokio::test]
async fn test_fetch_unexportable_keys_dump() {
    let setup = setup_empty().await;
    let unexportable_keys_setup = add_unexportable_keys(&setup.db, setup.organisation_id).await;

    let temp = NamedTempFile::new().unwrap();
    setup.provider.copy_db_to(temp.path()).await.unwrap();
    let unexportable = setup
        .provider
        .fetch_unexportable(Some(temp.path()))
        .await
        .unwrap();

    assert_eq!(unexportable.total_keys, unexportable_keys_setup.total());
    assert_eq!(
        unexportable.keys.len(),
        unexportable_keys_setup.unexportable_ids.len()
    );
    assert_eq_unordered(
        unexportable.keys.into_iter().map(|item| item.id),
        unexportable_keys_setup.unexportable_ids,
    );
}

#[tokio::test]
async fn test_fetch_unexportable_credentials_dump() {
    let setup = setup_empty().await;
    let unexportable_keys_setup = add_unexportable_keys(&setup.db, setup.organisation_id).await;
    let unexportable_credentials_setup =
        add_unexportable_credentials(&setup.db, setup.organisation_id, &unexportable_keys_setup)
            .await;

    let temp = NamedTempFile::new().unwrap();
    setup.provider.copy_db_to(temp.path()).await.unwrap();
    let unexportable = setup
        .provider
        .fetch_unexportable(Some(temp.path()))
        .await
        .unwrap();

    assert_eq!(
        unexportable.total_credentials,
        unexportable_credentials_setup.total()
    );
    assert_eq!(
        unexportable.credentials.len(),
        unexportable_credentials_setup.unexportable_ids.len()
    );
    assert_eq_unordered(
        unexportable.credentials.into_iter().map(|item| item.id),
        unexportable_credentials_setup.unexportable_ids,
    );
}

#[tokio::test]
async fn test_fetch_unexportable_dids_dump() {
    let setup = setup_empty().await;
    let unexportable_keys_setup = add_unexportable_keys(&setup.db, setup.organisation_id).await;
    let unexportable_dids_setup =
        add_unexportable_dids(&setup.db, setup.organisation_id, &unexportable_keys_setup).await;

    let temp = NamedTempFile::new().unwrap();
    setup.provider.copy_db_to(temp.path()).await.unwrap();
    let unexportable = setup
        .provider
        .fetch_unexportable(Some(temp.path()))
        .await
        .unwrap();

    assert_eq!(unexportable.total_dids, unexportable_dids_setup.total());
    assert_eq!(
        unexportable.dids.len(),
        unexportable_dids_setup.unexportable_ids.len()
    );
    assert_eq_unordered(
        unexportable.dids.into_iter().map(|item| item.id),
        unexportable_dids_setup.unexportable_ids,
    );
}

#[tokio::test]
async fn test_fetch_unexportable_identifiers_dump() {
    let setup = setup_empty().await;
    let mut unexportable_keys_setup = add_unexportable_keys(&setup.db, setup.organisation_id).await;
    // add two more sets of unexportable keys for each of the 3 types of identifier
    for _ in 0..2 {
        unexportable_keys_setup.join(add_unexportable_keys(&setup.db, setup.organisation_id).await);
    }
    let unexportable_identifiers_setup =
        add_unexportable_identifiers(&setup.db, setup.organisation_id, &unexportable_keys_setup)
            .await;

    let temp = NamedTempFile::new().unwrap();
    setup.provider.copy_db_to(temp.path()).await.unwrap();
    let unexportable = setup
        .provider
        .fetch_unexportable(Some(temp.path()))
        .await
        .unwrap();

    assert_eq!(
        unexportable.total_identifiers,
        unexportable_identifiers_setup.total()
    );
    assert_eq!(
        unexportable.identifiers.len(),
        unexportable_identifiers_setup.unexportable_ids.len()
    );
    assert_eq_unordered(
        unexportable.identifiers.into_iter().map(|item| item.id),
        unexportable_identifiers_setup.unexportable_ids,
    );
}

#[tokio::test]
async fn test_delete_unexportable_no_records() {
    let setup = setup_empty().await;

    let temp = NamedTempFile::new().unwrap();
    setup.provider.copy_db_to(temp.path()).await.unwrap();
    setup
        .provider
        .delete_unexportable(temp.path())
        .await
        .unwrap();
}

#[tokio::test]
async fn test_delete_unexportable_keys() {
    let setup = setup_empty().await;
    let unexportable_keys_setup = add_unexportable_keys(&setup.db, setup.organisation_id).await;

    let temp = NamedTempFile::new().unwrap();
    setup.provider.copy_db_to(temp.path()).await.unwrap();
    setup
        .provider
        .delete_unexportable(temp.path())
        .await
        .unwrap();

    let db_dump = db_conn(
        format!("sqlite:{}?mode=rw", temp.path().to_string_lossy()),
        true,
    )
    .await
    .unwrap();
    let keys = key::Entity::find().all(&db_dump).await.unwrap();

    let all_deleted = keys
        .iter()
        .filter(|key| key.deleted_at.is_some())
        .map(|key| key.id);
    assert_eq_unordered(
        all_deleted,
        unexportable_keys_setup
            .unexportable_ids
            .into_iter()
            .chain(unexportable_keys_setup.deleted_ids),
    );

    let not_deleted = keys
        .iter()
        .filter(|key| key.deleted_at.is_none())
        .map(|key| key.id);
    assert_eq_unordered(not_deleted, unexportable_keys_setup.exportable_ids);
}

#[tokio::test]
async fn test_delete_unexportable_credentials() {
    let setup = setup_empty().await;
    let unexportable_keys_setup = add_unexportable_keys(&setup.db, setup.organisation_id).await;
    let unexportable_credentials_setup =
        add_unexportable_credentials(&setup.db, setup.organisation_id, &unexportable_keys_setup)
            .await;

    let temp = NamedTempFile::new().unwrap();
    setup.provider.copy_db_to(temp.path()).await.unwrap();
    setup
        .provider
        .delete_unexportable(temp.path())
        .await
        .unwrap();

    let db_dump = db_conn(
        format!("sqlite:{}?mode=rw", temp.path().to_string_lossy()),
        true,
    )
    .await
    .unwrap();
    let credentials = credential::Entity::find().all(&db_dump).await.unwrap();

    let all_deleted = credentials
        .iter()
        .filter(|credential| credential.deleted_at.is_some())
        .map(|credential| credential.id);
    assert_eq_unordered(
        all_deleted,
        unexportable_credentials_setup
            .unexportable_ids
            .into_iter()
            .chain(unexportable_credentials_setup.deleted_ids),
    );

    let not_deleted = credentials
        .iter()
        .filter(|credential| credential.deleted_at.is_none())
        .map(|credential| credential.id);
    assert_eq_unordered(not_deleted, unexportable_credentials_setup.exportable_ids);
}

#[tokio::test]
async fn test_delete_unexportable_dids() {
    let setup = setup_empty().await;
    let unexportable_keys_setup = add_unexportable_keys(&setup.db, setup.organisation_id).await;
    let unexportable_dids_setup =
        add_unexportable_dids(&setup.db, setup.organisation_id, &unexportable_keys_setup).await;

    let temp = NamedTempFile::new().unwrap();
    setup.provider.copy_db_to(temp.path()).await.unwrap();
    setup
        .provider
        .delete_unexportable(temp.path())
        .await
        .unwrap();

    let db_dump = db_conn(
        format!("sqlite:{}?mode=rw", temp.path().to_string_lossy()),
        true,
    )
    .await
    .unwrap();
    let dids = did::Entity::find().all(&db_dump).await.unwrap();

    let all_deleted = dids
        .iter()
        .filter(|did| did.deleted_at.is_some())
        .map(|did| did.id);
    assert_eq_unordered(
        all_deleted,
        unexportable_dids_setup
            .unexportable_ids
            .into_iter()
            .chain(unexportable_dids_setup.deleted_ids),
    );

    let not_deleted = dids
        .iter()
        .filter(|did| did.deleted_at.is_none())
        .map(|did| did.id);
    assert_eq_unordered(not_deleted, unexportable_dids_setup.exportable_ids);
}

#[tokio::test]
async fn test_delete_unexportable_identifiers() {
    let setup = setup_empty().await;
    let mut unexportable_keys_setup = add_unexportable_keys(&setup.db, setup.organisation_id).await;
    // add two more sets of unexportable keys for each of the 3 types of identifier
    for _ in 0..2 {
        unexportable_keys_setup.join(add_unexportable_keys(&setup.db, setup.organisation_id).await);
    }
    let unexportable_identifiers_setup =
        add_unexportable_identifiers(&setup.db, setup.organisation_id, &unexportable_keys_setup)
            .await;

    let temp = NamedTempFile::new().unwrap();
    setup.provider.copy_db_to(temp.path()).await.unwrap();
    setup
        .provider
        .delete_unexportable(temp.path())
        .await
        .unwrap();

    let db_dump = db_conn(
        format!("sqlite:{}?mode=rw", temp.path().to_string_lossy()),
        true,
    )
    .await
    .unwrap();
    let identifiers = identifier::Entity::find().all(&db_dump).await.unwrap();

    let all_deleted = identifiers
        .iter()
        .filter(|identifier| identifier.deleted_at.is_some())
        .map(|identifier| identifier.id);
    assert_eq_unordered(
        all_deleted,
        unexportable_identifiers_setup
            .unexportable_ids
            .into_iter()
            .chain(unexportable_identifiers_setup.deleted_ids),
    );

    let not_deleted = identifiers
        .iter()
        .filter(|indentifier| indentifier.deleted_at.is_none())
        .map(|identifier| identifier.id);
    assert_eq_unordered(not_deleted, unexportable_identifiers_setup.exportable_ids);
}
