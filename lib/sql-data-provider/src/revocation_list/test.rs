use std::sync::Arc;
use std::vec;

use one_core::model::credential::CredentialStateEnum;
use one_core::model::identifier::{Identifier, IdentifierState, IdentifierType};
use one_core::model::revocation_list::{
    RevocationList, RevocationListEntityId, RevocationListEntityInfo, RevocationListEntry,
    RevocationListEntryStatus, RevocationListPurpose, StatusListCredentialFormat, StatusListType,
};
use one_core::repository::error::DataLayerError;
use one_core::repository::identifier_repository::MockIdentifierRepository;
use one_core::repository::revocation_list_repository::RevocationListRepository;
use shared_types::{CredentialId, RevocationListId};
use similar_asserts::assert_eq;
use uuid::Uuid;

use super::RevocationListProvider;
use crate::entity::credential_schema::KeyStorageSecurity;
use crate::entity::revocation_list::RevocationListFormat;
use crate::test_utilities::{
    dummy_organisation, get_dummy_date, insert_credential, insert_credential_schema_to_database,
    insert_identifier, insert_organisation_to_database, insert_revocation_list,
    insert_revocation_list_entry, setup_test_data_layer_and_connection,
};
use crate::transaction_context::TransactionManagerImpl;

struct TestSetup {
    pub provider: RevocationListProvider,
    pub db: sea_orm::DatabaseConnection,
    pub identifier: Identifier,
}

async fn setup() -> TestSetup {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;

    let organisation_id = insert_organisation_to_database(&db, None, None)
        .await
        .unwrap();

    let identifier_id =
        insert_identifier(&db, "issuer", Uuid::new_v4(), None, organisation_id, false)
            .await
            .unwrap();

    let identifier = Identifier {
        id: identifier_id,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        name: "name".to_string(),
        r#type: IdentifierType::Did,
        is_remote: false,
        state: IdentifierState::Active,
        deleted_at: None,
        organisation: Some(dummy_organisation(Some(organisation_id))),
        did: None,
        key: None,
        certificates: None,
    };

    TestSetup {
        provider: RevocationListProvider {
            db: TransactionManagerImpl::new(db.clone()),
            identifier_repository: Arc::new(MockIdentifierRepository::default()),
        },
        db,
        identifier,
    }
}

struct TestSetupWithList {
    pub provider: RevocationListProvider,
    pub db: sea_orm::DatabaseConnection,
    pub identifier: Identifier,
    pub list_id: RevocationListId,
}

async fn setup_with_list() -> TestSetupWithList {
    let TestSetup {
        provider,
        db,
        identifier,
    } = setup().await;

    let list_id = insert_revocation_list(
        &db,
        RevocationListPurpose::Revocation.into(),
        RevocationListFormat::Jwt,
        identifier.id,
        StatusListType::BitstringStatusList.to_string(),
    )
    .await
    .unwrap();

    TestSetupWithList {
        provider,
        db,
        identifier,
        list_id,
    }
}

#[tokio::test]
async fn test_create_revocation_list() {
    let setup = setup().await;

    let id = Uuid::new_v4().into();
    let result = setup
        .provider
        .create_revocation_list(RevocationList {
            id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            credentials: vec![],
            format: StatusListCredentialFormat::Jwt,
            r#type: StatusListType::BitstringStatusList,
            purpose: RevocationListPurpose::Revocation,
            issuer_identifier: Some(setup.identifier),
        })
        .await
        .unwrap();
    assert_eq!(id, result);
}

#[tokio::test]
async fn test_get_revocation_list() {
    let setup = setup_with_list().await;

    let result = setup
        .provider
        .get_revocation_list(&setup.list_id, &Default::default())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(setup.list_id, result.id);
}

#[tokio::test]
async fn test_get_revocation_by_issuer_identifier_id() {
    let setup = setup_with_list().await;

    let result = setup
        .provider
        .get_revocation_by_issuer_identifier_id(
            setup.identifier.id,
            RevocationListPurpose::Revocation,
            StatusListType::BitstringStatusList,
            &Default::default(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(setup.list_id, result.id);
}

#[tokio::test]
async fn test_update_credentials() {
    let setup = setup_with_list().await;

    setup
        .provider
        .update_credentials(&setup.list_id, vec![])
        .await
        .unwrap();
}

#[tokio::test]
async fn test_next_free_index_empty_list() {
    let setup = setup_with_list().await;

    let result = setup
        .provider
        .next_free_index(&setup.list_id, None)
        .await
        .unwrap();
    assert_eq!(result, 0);
}

#[tokio::test]
async fn test_next_free_index_list_with_entry() {
    let setup = setup_with_list().await;

    insert_revocation_list_entry(&setup.db, setup.list_id, 0, None)
        .await
        .unwrap();

    let result = setup
        .provider
        .next_free_index(&setup.list_id, None)
        .await
        .unwrap();
    assert_eq!(result, 1);
}

#[tokio::test]
async fn test_next_free_index_wrong_list_id() {
    let setup = setup_with_list().await;

    let result = setup
        .provider
        .next_free_index(&Uuid::new_v4().into(), None)
        .await;

    assert!(matches!(
        result,
        Err(DataLayerError::MissingRequiredRelation {
            relation: "revocation_list",
            ..
        })
    ));
}

#[tokio::test]
async fn test_create_credential_entry() {
    let setup = setup_with_list().await;

    let credential_id = create_dummy_credential(&setup.db, setup.identifier).await;

    setup
        .provider
        .create_entry(
            setup.list_id,
            RevocationListEntityId::Credential(credential_id),
            0,
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn test_get_entries_empty_list() {
    let setup = setup_with_list().await;

    let results = setup.provider.get_entries(setup.list_id).await.unwrap();
    assert_eq!(results.len(), 0);
}

#[tokio::test]
async fn test_get_entries_non_empty() {
    let setup = setup_with_list().await;

    insert_revocation_list_entry(&setup.db, setup.list_id, 1, None)
        .await
        .unwrap();

    let credential_id = create_dummy_credential(&setup.db, setup.identifier).await;
    insert_revocation_list_entry(&setup.db, setup.list_id, 2, Some(credential_id))
        .await
        .unwrap();

    let results = setup.provider.get_entries(setup.list_id).await.unwrap();
    assert_eq!(results.len(), 2);
    assert_eq!(
        results[0],
        RevocationListEntry {
            entity_info: RevocationListEntityInfo::WalletUnitAttestedKey,
            index: 1,
            status: RevocationListEntryStatus::Active,
        }
    );
    assert_eq!(
        results[1],
        RevocationListEntry {
            entity_info: RevocationListEntityInfo::Credential(credential_id),
            index: 2,
            status: RevocationListEntryStatus::Active,
        }
    );
}

async fn create_dummy_credential(
    db: &sea_orm::DatabaseConnection,
    identifier: Identifier,
) -> CredentialId {
    let organisation = identifier.organisation.to_owned().unwrap();

    let credential_schema_name = "schema";
    let credential_schema_id = insert_credential_schema_to_database(
        db,
        None,
        organisation.id,
        credential_schema_name,
        "JWT",
        "NONE",
        Some(KeyStorageSecurity::Basic),
    )
    .await
    .unwrap();

    let credential = insert_credential(
        db,
        &credential_schema_id,
        CredentialStateEnum::Created,
        "OPENID4VCI_DRAFT13",
        identifier.id,
        None,
        None,
        Uuid::new_v4().into(),
    )
    .await
    .unwrap();

    credential.id
}
