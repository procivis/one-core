use std::time::Duration;

use one_core::model::credential::CredentialStateEnum;
use one_core::model::validity_credential::{Lvvc, ValidityCredential, ValidityCredentialType};
use one_core::repository::validity_credential_repository::ValidityCredentialRepository;
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait, IntoActiveModel};
use shared_types::CredentialId;
use similar_asserts::assert_eq;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::entity::did::DidType;
use crate::entity::validity_credential;
use crate::validity_credential::ValidityCredentialProvider;
use crate::{db_conn, test_utilities};

#[tokio::test]
async fn test_insert_lvvc() {
    let db_conn = db_conn("sqlite::memory:", true).await.unwrap();
    let provider = ValidityCredentialProvider::new(db_conn.clone());

    let credential_id = create_and_store_credential(&db_conn).await;

    let lvvc = Lvvc {
        id: Uuid::new_v4(),
        created_date: OffsetDateTime::now_utc(),
        credential: vec![1, 2, 3],
        linked_credential_id: credential_id,
    };

    provider.insert(lvvc.clone().into()).await.unwrap();

    let lvvc_model = validity_credential::Entity::find_by_id(lvvc.id)
        .one(&db_conn)
        .await
        .unwrap()
        .map(ValidityCredential::try_from)
        .unwrap()
        .unwrap();

    assert_eq!(lvvc, Lvvc::try_from(lvvc_model).unwrap())
}

#[tokio::test]
async fn test_get_latest_lvvc_by_credential_id() {
    let db_conn = db_conn("sqlite::memory:", true).await.unwrap();
    let provider = ValidityCredentialProvider::new(db_conn.clone());

    let credential_id = create_and_store_credential(&db_conn).await;
    let lvvcs = create_lvvcs_for(credential_id, &db_conn).await;

    let latest_lvvc = provider
        .get_latest_by_credential_id(credential_id, ValidityCredentialType::Lvvc)
        .await
        .unwrap()
        .unwrap()
        .try_into()
        .unwrap();

    assert_eq!(
        lvvcs.iter().max_by_key(|v| v.created_date).unwrap(),
        &latest_lvvc
    )
}

#[tokio::test]
async fn test_get_all_lvvc_by_credential_id() {
    let db_conn = db_conn("sqlite::memory:", true).await.unwrap();
    let provider = ValidityCredentialProvider::new(db_conn.clone());

    let credential_id = create_and_store_credential(&db_conn).await;

    let mut expected_lvvcs = create_lvvcs_for(credential_id, &db_conn).await;
    expected_lvvcs.sort_by_key(|v| v.created_date);

    let mut lvvc = provider
        .get_all_by_credential_id(credential_id, ValidityCredentialType::Lvvc)
        .await
        .unwrap()
        .into_iter()
        .map(Lvvc::try_from)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    lvvc.sort_by_key(|v| v.created_date);

    assert_eq!(expected_lvvcs, lvvc)
}

async fn create_lvvcs_for(credential_id: CredentialId, db_conn: &DatabaseConnection) -> Vec<Lvvc> {
    let now = OffsetDateTime::now_utc();
    let lvvcs = vec![
        Lvvc {
            id: Uuid::new_v4(),
            created_date: now,
            credential: b"credential-1".into(),
            linked_credential_id: credential_id,
        },
        Lvvc {
            id: Uuid::new_v4(),
            created_date: now + Duration::from_secs(60),
            credential: b"credential-2".into(),
            linked_credential_id: credential_id,
        },
    ];

    for lvvc in &lvvcs {
        let validity_credential: ValidityCredential = lvvc.clone().into();
        validity_credential::Model::from(validity_credential)
            .into_active_model()
            .insert(db_conn)
            .await
            .unwrap();
    }

    lvvcs
}

async fn create_and_store_credential(db_conn: &DatabaseConnection) -> CredentialId {
    // organisation
    let organisation_id = test_utilities::insert_organisation_to_database(db_conn, None, None)
        .await
        .unwrap();

    // credential schema
    let credential_schema_id = test_utilities::insert_credential_schema_to_database(
        db_conn,
        None,
        organisation_id,
        "credential-schema",
        "jwt",
        "LVVC",
    )
    .await
    .unwrap();

    // did
    let did_id = test_utilities::insert_did(
        db_conn,
        "did-test",
        Uuid::new_v4().into(),
        "did:example:123".parse().unwrap(),
        organisation_id,
        "web",
        DidType::Remote,
        None,
    )
    .await
    .unwrap();

    let identifier_id = test_utilities::insert_identifier(
        db_conn,
        "identifier",
        Uuid::new_v4(),
        Some(did_id),
        organisation_id,
        true,
    )
    .await
    .unwrap();

    // credential
    test_utilities::insert_credential(
        db_conn,
        &credential_schema_id,
        CredentialStateEnum::Created,
        "OPENID4VCI_DRAFT13",
        identifier_id,
        None,
        None,
        Uuid::new_v4().into(),
    )
    .await
    .unwrap()
    .id
}
