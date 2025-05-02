use std::str::FromStr;

use one_core::model::did::Did;
use one_core::model::identifier::{Identifier, IdentifierStatus, IdentifierType};
use one_core::model::organisation::Organisation;
use one_core::repository::identifier_repository::IdentifierRepository;
use shared_types::DidValue;
use uuid::Uuid;

use super::IdentifierProvider;
use crate::test_utilities::{
    dummy_organisation, get_dummy_date, insert_did_key, insert_organisation_to_database,
    setup_test_data_layer_and_connection,
};

struct TestSetup {
    pub provider: IdentifierProvider,
    pub organisation: Organisation,
    pub did: Did,
}

async fn setup() -> TestSetup {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;

    let organisation_id = insert_organisation_to_database(&db, None, None)
        .await
        .unwrap();
    let organisation = dummy_organisation(Some(organisation_id));

    let did_id = insert_did_key(
        &db,
        "test_did",
        Uuid::new_v4(),
        DidValue::from_str("did:test:123").unwrap(),
        "KEY",
        organisation_id,
    )
    .await
    .unwrap();

    let did = Did {
        id: did_id,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        name: "test_did".to_string(),
        did: DidValue::from_str("did:test:123").unwrap(),
        did_type: one_core::model::did::DidType::Local,
        did_method: "KEY".to_string(),
        deactivated: false,
        log: None,
        keys: None,
        organisation: Some(organisation.clone()),
    };

    TestSetup {
        provider: IdentifierProvider { db: db.clone() },
        organisation,
        did,
    }
}

#[tokio::test]
async fn test_create_and_delete_identifier() {
    let setup = setup().await;
    let id = Uuid::new_v4().into();

    let identifier = Identifier {
        id,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        name: "test_identifier".to_string(),
        r#type: IdentifierType::Did,
        is_remote: false,
        status: IdentifierStatus::Active,
        organisation: Some(setup.organisation),
        did: Some(setup.did),
        key: None,
    };

    assert_eq!(id, setup.provider.create(identifier).await.unwrap());

    setup.provider.delete(&id).await.unwrap();
}
