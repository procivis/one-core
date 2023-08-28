use crate::{did::DidProvider, test_utilities::*};
use one_core::model::{
    did::{DidId, DidValue},
    organisation::OrganisationId,
};
use uuid::Uuid;

pub(crate) struct TestSetup {
    pub provider: DidProvider,
    pub organisation_id: OrganisationId,
    pub db: sea_orm::DatabaseConnection,
}

pub(crate) async fn setup_empty() -> TestSetup {
    let data_layer = setup_test_data_provider_and_connection().await.unwrap();
    let db = data_layer.db;

    let organisation_id = insert_organisation_to_database(&db, None).await.unwrap();

    TestSetup {
        provider: DidProvider { db: db.clone() },
        organisation_id: Uuid::parse_str(&organisation_id).unwrap(),
        db,
    }
}

pub(crate) struct TestSetupWithDid {
    pub provider: DidProvider,
    pub did_name: String,
    pub did_value: DidValue,
    pub did_id: DidId,
    pub organisation_id: OrganisationId,
}

pub(crate) async fn setup_with_did() -> TestSetupWithDid {
    let TestSetup {
        provider,
        organisation_id,
        db,
    } = setup_empty().await;

    let did_name = "test did name";
    let did_value = "test:did";
    let did_id = Uuid::parse_str(
        &insert_did(&db, did_name, did_value, &organisation_id.to_string())
            .await
            .unwrap(),
    )
    .unwrap();

    TestSetupWithDid {
        provider,
        organisation_id,
        did_id,
        did_value: did_value.to_string(),
        did_name: did_name.to_string(),
    }
}
