use super::OrganisationProvider;
use crate::test_utilities::*;
use one_core::{
    model::organisation::{Organisation, OrganisationRelations},
    repository::organisation_repository::OrganisationRepository,
};
use sea_orm::{DatabaseConnection, EntityTrait};
use time::OffsetDateTime;
use uuid::Uuid;

struct TestSetup {
    pub db: DatabaseConnection,
    pub repository: Box<dyn OrganisationRepository>,
}

async fn setup() -> TestSetup {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;
    TestSetup {
        repository: Box::new(OrganisationProvider { db: db.clone() }),
        db,
    }
}

#[tokio::test]
async fn test_create_organisation() {
    let TestSetup { db, repository } = setup().await;

    let org_id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();

    let organisation = Organisation {
        id: org_id,
        created_date: now,
        last_modified: now,
    };

    let result = repository.create_organisation(organisation).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), org_id);

    assert_eq!(
        crate::entity::organisation::Entity::find()
            .all(&db)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn test_get_organisation_missing() {
    let TestSetup { repository, .. } = setup().await;

    let result = repository
        .get_organisation(&Uuid::new_v4(), &OrganisationRelations::default())
        .await;
    assert!(matches!(result, Ok(None)));
}

#[tokio::test]
async fn test_get_organisation_success() {
    let TestSetup { repository, db } = setup().await;

    let org_id = Uuid::new_v4();
    insert_organisation_to_database(&db, Some(org_id))
        .await
        .unwrap();

    let result = repository
        .get_organisation(&org_id, &OrganisationRelations::default())
        .await;

    assert!(result.is_ok());
    let organisation = result.unwrap().unwrap();
    assert_eq!(organisation.id, org_id);
}

#[tokio::test]
async fn test_get_organisation_list() {
    let TestSetup { repository, db } = setup().await;

    let org_id = Uuid::new_v4();
    insert_organisation_to_database(&db, Some(org_id))
        .await
        .unwrap();

    let result = repository.get_organisation_list().await;

    assert!(result.is_ok());
    let organisations = result.unwrap();
    assert_eq!(organisations.len(), 1);
    assert_eq!(organisations[0].id, org_id);
}
