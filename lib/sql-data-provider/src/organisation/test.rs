use one_core::model::common::SortDirection;
use one_core::model::list_query::{ListPagination, ListSorting};
use one_core::model::organisation::{
    Organisation, OrganisationListQuery, OrganisationRelations, SortableOrganisationColumn,
    UpdateOrganisationRequest,
};
use one_core::repository::organisation_repository::OrganisationRepository;
use sea_orm::{DatabaseConnection, EntityTrait};
use similar_asserts::assert_eq;
use time::OffsetDateTime;
use uuid::Uuid;

use super::OrganisationProvider;
use crate::test_utilities::*;
use crate::transaction_context::TransactionManagerImpl;

struct TestSetup {
    pub db: DatabaseConnection,
    pub repository: Box<dyn OrganisationRepository>,
}

async fn setup() -> TestSetup {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;
    TestSetup {
        repository: Box::new(OrganisationProvider {
            db: TransactionManagerImpl::new(db.clone()),
        }),
        db,
    }
}

#[tokio::test]
async fn test_create_organisation() {
    let TestSetup { db, repository } = setup().await;

    let org_id = Uuid::new_v4().into();
    let now = OffsetDateTime::now_utc();

    let organisation = Organisation {
        id: org_id,
        name: org_id.to_string(),
        created_date: now,
        last_modified: now,
        deactivated_at: None,
        wallet_provider: None,
        wallet_provider_issuer: None,
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
        .get_organisation(&Uuid::new_v4().into(), &OrganisationRelations::default())
        .await;
    assert!(matches!(result, Ok(None)));
}

#[tokio::test]
async fn test_get_organisation_success() {
    let TestSetup { repository, db } = setup().await;

    let org_id = Uuid::new_v4().into();
    insert_organisation_to_database(&db, Some(org_id), None)
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

    let org_id = Uuid::new_v4().into();
    insert_organisation_to_database(&db, Some(org_id), None)
        .await
        .unwrap();

    let org2_id = Uuid::new_v4().into();
    insert_organisation_to_database(&db, Some(org2_id), None)
        .await
        .unwrap();

    let result = repository
        .get_organisation_list(OrganisationListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 5,
            }),
            sorting: Some(ListSorting {
                column: SortableOrganisationColumn::CreatedDate,
                direction: Some(SortDirection::Ascending),
            }),
            ..Default::default()
        })
        .await;

    assert!(result.is_ok());
    let organisations = result.unwrap();
    assert_eq!(organisations.total_pages, 1);
    assert_eq!(organisations.total_items, 2);
    assert_eq!(organisations.values.len(), 2);
    assert_eq!(organisations.values[0].id, org_id);
    assert_eq!(organisations.values[1].id, org2_id);
}

#[tokio::test]
async fn test_update_organisation() {
    let TestSetup { db, repository } = setup().await;

    let org_id = Uuid::new_v4().into();
    insert_organisation_to_database(&db, Some(org_id), None)
        .await
        .unwrap();

    let request = UpdateOrganisationRequest {
        id: org_id,
        name: Some("name".to_string()),
        deactivate: None,
        wallet_provider: None,
        wallet_provider_issuer: None,
    };

    let result = repository.update_organisation(request).await;
    assert!(result.is_ok());

    let organisations = crate::entity::organisation::Entity::find()
        .all(&db)
        .await
        .unwrap();
    assert_eq!(organisations.len(), 1);
    assert_eq!(organisations[0].name, "name");
    // last_modified has been updated
    assert!(organisations[0].last_modified > organisations[0].created_date);
}
