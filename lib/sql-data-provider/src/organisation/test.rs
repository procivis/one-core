use sea_orm::EntityTrait;
use time::OffsetDateTime;
use uuid::Uuid;

use one_core::model;

use crate::entity::Organisation;
use crate::test_utilities::*;

#[tokio::test]
async fn create_organisation_id_provided() {
    let data_layer = setup_test_data_layer_and_connection().await;

    let org_id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();

    let organisation = model::organisation::Organisation {
        id: org_id,
        created_date: now,
        last_modified: now,
    };

    let response = data_layer
        .organisation_repository
        .create_organisation(organisation)
        .await;
    assert!(response.is_ok());
    assert_eq!(response.unwrap(), org_id);

    assert_eq!(
        Organisation::find()
            .all(&data_layer.db)
            .await
            .unwrap()
            .len(),
        1
    );
}

// #[cfg(test)]
// mod tests {
//     use crate::test_utilities::*;
//     use one_core::repository::error::DataLayerError;
//     use uuid::Uuid;

//     #[tokio::test]
//     async fn test_get_organisations() {
//         let data_layer = setup_test_data_layer_and_connection().await.unwrap();

//         let org_uuid = Uuid::new_v4();

//         insert_organisation_to_database(&data_layer.db, Some(org_uuid))
//             .await
//             .unwrap();

//         let details = data_layer
//             .get_organisation_details(&org_uuid.to_string())
//             .await;

//         assert!(details.is_ok());
//         assert_eq!(details.unwrap().id, org_uuid.to_string());
//     }

//     #[tokio::test]
//     async fn test_get_not_existing_organisation() {
//         let data_layer = setup_test_data_layer_and_connection().await.unwrap();

//         let org_uuid = Uuid::new_v4();

//         let details = data_layer
//             .get_organisation_details(&org_uuid.to_string())
//             .await;

//         assert!(details.is_err());
//         assert_eq!(details, Err(DataLayerError::RecordNotFound));
//     }
// }

// #[cfg(test)]
// mod tests {
//     use crate::test_utilities::*;
//     use uuid::Uuid;

//     #[tokio::test]
//     async fn test_get_organisations() {
//         let data_layer = setup_test_data_layer_and_connection().await.unwrap();

//         let details = data_layer.get_organisations().await;
//         assert!(details.is_ok());
//         assert_eq!(details.unwrap().len(), 0);

//         let uuid = [Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];

//         insert_organisation_to_database(&data_layer.db, Some(uuid[0]))
//             .await
//             .unwrap();

//         let details = data_layer.get_organisations().await;
//         assert!(details.is_ok());
//         assert_eq!(details.as_ref().unwrap().len(), 1);
//         assert_eq!(details.unwrap()[0].id, uuid[0]);

//         insert_organisation_to_database(&data_layer.db, Some(uuid[1]))
//             .await
//             .unwrap();
//         insert_organisation_to_database(&data_layer.db, Some(uuid[2]))
//             .await
//             .unwrap();

//         let details = data_layer.get_organisations().await;
//         assert!(details.is_ok());
//         assert_eq!(details.as_ref().unwrap().len(), 3);
//         assert!(details.unwrap().iter().all(|org| uuid.contains(&org.id)));
//     }
// }
