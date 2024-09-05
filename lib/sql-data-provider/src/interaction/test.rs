use std::str::FromStr;
use std::vec;

use one_core::model::interaction::{Interaction, InteractionRelations};
use one_core::repository::interaction_repository::InteractionRepository;
use sea_orm::DbErr;
use url::Url;
use uuid::Uuid;

use super::InteractionProvider;
use crate::test_utilities::{
    get_dummy_date, get_interaction, insert_interaction, setup_test_data_layer_and_connection,
};

struct TestSetup {
    pub provider: InteractionProvider,
    pub db: sea_orm::DatabaseConnection,
}

async fn setup() -> TestSetup {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;

    TestSetup {
        provider: InteractionProvider { db: db.clone() },
        db,
    }
}

struct TestSetupWithInteraction {
    pub db: sea_orm::DatabaseConnection,
    pub provider: InteractionProvider,
    pub interaction_id: Uuid,
    pub host: Url,
    pub data: Vec<u8>,
}

async fn setup_with_interaction() -> TestSetupWithInteraction {
    let setup = setup().await;

    let host: Url = "http://www.host.co".parse().unwrap();
    let data = vec![1, 2, 3];

    let id = insert_interaction(&setup.db, host.as_str(), &data)
        .await
        .unwrap();

    let id = Uuid::from_str(&id).unwrap();

    TestSetupWithInteraction {
        db: setup.db,
        provider: setup.provider,
        interaction_id: id,
        host,
        data,
    }
}

#[tokio::test]
async fn test_create_interaction() {
    let setup = setup().await;

    let id = Uuid::new_v4();
    let interaction = Interaction {
        id,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        host: Some("http://www.host.co".parse().unwrap()),
        data: Some(vec![1, 2, 3]),
    };

    let result = setup.provider.create_interaction(interaction).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), id);

    let model = get_interaction(&setup.db, &id).await.unwrap();
    assert_eq!(model.host, Some("http://www.host.co/".to_owned()));
    assert_eq!(model.data, Some(vec![1, 2, 3]));
}

#[tokio::test]
async fn test_get_interaction() {
    let setup = setup_with_interaction().await;

    let result = setup
        .provider
        .get_interaction(&setup.interaction_id, &InteractionRelations::default())
        .await
        .unwrap();

    let interaction = result.unwrap();

    assert_eq!(interaction.data, Some(setup.data));
    assert_eq!(interaction.host, Some(setup.host));
}

#[tokio::test]
async fn test_delete_interaction() {
    let setup = setup_with_interaction().await;

    let result = setup
        .provider
        .delete_interaction(&setup.interaction_id)
        .await;

    assert!(result.is_ok());

    let result = get_interaction(&setup.db, &setup.interaction_id).await;

    assert!(matches!(result, Err(DbErr::RecordNotFound(_))));
}
