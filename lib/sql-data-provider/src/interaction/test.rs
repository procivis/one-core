use std::{str::FromStr, vec};

use one_core::{
    model::interaction::{Interaction, InteractionRelations},
    repository::interaction_repository::InteractionRepository,
};
use uuid::Uuid;

use crate::test_utilities::{
    get_dummy_date, get_interaction, insert_interaction, setup_test_data_layer_and_connection,
};

use super::InteractionProvider;

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
    pub provider: InteractionProvider,
    pub interaction_id: Uuid,
    pub host: String,
    pub data: Vec<u8>,
}

async fn setup_with_interaction() -> TestSetupWithInteraction {
    let setup = setup().await;

    let host = "host".to_string();
    let data = vec![1, 2, 3];

    let id = insert_interaction(&setup.db, &host, &data).await.unwrap();

    let id = Uuid::from_str(&id).unwrap();

    TestSetupWithInteraction {
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
        host: Some("host".to_owned()),
        data: Some(vec![1, 2, 3]),
    };

    let result = setup.provider.create_interaction(interaction).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), id);

    let model = get_interaction(&setup.db, &id).await.unwrap();
    assert_eq!(model.host, Some("host".to_owned()));
    assert_eq!(model.data, Some(vec![1, 2, 3]));
}

#[tokio::test]
async fn test_get_interaction() {
    let setup = setup_with_interaction().await;

    let result = setup
        .provider
        .get_interaction(&setup.interaction_id, &InteractionRelations::default())
        .await;

    assert!(result.is_ok());

    let interaction = result.unwrap();

    assert_eq!(interaction.data, Some(setup.data));
    assert_eq!(interaction.host, Some(setup.host));
}
