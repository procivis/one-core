use std::sync::Arc;
use std::vec;

use one_core::error::ErrorCode;
use one_core::model::ecosystem::EcosystemOutcomes;
use one_core::model::history::HistoryErrorMetadata;
use one_core::model::interaction::{
    Interaction, InteractionEcosystems, InteractionType, UpdateInteractionRequest,
};
use one_core::repository::error::DataLayerError;
use one_core::repository::interaction_repository::InteractionRepository;
use one_core::repository::key_repository::MockKeyRepository;
use one_core::repository::organisation_repository::MockOrganisationRepository;
use sea_orm::DbErr;
use shared_types::{EcosystemId, InteractionId};
use similar_asserts::assert_eq;
use uuid::Uuid;

use super::InteractionProvider;
use crate::test_utilities::{
    dummy_organisation, get_dummy_date, get_interaction, insert_interaction,
    insert_organisation_to_database, insert_used_nonce, setup_test_data_layer_and_connection,
};
use crate::transaction_context::TransactionManagerImpl;

#[derive(Default)]
struct Repositories {
    pub organisation_repository: MockOrganisationRepository,
    pub key_repository: MockKeyRepository,
}

struct TestSetup {
    pub provider: InteractionProvider,
    pub db: sea_orm::DatabaseConnection,
}

async fn setup(repositories: Repositories) -> TestSetup {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;

    TestSetup {
        provider: InteractionProvider {
            db: TransactionManagerImpl::new(db.clone()),
            organisation_repository: Arc::from(repositories.organisation_repository),
            key_repository: Arc::from(repositories.key_repository),
        },
        db,
    }
}

struct TestSetupWithInteraction {
    pub db: sea_orm::DatabaseConnection,
    pub provider: InteractionProvider,
    pub interaction_id: InteractionId,
    pub data: Vec<u8>,
}

async fn setup_with_interaction() -> TestSetupWithInteraction {
    let setup = setup(Repositories::default()).await;

    let data = vec![1, 2, 3];

    let organisation_id = insert_organisation_to_database(&setup.db, None)
        .await
        .unwrap();

    let id = insert_interaction(
        &setup.db,
        &data,
        organisation_id,
        crate::entity::interaction::InteractionType::Issuance,
    )
    .await
    .unwrap();

    TestSetupWithInteraction {
        db: setup.db,
        provider: setup.provider,
        interaction_id: id,
        data,
    }
}

#[tokio::test]
async fn test_create_interaction() {
    let setup = setup(Repositories::default()).await;
    let organisation_id = insert_organisation_to_database(&setup.db, None)
        .await
        .unwrap();

    let organisation = dummy_organisation(Some(organisation_id));

    let id = Uuid::new_v4().into();
    let interaction = Interaction {
        dpop_key: None,
        id,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        data: Some(vec![1, 2, 3]),
        organisation: organisation.into(),
        interaction_type: InteractionType::Issuance,
        expires_at: None,
        ecosystem: None,
        ecosystem_data: Default::default(),
    };

    let result = setup.provider.create_interaction(interaction).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), id);

    let model = get_interaction(&setup.db, &id).await.unwrap();
    assert_eq!(model.data, Some(vec![1, 2, 3]));
}

#[tokio::test]
async fn test_get_interaction() {
    let setup = setup_with_interaction().await;

    let interaction = setup
        .provider
        .get_interaction(&setup.interaction_id, None)
        .await
        .unwrap();

    assert_eq!(interaction.data, Some(setup.data));
}

#[tokio::test]
async fn test_mark_nonces_as_used_success() {
    let setup = setup(Repositories::default()).await;

    let organisation_id = insert_organisation_to_database(&setup.db, None)
        .await
        .unwrap();
    let interaction_id = insert_interaction(
        &setup.db,
        &[],
        organisation_id,
        crate::entity::interaction::InteractionType::Issuance,
    )
    .await
    .unwrap();

    let nonce_id = Uuid::new_v4().into();
    setup
        .provider
        .mark_nonces_as_used(&interaction_id, vec![nonce_id])
        .await
        .unwrap();
}

#[tokio::test]
async fn test_mark_nonces_as_used_already_used() {
    let setup = setup(Repositories::default()).await;

    let organisation_id = insert_organisation_to_database(&setup.db, None)
        .await
        .unwrap();
    let nonce_id = Uuid::new_v4().into();
    let interaction_id = insert_interaction(
        &setup.db,
        &[],
        organisation_id,
        crate::entity::interaction::InteractionType::Issuance,
    )
    .await
    .unwrap();

    insert_used_nonce(&setup.db, nonce_id, interaction_id)
        .await
        .unwrap();

    let result = setup
        .provider
        .mark_nonces_as_used(&interaction_id, vec![nonce_id])
        .await;
    assert!(matches!(result, Err(DataLayerError::AlreadyExists(_))));
}

#[tokio::test]
async fn test_mark_nonces_as_used_already_used_different_interaction() {
    let setup = setup(Repositories::default()).await;

    let organisation_id = insert_organisation_to_database(&setup.db, None)
        .await
        .unwrap();
    let nonce_id = Uuid::new_v4().into();
    let other_interaction_id = insert_interaction(
        &setup.db,
        &[],
        organisation_id,
        crate::entity::interaction::InteractionType::Issuance,
    )
    .await
    .unwrap();
    insert_used_nonce(&setup.db, nonce_id, other_interaction_id)
        .await
        .unwrap();

    let interaction_id = insert_interaction(
        &setup.db,
        &[],
        organisation_id,
        crate::entity::interaction::InteractionType::Issuance,
    )
    .await
    .unwrap();

    let result = setup
        .provider
        .mark_nonces_as_used(&interaction_id, vec![nonce_id])
        .await;
    assert!(matches!(result, Err(DataLayerError::AlreadyExists(_))));
}

#[tokio::test]
async fn test_update_interaction() {
    let setup = setup_with_interaction().await;

    let data = "foo".as_bytes().to_vec();
    setup
        .provider
        .update_interaction(
            setup.interaction_id,
            UpdateInteractionRequest {
                data: Some(Some(data.clone())),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let result = get_interaction(&setup.db, &setup.interaction_id)
        .await
        .unwrap();
    assert_eq!(result.data, Some(data));
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

#[tokio::test]
async fn test_update_interaction_ecosystem_outcomes() {
    let setup = setup_with_interaction().await;

    let mut outcomes = EcosystemOutcomes::default();
    outcomes.record(EcosystemId::from("EUDI"), Ok(()));
    outcomes.record(
        EcosystemId::from("OTHER"),
        Err(HistoryErrorMetadata {
            error_code: ErrorCode::BR_0477,
            message: "rejected".to_string(),
        }),
    );

    let mut ecosystem_data = InteractionEcosystems::default();
    ecosystem_data.merge_outcomes(&outcomes);

    setup
        .provider
        .update_interaction(
            setup.interaction_id,
            UpdateInteractionRequest {
                ecosystem_data: Some(ecosystem_data),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let result = setup
        .provider
        .get_interaction(&setup.interaction_id, None)
        .await
        .unwrap();
    assert_eq!(&outcomes, result.ecosystem_data.outcomes());
    // no ecosystem left is a result, not the same as no step having run
    assert_eq!(
        vec![EcosystemId::from("EUDI")],
        result.ecosystem_data.outcomes().applicable()
    );
}
