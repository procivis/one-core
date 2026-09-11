use std::sync::Arc;

use one_core::model::interaction::{Interaction, InteractionEcosystems, InteractionType};
use one_core::model::organisation::Organisation;
use one_core::repository::error::DataLayerError;
use one_core::repository::interaction_repository::InteractionRepository;
use shared_types::{EcosystemId, InteractionId};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Default)]
pub struct TestingInteractionParams {
    pub id: Option<InteractionId>,
    pub data: Option<Vec<u8>>,
    pub created_date: Option<OffsetDateTime>,
    pub last_modified: Option<OffsetDateTime>,
    pub expires_at: Option<OffsetDateTime>,
    pub ecosystem: Option<EcosystemId>,
    pub ecosystem_data: InteractionEcosystems,
}

pub struct InteractionsDB {
    repository: Arc<dyn InteractionRepository>,
}

impl InteractionsDB {
    pub fn new(repository: Arc<dyn InteractionRepository>) -> Self {
        Self { repository }
    }

    pub async fn create(
        &self,
        organisation: &Organisation,
        interaction_type: InteractionType,
        params: TestingInteractionParams,
    ) -> Interaction {
        let interaction = Interaction {
            id: params.id.unwrap_or(Uuid::new_v4().into()),
            created_date: params.created_date.unwrap_or(one_core::clock::now_utc()),
            last_modified: params.last_modified.unwrap_or(one_core::clock::now_utc()),
            data: params.data,
            organisation: organisation.to_owned().into(),
            interaction_type,
            expires_at: params.expires_at,
            ecosystem: params.ecosystem,
            ecosystem_data: params.ecosystem_data,
        };

        self.repository
            .create_interaction(interaction.to_owned())
            .await
            .unwrap();

        interaction
    }

    pub async fn get(&self, id: impl Into<InteractionId>) -> Option<Interaction> {
        match self.repository.get_interaction(&id.into(), None).await {
            Ok(interaction) => Some(interaction),
            Err(DataLayerError::EntityNotFound { .. }) => None,
            Err(err) => panic!("get interaction: {err}"),
        }
    }
}
