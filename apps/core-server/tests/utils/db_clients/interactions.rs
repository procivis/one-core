use std::sync::Arc;

use one_core::model::interaction::{Interaction, InteractionId, InteractionType};
use one_core::model::organisation::Organisation;
use one_core::repository::interaction_repository::InteractionRepository;
use time::OffsetDateTime;
use uuid::Uuid;

pub struct InteractionsDB {
    repository: Arc<dyn InteractionRepository>,
}

impl InteractionsDB {
    pub fn new(repository: Arc<dyn InteractionRepository>) -> Self {
        Self { repository }
    }

    pub async fn create(
        &self,
        id: Option<Uuid>,
        data: &[u8],
        organisation: &Organisation,
        interaction_type: InteractionType,
    ) -> Interaction {
        let interaction = Interaction {
            id: id.unwrap_or_else(Uuid::new_v4),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            data: Some(data.into()),
            organisation: Some(organisation.to_owned()),
            nonce_id: None,
            interaction_type,
        };

        self.repository
            .create_interaction(interaction.to_owned())
            .await
            .unwrap();

        interaction
    }

    pub async fn get(&self, id: impl Into<InteractionId>) -> Option<Interaction> {
        self.repository
            .get_interaction(&id.into(), &Default::default(), None)
            .await
            .unwrap()
    }
}
