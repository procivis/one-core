use std::sync::Arc;

use one_core::model::interaction::{Interaction, InteractionId};
use one_core::model::organisation::Organisation;
use one_core::repository::interaction_repository::InteractionRepository;
use time::OffsetDateTime;
use url::Url;
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
        host: &str,
        data: &[u8],
        organisation: &Organisation,
    ) -> Interaction {
        let interaction = Interaction {
            id: id.unwrap_or_else(Uuid::new_v4),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            host: Some(Url::parse(host).unwrap()),
            data: Some(data.into()),
            organisation: Some(organisation.to_owned()),
        };

        self.repository
            .create_interaction(interaction.to_owned())
            .await
            .unwrap();

        interaction
    }

    pub async fn get(&self, id: impl Into<InteractionId>) -> Option<Interaction> {
        self.repository
            .get_interaction(&id.into(), &Default::default())
            .await
            .unwrap()
    }
}
