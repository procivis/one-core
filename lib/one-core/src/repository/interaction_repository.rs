use crate::model::interaction::{Interaction, InteractionId, InteractionRelations};

use super::error::DataLayerError;

#[async_trait::async_trait]
pub trait InteractionRepository {
    async fn create_interaction(
        &self,
        request: Interaction,
    ) -> Result<InteractionId, DataLayerError>;

    async fn get_interaction(
        &self,
        id: &InteractionId,
        relations: &InteractionRelations,
    ) -> Result<Interaction, DataLayerError>;
}
