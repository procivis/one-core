use super::error::DataLayerError;
use crate::model::interaction::{
    Interaction, InteractionId, InteractionRelations, UpdateInteractionRequest,
};

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait InteractionRepository: Send + Sync {
    async fn create_interaction(
        &self,
        request: Interaction,
    ) -> Result<InteractionId, DataLayerError>;

    async fn update_interaction(
        &self,
        request: UpdateInteractionRequest,
    ) -> Result<(), DataLayerError>;

    async fn get_interaction(
        &self,
        id: &InteractionId,
        relations: &InteractionRelations,
    ) -> Result<Option<Interaction>, DataLayerError>;

    async fn delete_interaction(&self, id: &InteractionId) -> Result<(), DataLayerError>;
}
