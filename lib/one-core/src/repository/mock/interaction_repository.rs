use crate::{
    model::interaction::{Interaction, InteractionId, InteractionRelations},
    repository::error::DataLayerError,
};
use mockall::*;

#[derive(Default)]
struct InteractionRepository;

mock! {
    pub InteractionRepository {
        pub fn create_interaction(
            &self,
            request: Interaction,
        ) -> Result<InteractionId, DataLayerError>;

        pub fn get_interaction(
            &self,
            id: &InteractionId,
            relations: &InteractionRelations,
        ) -> Result<Interaction, DataLayerError>;
    }
}

#[async_trait::async_trait]
impl crate::repository::interaction_repository::InteractionRepository
    for MockInteractionRepository
{
    async fn create_interaction(
        &self,
        request: Interaction,
    ) -> Result<InteractionId, DataLayerError> {
        self.create_interaction(request)
    }

    async fn get_interaction(
        &self,
        id: &InteractionId,
        relations: &InteractionRelations,
    ) -> Result<Interaction, DataLayerError> {
        self.get_interaction(id, relations)
    }
}
