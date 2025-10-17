use time::OffsetDateTime;

use crate::model::interaction::{Interaction, InteractionId, InteractionType};
use crate::model::organisation::Organisation;
use crate::repository::interaction_repository::InteractionRepository;
use crate::service::error::ServiceError;

pub(crate) async fn add_new_interaction(
    interaction_id: InteractionId,
    interaction_repository: &dyn InteractionRepository,
    data: Option<Vec<u8>>,
    organisation: Option<Organisation>,
    interaction_type: InteractionType,
) -> Result<Interaction, ServiceError> {
    let now = OffsetDateTime::now_utc();

    let new_interaction = Interaction {
        id: interaction_id,
        created_date: now,
        last_modified: now,
        data,
        organisation,
        nonce_id: None,
        interaction_type,
    };

    interaction_repository
        .create_interaction(new_interaction.clone())
        .await?;
    Ok(new_interaction)
}

pub(crate) async fn clear_previous_interaction(
    interaction_repository: &dyn InteractionRepository,
    interaction: &Option<Interaction>,
) -> Result<(), ServiceError> {
    if let Some(interaction) = interaction.as_ref() {
        interaction_repository
            .delete_interaction(&interaction.id)
            .await?;
    }
    Ok(())
}
