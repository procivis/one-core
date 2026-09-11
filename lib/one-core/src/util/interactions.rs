use shared_types::{EcosystemId, InteractionId};
use time::OffsetDateTime;

use crate::error::ContextWithErrorCode;
use crate::model::interaction::{Interaction, InteractionType};
use crate::model::organisation::Organisation;
use crate::model::relation::Related;
use crate::repository::interaction_repository::InteractionRepository;
use crate::service::error::ServiceError;

pub(crate) async fn add_new_interaction(
    interaction_id: InteractionId,
    interaction_repository: &dyn InteractionRepository,
    data: Option<Vec<u8>>,
    organisation: impl Into<Related<Organisation>>,
    interaction_type: InteractionType,
    expires_at: Option<OffsetDateTime>,
    ecosystem: Option<EcosystemId>,
) -> Result<Interaction, ServiceError> {
    let now = crate::clock::now_utc();

    let new_interaction = Interaction {
        id: interaction_id,
        created_date: now,
        last_modified: now,
        data,
        organisation: organisation.into(),
        interaction_type,
        expires_at,
        ecosystem,
        ecosystem_data: Default::default(),
    };

    interaction_repository
        .create_interaction(new_interaction.clone())
        .await
        .error_while("creating interaction")?;
    Ok(new_interaction)
}

pub(crate) async fn clear_previous_interaction(
    interaction_repository: &dyn InteractionRepository,
    interaction_id: Option<&InteractionId>,
) -> Result<(), ServiceError> {
    if let Some(interaction_id) = interaction_id {
        interaction_repository
            .delete_interaction(interaction_id)
            .await
            .error_while("deleting interaction")?;
    }
    Ok(())
}
