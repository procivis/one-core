use shared_types::CredentialId;
use time::OffsetDateTime;

use crate::model::credential::UpdateCredentialRequest;
use crate::model::interaction::{Interaction, InteractionId};
use crate::model::organisation::Organisation;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::service::error::ServiceError;

pub async fn add_new_interaction(
    interaction_id: InteractionId,
    base_url: &Option<String>,
    interaction_repository: &dyn InteractionRepository,
    data: Option<Vec<u8>>,
    organisation: Option<Organisation>,
) -> Result<Interaction, ServiceError> {
    let now = OffsetDateTime::now_utc();
    let host = base_url
        .as_ref()
        .map(|url| {
            url.parse()
                .map_err(|_| ServiceError::MappingError(format!("Invalid base url {url}")))
        })
        .transpose()?;

    let new_interaction = Interaction {
        id: interaction_id,
        created_date: now,
        last_modified: now,
        host,
        data,
        organisation,
    };

    interaction_repository
        .create_interaction(new_interaction.clone())
        .await?;
    Ok(new_interaction)
}

pub async fn update_credentials_interaction(
    credential_id: CredentialId,
    interaction_id: InteractionId,
    credential_repository: &dyn CredentialRepository,
) -> Result<(), ServiceError> {
    let update = UpdateCredentialRequest {
        interaction: Some(interaction_id.to_owned()),
        ..Default::default()
    };

    credential_repository
        .update_credential(credential_id, update)
        .await?;
    Ok(())
}

pub async fn clear_previous_interaction(
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
