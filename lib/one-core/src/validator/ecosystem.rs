use std::sync::Arc;

use shared_types::{EcosystemId, InteractionId};

use crate::error::{ContextWithErrorCode, ErrorCode, ErrorCodeMixin, NestedError};
use crate::model::interaction::{Interaction, UpdateInteractionRequest};
use crate::model::organisation::Organisation;
use crate::provider::ProviderExt;
use crate::provider::ecosystem::Ecosystem;
use crate::provider::ecosystem::directory::EcosystemDirectory;
use crate::provider::ecosystem::model::ProtocolArtifact;
use crate::repository::interaction_repository::InteractionRepository;

#[derive(thiserror::Error, Debug)]
pub(crate) enum EcosystemValidationError {
    #[error("No ecosystem selected")]
    NoEcosystemSelected,
    #[error("No ecosystem detected")]
    NoEcosystemDetected,
    #[error("Ecosystem not permitted")]
    EcosystemNotPermitted,

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for EcosystemValidationError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::NoEcosystemSelected | Self::NoEcosystemDetected => ErrorCode::BR_0476,
            Self::EcosystemNotPermitted => ErrorCode::BR_0475,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}

/// check user selection of ecosystem, always allows no selection (e.g. for later possible autodetection)
pub(crate) fn validate_ecosystem_selection_allow_not_set(
    user_selection: Option<&EcosystemId>,
    organisation: &Organisation,
    ecosystem_provider: &dyn EcosystemDirectory,
) -> Result<(), EcosystemValidationError> {
    if let Some(ecosystem_id) = user_selection {
        let ecosystem = ecosystem_provider.get(ecosystem_id)?;
        ecosystem.ensure_enabled()?;

        if !organisation
            .configuration
            .selected_ecosystems
            .contains(ecosystem_id)
        {
            return Err(EcosystemValidationError::EcosystemNotPermitted);
        }
    }

    Ok(())
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum SelectionRole {
    Issuer,
    Holder,
    Verifier,
}

/// checks ecosystem selection, enforcing selection based on organisation config
pub(crate) fn validate_ecosystem_selection_final(
    user_selection: Option<&EcosystemId>,
    organisation: &Organisation,
    ecosystem_provider: &dyn EcosystemDirectory,
    role: SelectionRole,
) -> Result<(), EcosystemValidationError> {
    if user_selection.is_some() {
        return validate_ecosystem_selection_allow_not_set(
            user_selection,
            organisation,
            ecosystem_provider,
        );
    }

    let configuration = &organisation.configuration;
    let ecosystem_enforced = match role {
        SelectionRole::Issuer => configuration.enforce_ecosystem_as_issuer,
        SelectionRole::Holder => configuration.enforce_ecosystem_as_holder,
        SelectionRole::Verifier => configuration.enforce_ecosystem_as_verifier,
    };

    if ecosystem_enforced {
        return Err(EcosystemValidationError::NoEcosystemSelected);
    }

    Ok(())
}

/// Auto-detect and validate ecosystem from a specific artifact
///
/// if enforced via config, will fail if
/// - either user selection exists and cannot validate the artifact
/// - or there is no user selection and the artifact cannot be validated by any permitted ecosystem
///
/// on success, the final selection is written into the interaction as well as returned
pub(crate) async fn ecosystem_autodetection(
    interaction_id: InteractionId,
    artifact: &ProtocolArtifact<'_>,
    user_selection: Option<EcosystemId>,
    interaction_repository: &dyn InteractionRepository,
    ecosystem_provider: &dyn EcosystemDirectory,
    role: SelectionRole,
) -> Result<Option<EcosystemId>, EcosystemValidationError> {
    let interaction = interaction_repository
        .get_interaction(&interaction_id, None)
        .await
        .error_while("loading interaction")?;

    let configuration = &interaction.organisation.as_ref().await?.configuration;

    let validated_ecosystem = if let Some(user_selection) = &user_selection {
        if !configuration.selected_ecosystems.contains(user_selection) {
            return Err(EcosystemValidationError::EcosystemNotPermitted);
        }

        let ecosystem = ecosystem_provider.get(user_selection)?;
        ecosystem
            .validate_interaction(artifact, &interaction)
            .await
            .error_while("validating interaction")?;
        Some(ecosystem)
    } else {
        if let Some(detected) = find_validating(
            &configuration.selected_ecosystems,
            artifact,
            &interaction,
            ecosystem_provider,
        )
        .await
        {
            Some(detected)
        } else {
            let ecosystem_selection_enforced = match role {
                SelectionRole::Issuer => configuration.enforce_ecosystem_as_issuer,
                SelectionRole::Holder => configuration.enforce_ecosystem_as_holder,
                SelectionRole::Verifier => configuration.enforce_ecosystem_as_verifier,
            };

            if ecosystem_selection_enforced {
                return Err(EcosystemValidationError::NoEcosystemDetected);
            }

            None
        }
    };

    let validated_ecosystem =
        validated_ecosystem.map(|ecosystem| ecosystem.config_name().to_owned());

    if interaction.ecosystem != validated_ecosystem {
        interaction_repository
            .update_interaction(
                interaction_id,
                UpdateInteractionRequest {
                    ecosystem: Some(validated_ecosystem.to_owned()),
                    ..Default::default()
                },
            )
            .await
            .error_while("updating interaction")?;
    }

    Ok(validated_ecosystem)
}

async fn find_validating(
    permitted_ecosystems: &[EcosystemId],
    artifact: &ProtocolArtifact<'_>,
    interaction: &Interaction,
    ecosystem_provider: &dyn EcosystemDirectory,
) -> Option<Arc<dyn Ecosystem>> {
    for ecosystem_id in permitted_ecosystems {
        let Ok(ecosystem) = ecosystem_provider.get(ecosystem_id) else {
            continue;
        };
        if ecosystem
            .validate_interaction(artifact, interaction)
            .await
            .is_ok()
        {
            return Some(ecosystem);
        }
    }

    None
}
