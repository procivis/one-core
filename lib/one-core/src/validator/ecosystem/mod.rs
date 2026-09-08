use std::collections::HashMap;

use shared_types::{EcosystemId, InteractionId};

use crate::error::{ContextWithErrorCode, ErrorCode, ErrorCodeMixin, NestedError};
use crate::model::interaction::{EcosystemDetection, Interaction, UpdateInteractionRequest};
use crate::model::organisation::{Organisation, OrganisationConfiguration};
use crate::provider::ProviderExt;
use crate::provider::ecosystem::directory::EcosystemDirectory;
use crate::provider::ecosystem::model::ProtocolArtifact;
use crate::repository::interaction_repository::InteractionRepository;

#[cfg(test)]
mod test;

#[derive(thiserror::Error, Debug)]
pub(crate) enum EcosystemValidationError {
    #[error("No ecosystem selected")]
    NoEcosystemSelected,
    #[error("No ecosystem detected")]
    NoEcosystemDetected,
    #[error("Ecosystem not permitted")]
    EcosystemNotPermitted,
    #[error("Ecosystem `{0}` already committed on this interaction")]
    EcosystemAlreadyCommitted(EcosystemId),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for EcosystemValidationError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::NoEcosystemSelected | Self::NoEcosystemDetected => ErrorCode::BR_0476,
            Self::EcosystemNotPermitted => ErrorCode::BR_0475,
            Self::EcosystemAlreadyCommitted(_) => ErrorCode::BR_0477,
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

    if ecosystem_enforced(&organisation.configuration, role) {
        return Err(EcosystemValidationError::NoEcosystemSelected);
    }

    Ok(())
}

fn ecosystem_enforced(configuration: &OrganisationConfiguration, role: SelectionRole) -> bool {
    match role {
        SelectionRole::Issuer => configuration.enforce_ecosystem_as_issuer,
        SelectionRole::Holder => configuration.enforce_ecosystem_as_holder,
        SelectionRole::Verifier => configuration.enforce_ecosystem_as_verifier,
    }
}

/// The user picked the ecosystem explicitly: that is a commitment, not a candidate for
/// autodetection. Validates the selection against the artifact of this step and records it on the
/// interaction, so that every later step runs under it.
pub(crate) async fn commit_selected_ecosystem(
    interaction_id: InteractionId,
    artifact: &ProtocolArtifact<'_>,
    selection: &EcosystemId,
    interaction_repository: &dyn InteractionRepository,
    ecosystem_provider: &dyn EcosystemDirectory,
) -> Result<(), EcosystemValidationError> {
    let interaction = load(interaction_id, interaction_repository).await?;

    if let Some(committed) = interaction.ecosystem {
        return Err(EcosystemValidationError::EcosystemAlreadyCommitted(
            committed,
        ));
    }

    validate_committed(&interaction, selection, artifact, ecosystem_provider).await?;

    interaction_repository
        .update_interaction(
            interaction_id,
            UpdateInteractionRequest {
                ecosystem: Some(Some(selection.to_owned())),
                ..Default::default()
            },
        )
        .await
        .error_while("committing ecosystem")?;

    Ok(())
}

/// Carry the ecosystem of an interaction through one step.
///
/// A committed ecosystem is not subject to narrowing: it either validates the artifact or the step
/// fails. Without a commitment, autodetection narrows the ecosystems still applicable by this
/// step's artifact, which fails only if enforced via config and nothing is left.
pub(crate) async fn validate_ecosystem_step(
    interaction_id: InteractionId,
    artifact: &ProtocolArtifact<'_>,
    interaction_repository: &dyn InteractionRepository,
    ecosystem_provider: &dyn EcosystemDirectory,
    role: SelectionRole,
) -> Result<(), EcosystemValidationError> {
    step(
        interaction_id,
        artifact,
        interaction_repository,
        ecosystem_provider,
        role,
    )
    .await?;

    Ok(())
}

/// As [`validate_ecosystem_step`], for the last artifact that adds information: whatever
/// autodetection is left with gets committed. Returns the ecosystem the interaction runs under.
pub(crate) async fn resolve_ecosystem(
    interaction_id: InteractionId,
    artifact: &ProtocolArtifact<'_>,
    interaction_repository: &dyn InteractionRepository,
    ecosystem_provider: &dyn EcosystemDirectory,
    role: SelectionRole,
) -> Result<Option<EcosystemId>, EcosystemValidationError> {
    let applicable = match step(
        interaction_id,
        artifact,
        interaction_repository,
        ecosystem_provider,
        role,
    )
    .await?
    {
        // already committed, by the user selecting it or by an earlier step
        StepOutcome::Committed(ecosystem) => return Ok(Some(ecosystem)),
        StepOutcome::Applicable(applicable) => applicable,
    };

    // commit the first still applicable ecosystem
    let committed = applicable.into_iter().next();
    interaction_repository
        .update_interaction(
            interaction_id,
            UpdateInteractionRequest {
                ecosystem: Some(committed.to_owned()),
                ..Default::default()
            },
        )
        .await
        .error_while("committing ecosystem")?;

    Ok(committed)
}

/// The ecosystems an interaction resolves to from its credentials.
#[derive(Debug)]
pub(crate) struct ResolvedEcosystems {
    /// the ecosystem the interaction ends up committed to: it validated every credential
    pub committed: Option<EcosystemId>,
    /// per credential (indexed as the artifacts): the ecosystem providing its trust information
    pub per_credential: Vec<Option<EcosystemId>>,
}

/// Resolve the ecosystems of an interaction from its credentials, one artifact per credential.
///
/// The interaction commits to the first ecosystem that validates every credential. If none
/// does, nothing is committed, and each credential individually keeps the trust of the first
/// ecosystem that validates it.
pub(crate) async fn resolve_credential_ecosystems(
    interaction_id: InteractionId,
    artifacts: &[ProtocolArtifact<'_>],
    interaction_repository: &dyn InteractionRepository,
    ecosystem_provider: &dyn EcosystemDirectory,
    role: SelectionRole,
) -> Result<ResolvedEcosystems, EcosystemValidationError> {
    let interaction = load(interaction_id, interaction_repository).await?;

    // if ecosystem is commited, all credentials must match
    if let Some(committed) = interaction.ecosystem.to_owned() {
        for artifact in artifacts {
            // TODO ONE-10972: find a nicer way to do this
            let interaction = load(interaction_id, interaction_repository).await?;
            validate_committed(&interaction, &committed, artifact, ecosystem_provider).await?;
        }

        return Ok(ResolvedEcosystems {
            per_credential: vec![Some(committed.to_owned()); artifacts.len()],
            committed: Some(committed),
        });
    }

    if artifacts.is_empty() {
        return Ok(ResolvedEcosystems {
            committed: None,
            per_credential: vec![],
        });
    }

    let configuration = interaction
        .organisation
        .as_ref()
        .await?
        .configuration
        .to_owned();

    let mut outcomes = ValidationOutcomes {
        interaction_id,
        artifacts,
        interaction_repository,
        ecosystem_provider,
        outcomes: HashMap::new(),
    };

    // the interaction level: a candidate stays applicable only if it validates every credential
    let mut applicable = Vec::new();
    for candidate in remaining_candidates(&interaction, &configuration) {
        if outcomes.validates_all(&candidate).await? {
            applicable.push(candidate);
        }
    }

    if applicable.is_empty() && ecosystem_enforced(&configuration, role) {
        return Err(EcosystemValidationError::NoEcosystemDetected);
    }

    persist_detection(interaction_id, &applicable, interaction_repository).await?;

    // commit the first still applicable ecosystem
    if let Some(committed) = applicable.into_iter().next() {
        interaction_repository
            .update_interaction(
                interaction_id,
                UpdateInteractionRequest {
                    ecosystem: Some(Some(committed.to_owned())),
                    ..Default::default()
                },
            )
            .await
            .error_while("committing ecosystem")?;

        // the interaction runs under this ecosystem, and it validated every credential
        return Ok(ResolvedEcosystems {
            per_credential: vec![Some(committed.to_owned()); artifacts.len()],
            committed: Some(committed),
        });
    }

    // no ecosystem validates the full submission: trust is still autodetected per credential,
    // from the first ecosystem of the organisation's selection that validates it
    let mut per_credential = Vec::with_capacity(artifacts.len());
    for index in 0..artifacts.len() {
        let mut detected = None;
        for ecosystem_id in &configuration.selected_ecosystems {
            if outcomes.validates(ecosystem_id, index).await? {
                detected = Some(ecosystem_id.to_owned());
                break;
            }
        }
        per_credential.push(detected);
    }

    Ok(ResolvedEcosystems {
        committed: None,
        per_credential,
    })
}

/// Which ecosystems validate which of a submission's artifacts, each pair consulted at most once.
struct ValidationOutcomes<'a> {
    interaction_id: InteractionId,
    artifacts: &'a [ProtocolArtifact<'a>],
    interaction_repository: &'a dyn InteractionRepository,
    ecosystem_provider: &'a dyn EcosystemDirectory,
    // whether the ecosystem validated the artifact at the given position in `artifacts`
    outcomes: HashMap<(EcosystemId, usize), bool>,
}

impl ValidationOutcomes<'_> {
    /// Whether `ecosystem_id` validates every artifact of the submission.
    async fn validates_all(
        &mut self,
        ecosystem_id: &EcosystemId,
    ) -> Result<bool, EcosystemValidationError> {
        for index in 0..self.artifacts.len() {
            if !self.validates(ecosystem_id, index).await? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Whether `ecosystem_id` validates the artifact at `index`.
    async fn validates(
        &mut self,
        ecosystem_id: &EcosystemId,
        index: usize,
    ) -> Result<bool, EcosystemValidationError> {
        let key = (ecosystem_id.to_owned(), index);
        if let Some(outcome) = self.outcomes.get(&key) {
            return Ok(*outcome);
        }
        let Some(artifact) = self.artifacts.get(index) else {
            return Ok(false);
        };

        let outcome = match self.ecosystem_provider.get(ecosystem_id) {
            Ok(ecosystem) => {
                // TODO ONE-10972: find a nicer way to do this
                let interaction = load(self.interaction_id, self.interaction_repository).await?;
                match ecosystem.validate_interaction(artifact, &interaction).await {
                    Ok(()) => true,
                    Err(err) => {
                        tracing::info!(ecosystem = %ecosystem_id, %err, "Ecosystem rejected the credential");
                        false
                    }
                }
            }
            Err(err) => {
                tracing::warn!(ecosystem = %ecosystem_id, %err, "Ecosystem unavailable, dropping candidate");
                false
            }
        };

        self.outcomes.insert(key, outcome);
        Ok(outcome)
    }
}

/// Where one step leaves the ecosystem of an interaction.
enum StepOutcome {
    /// the interaction runs under this ecosystem, and it validated the artifact
    Committed(EcosystemId),
    /// nothing is committed yet: the ecosystems autodetection still considers applicable
    Applicable(Vec<EcosystemId>),
}

/// The step itself: validate what is committed, or narrow if nothing is.
async fn step(
    interaction_id: InteractionId,
    artifact: &ProtocolArtifact<'_>,
    interaction_repository: &dyn InteractionRepository,
    ecosystem_provider: &dyn EcosystemDirectory,
    role: SelectionRole,
) -> Result<StepOutcome, EcosystemValidationError> {
    let interaction = load(interaction_id, interaction_repository).await?;

    if let Some(committed) = &interaction.ecosystem {
        validate_committed(&interaction, committed, artifact, ecosystem_provider).await?;
        return Ok(StepOutcome::Committed(committed.to_owned()));
    }

    narrow(
        &interaction,
        artifact,
        interaction_repository,
        ecosystem_provider,
        role,
    )
    .await
    .map(StepOutcome::Applicable)
}

/// A committed ecosystem either validates the artifact or the step fails.
async fn validate_committed(
    interaction: &Interaction,
    ecosystem_id: &EcosystemId,
    artifact: &ProtocolArtifact<'_>,
    ecosystem_provider: &dyn EcosystemDirectory,
) -> Result<(), EcosystemValidationError> {
    let permitted = interaction
        .organisation
        .as_ref()
        .await?
        .configuration
        .selected_ecosystems
        .contains(ecosystem_id);
    if !permitted {
        return Err(EcosystemValidationError::EcosystemNotPermitted);
    }

    let ecosystem = ecosystem_provider.get(ecosystem_id)?;
    ecosystem
        .validate_interaction(artifact, interaction)
        .await
        .error_while("validating interaction")?;

    Ok(())
}

/// The narrowing itself, persisting the ecosystems that are still applicable.
async fn narrow(
    interaction: &Interaction,
    artifact: &ProtocolArtifact<'_>,
    interaction_repository: &dyn InteractionRepository,
    ecosystem_provider: &dyn EcosystemDirectory,
    role: SelectionRole,
) -> Result<Vec<EcosystemId>, EcosystemValidationError> {
    let interaction_id = interaction.id;
    let configuration = interaction
        .organisation
        .as_ref()
        .await?
        .configuration
        .to_owned();

    let candidates = remaining_candidates(interaction, &configuration);
    let applicable = narrow_candidates(
        interaction_id,
        &candidates,
        artifact,
        interaction_repository,
        ecosystem_provider,
    )
    .await?;

    if applicable.is_empty() && ecosystem_enforced(&configuration, role) {
        return Err(EcosystemValidationError::NoEcosystemDetected);
    }

    persist_detection(interaction_id, &applicable, interaction_repository).await?;

    Ok(applicable)
}

/// Persist what narrowing left applicable, unless unchanged.
async fn persist_detection(
    interaction_id: InteractionId,
    applicable: &[EcosystemId],
    interaction_repository: &dyn InteractionRepository,
) -> Result<(), EcosystemValidationError> {
    // Reload, as ecosystem validation may persist the ecosystems' own interaction data
    // TODO ONE-10972: find a nicer way to do this
    let mut interaction = load(interaction_id, interaction_repository).await?;

    let detection = EcosystemDetection::Applicable(applicable.to_owned());
    if interaction.ecosystem_data.detection() != &detection {
        interaction.ecosystem_data.set_detection(detection);
        interaction_repository
            .update_interaction(
                interaction_id,
                UpdateInteractionRequest {
                    ecosystem_data: Some(interaction.ecosystem_data.to_owned()),
                    ..Default::default()
                },
            )
            .await
            .error_while("updating interaction")?;
    }

    Ok(())
}

async fn load(
    interaction_id: InteractionId,
    interaction_repository: &dyn InteractionRepository,
) -> Result<Interaction, EcosystemValidationError> {
    Ok(interaction_repository
        .get_interaction(&interaction_id, None)
        .await
        .error_while("loading interaction")?)
}

/// Ecosystems that may still be detected on this interaction minus the ones that have been
/// deselected in the meantime.
fn remaining_candidates(
    interaction: &Interaction,
    configuration: &OrganisationConfiguration,
) -> Vec<EcosystemId> {
    let selected = &configuration.selected_ecosystems;

    match interaction.ecosystem_data.detection() {
        EcosystemDetection::Pending => selected.to_owned(),
        EcosystemDetection::Applicable(applicable) => {
            let mut candidates = applicable.to_owned();
            candidates.retain(|ecosystem| selected.contains(ecosystem));
            candidates
        }
    }
}

/// Candidates that still validate the artifact of this step.
///
/// Every candidate is consulted: which ecosystems remain applicable can only be decided once the
/// interaction completes, so narrowing may not stop at the first one that happens to validate.
async fn narrow_candidates(
    interaction_id: InteractionId,
    candidates: &[EcosystemId],
    artifact: &ProtocolArtifact<'_>,
    interaction_repository: &dyn InteractionRepository,
    ecosystem_provider: &dyn EcosystemDirectory,
) -> Result<Vec<EcosystemId>, EcosystemValidationError> {
    let mut applicable = Vec::with_capacity(candidates.len());

    for ecosystem_id in candidates {
        let ecosystem = match ecosystem_provider.get(ecosystem_id) {
            Ok(ecosystem) => ecosystem,
            Err(err) => {
                tracing::warn!(ecosystem = %ecosystem_id, %err, "Ecosystem unavailable, dropping candidate");
                continue;
            }
        };

        // reloaded per candidate: validating persists the ecosystem's own interaction data, and
        // the next candidate must not write its slot on top of a copy predating that
        // TODO ONE-10972: find a nicer way to do this
        let interaction = interaction_repository
            .get_interaction(&interaction_id, None)
            .await
            .error_while("loading interaction")?;

        match ecosystem.validate_interaction(artifact, &interaction).await {
            Ok(()) => applicable.push(ecosystem_id.to_owned()),
            Err(err) => {
                tracing::info!(ecosystem = %ecosystem_id, %err, "Ecosystem rejected the artifact, dropping candidate");
            }
        }
    }

    Ok(applicable)
}
