//! Finds the ecosystem of an interaction.
//!
//! Callers call `resolve` once for each protocol step. Holder issuance has two steps: the
//! invitation, then the issued credentials. The other flows have one step.
//!
//! The resolver writes the `ECOSYSTEMS_RESOLVED` history events. Callers do not write them.

use std::sync::Arc;

use itertools::Itertools;
use shared_types::{EcosystemId, EntityId, InteractionId};
use uuid::Uuid;

use crate::error::ContextWithErrorCode;
use crate::model::ecosystem::EcosystemOutcomes;
use crate::model::history::{
    History, HistoryAction, HistoryEntityType, HistoryMetadata, HistorySource,
};
use crate::model::interaction::{Interaction, UpdateInteractionRequest};
use crate::model::organisation::OrganisationConfiguration;
use crate::proto::session_provider::{SessionExt, SessionProvider};
use crate::provider::ecosystem::directory::EcosystemDirectory;
use crate::provider::ecosystem::model::ProtocolArtifact;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::validator::ecosystem::EcosystemValidationError;

#[cfg(test)]
mod test;

#[async_trait::async_trait]
pub(crate) trait EcosystemResolver: Send + Sync {
    /// Validates the artifacts of one step. There is one artifact for each credential.
    ///
    /// If the user selected an ecosystem, or an earlier step chose one, only that ecosystem
    /// validates. The call fails if it rejects an artifact.
    ///
    /// Otherwise, each ecosystem that the organisation allows validates. An ecosystem that
    /// rejects an artifact is not asked again in later steps. In the last step, the first
    /// ecosystem that accepts all artifacts is stored in `interaction.ecosystem`. The call fails
    /// if no ecosystem accepts and the organisation enforces an ecosystem.
    async fn resolve<'a>(
        &self,
        interaction_id: InteractionId,
        artifacts: &[ProtocolArtifact<'a>],
        selection: Option<&EcosystemId>,
    ) -> Result<ResolvedEcosystems, EcosystemValidationError>;

    /// Validates the credentials of a batch refresh against `interaction.ecosystem`.
    /// There is one `ProtocolArtifact::HolderIssuanceCredential` for each refreshed credential.
    /// A rejection fails the refresh. No history event is written.
    async fn revalidate<'a>(
        &self,
        interaction: &Interaction,
        artifacts: &[ProtocolArtifact<'a>],
    ) -> Result<(), EcosystemValidationError>;
}

/// Result of [`EcosystemResolver::resolve`].
#[derive(Debug)]
pub(crate) struct ResolvedEcosystems {
    /// The ecosystem of the interaction, if it is chosen.
    pub ecosystem: Option<EcosystemId>,
    /// The ecosystem of each credential, in the order that [`EcosystemResolver::resolve`] got them.
    pub per_credential: Vec<Option<EcosystemId>>,
    /// Which ecosystems accepted and which rejected.
    /// This includes earlier calls to [`EcosystemResolver::resolve`] for the same interaction.
    pub outcomes: EcosystemOutcomes,
}

pub(crate) struct EcosystemResolverProto {
    interaction_repository: Arc<dyn InteractionRepository>,
    ecosystem_provider: Arc<dyn EcosystemDirectory>,
    history_repository: Arc<dyn HistoryRepository>,
    session_provider: Arc<dyn SessionProvider>,
}

impl EcosystemResolverProto {
    pub(crate) fn new(
        interaction_repository: Arc<dyn InteractionRepository>,
        ecosystem_provider: Arc<dyn EcosystemDirectory>,
        history_repository: Arc<dyn HistoryRepository>,
        session_provider: Arc<dyn SessionProvider>,
    ) -> Self {
        Self {
            interaction_repository,
            ecosystem_provider,
            history_repository,
            session_provider,
        }
    }
}

#[async_trait::async_trait]
impl EcosystemResolver for EcosystemResolverProto {
    async fn resolve<'a>(
        &self,
        interaction_id: InteractionId,
        artifacts: &[ProtocolArtifact<'a>],
        selection: Option<&EcosystemId>,
    ) -> Result<ResolvedEcosystems, EcosystemValidationError> {
        let mut interaction = self.load(interaction_id).await?;

        let committed = match (selection, &interaction.ecosystem) {
            (Some(_), Some(committed)) => {
                return Err(EcosystemValidationError::EcosystemAlreadyCommitted(
                    committed.to_owned(),
                ));
            }
            (Some(selection), None) => Some(selection.to_owned()),
            (None, committed) => committed.to_owned(),
        };

        // The user selected an ecosystem, or an earlier step chose one.
        // Only this ecosystem validates the credentials. Other ecosystems are not asked.
        if let Some(committed) = committed {
            let mut outcomes = EcosystemOutcomes::default();
            for artifact in artifacts {
                outcomes.merge(
                    &self
                        .validate_with_interaction_ecosystem(&mut interaction, &committed, artifact)
                        .await?,
                );
            }
            interaction.ecosystem = Some(committed.to_owned());
            self.save(&interaction, &outcomes).await?;

            return Ok(ResolvedEcosystems {
                per_credential: vec![Some(committed.to_owned()); artifacts.len()],
                ecosystem: Some(committed),
                outcomes: with_earlier_steps(&interaction, &outcomes),
            });
        }

        let Some(artifact) = artifacts.first() else {
            return Ok(ResolvedEcosystems {
                ecosystem: None,
                per_credential: vec![],
                outcomes: EcosystemOutcomes::default(),
            });
        };

        let configuration = interaction
            .organisation
            .as_ref()
            .await?
            .configuration
            .to_owned();

        let candidates = remaining_candidates(&interaction, &configuration);
        let mut per_artifact = Vec::with_capacity(artifacts.len());
        for artifact in artifacts {
            per_artifact.push(
                self.check_candidates(&mut interaction, &candidates, artifact)
                    .await,
            );
        }

        // An ecosystem stays a candidate only if it accepts all credentials.
        let outcomes = EcosystemOutcomes::merged(&per_artifact);
        let applicable = outcomes.applicable();

        if applicable.is_empty() && enforced(&configuration, artifact) {
            self.write_history(
                &interaction,
                artifacts
                    .iter()
                    .filter_map(history_entity_on_failure)
                    .unique(),
                &outcomes,
            )
            .await;
            return Err(EcosystemValidationError::NoEcosystemDetected(
                with_earlier_steps(&interaction, &outcomes),
            ));
        }

        for (artifact, outcomes) in artifacts.iter().zip(&per_artifact) {
            self.write_history(&interaction, history_entity(artifact), outcomes)
                .await;
        }

        interaction.ecosystem = applicable
            .into_iter()
            .next()
            .filter(|_| is_final_step(artifact));
        self.save(&interaction, &outcomes).await?;

        let per_credential = match &interaction.ecosystem {
            Some(committed) => vec![Some(committed.to_owned()); artifacts.len()],
            // No candidate accepts all credentials. Each credential gets the first candidate
            // that accepts it.
            None => per_artifact
                .iter()
                .map(|outcomes| outcomes.applicable().into_iter().next())
                .collect(),
        };

        Ok(ResolvedEcosystems {
            outcomes: with_earlier_steps(&interaction, &outcomes),
            ecosystem: interaction.ecosystem,
            per_credential,
        })
    }

    #[expect(clippy::disallowed_methods)]
    async fn revalidate<'a>(
        &self,
        interaction: &Interaction,
        artifacts: &[ProtocolArtifact<'a>],
    ) -> Result<(), EcosystemValidationError> {
        let Some(committed) = &interaction.ecosystem else {
            return Ok(());
        };
        ensure_permitted(interaction, committed).await?;

        let ecosystem = self.ecosystem_provider.get(committed)?;
        for artifact in artifacts {
            ecosystem
                .validate_interaction(artifact, interaction)
                .await
                .map_err(|source| EcosystemValidationError::Rejected {
                    ecosystem: committed.to_owned(),
                    source,
                })?;
        }
        Ok(())
    }
}

impl EcosystemResolverProto {
    #[expect(clippy::disallowed_methods)]
    async fn validate_with_interaction_ecosystem(
        &self,
        interaction: &mut Interaction,
        ecosystem_id: &EcosystemId,
        artifact: &ProtocolArtifact<'_>,
    ) -> Result<EcosystemOutcomes, EcosystemValidationError> {
        ensure_permitted(interaction, ecosystem_id).await?;

        let ecosystem = self.ecosystem_provider.get(ecosystem_id)?;
        let data = match ecosystem.validate_interaction(artifact, interaction).await {
            Ok(data) => data,
            Err(error) => {
                self.write_history(
                    interaction,
                    history_entity_on_failure(artifact),
                    &EcosystemOutcomes::rejected(ecosystem_id.to_owned(), &error),
                )
                .await;
                return Err(EcosystemValidationError::Rejected {
                    ecosystem: ecosystem_id.to_owned(),
                    source: error,
                });
            }
        };
        store_ecosystem_data(interaction, ecosystem_id, data);

        let outcomes = EcosystemOutcomes::validated(ecosystem_id.to_owned());
        self.write_history(interaction, history_entity(artifact), &outcomes)
            .await;
        Ok(outcomes)
    }

    /// Asks all candidates, also after one accepts. The ecosystem is chosen in the last step.
    #[expect(clippy::disallowed_methods)]
    async fn check_candidates(
        &self,
        interaction: &mut Interaction,
        candidates: &[EcosystemId],
        artifact: &ProtocolArtifact<'_>,
    ) -> EcosystemOutcomes {
        let mut outcomes = EcosystemOutcomes::default();

        for ecosystem_id in candidates {
            let ecosystem = match self.ecosystem_provider.get(ecosystem_id) {
                Ok(ecosystem) => ecosystem,
                Err(err) => {
                    tracing::warn!(ecosystem = %ecosystem_id, %err, "Ecosystem unavailable, dropping candidate");
                    outcomes.record(ecosystem_id.to_owned(), Err(err.into()));
                    continue;
                }
            };

            let outcome = match ecosystem.validate_interaction(artifact, interaction).await {
                Ok(data) => {
                    store_ecosystem_data(interaction, ecosystem_id, data);
                    Ok(())
                }
                Err(err) => {
                    tracing::info!(ecosystem = %ecosystem_id, %err, "Ecosystem rejected the artifact, dropping candidate");
                    Err(err.into())
                }
            };
            outcomes.record(ecosystem_id.to_owned(), outcome);
        }

        outcomes
    }

    /// The stored outcomes give the candidates of the next step.
    async fn save(
        &self,
        interaction: &Interaction,
        outcomes: &EcosystemOutcomes,
    ) -> Result<(), EcosystemValidationError> {
        if outcomes.is_empty() && interaction.ecosystem.is_none() {
            return Ok(());
        }

        let mut ecosystem_data = interaction.ecosystem_data.to_owned();
        ecosystem_data.merge_outcomes(outcomes);

        self.interaction_repository
            .update_interaction(
                interaction.id,
                UpdateInteractionRequest {
                    ecosystem: interaction.ecosystem.to_owned().map(Some),
                    ecosystem_data: Some(ecosystem_data),
                    ..Default::default()
                },
            )
            .await
            .error_while("updating interaction")?;
        Ok(())
    }

    async fn load(
        &self,
        interaction_id: InteractionId,
    ) -> Result<Interaction, EcosystemValidationError> {
        Ok(self
            .interaction_repository
            .get_interaction(&interaction_id, None)
            .await
            .error_while("loading interaction")?)
    }

    /// The event also holds the outcomes of earlier steps. A failed write only logs a warning.
    async fn write_history(
        &self,
        interaction: &Interaction,
        entities: impl IntoIterator<Item = (EntityId, HistoryEntityType)>,
        outcomes: &EcosystemOutcomes,
    ) {
        let resolved = with_earlier_steps(interaction, outcomes);
        if resolved.is_empty() {
            return;
        }

        for (entity_id, entity_type) in entities {
            let result = self
                .history_repository
                .create_history(History {
                    id: Uuid::new_v4().into(),
                    created_date: crate::clock::now_utc(),
                    action: HistoryAction::EcosystemsResolved,
                    name: Default::default(),
                    target: None,
                    source: HistorySource::Core,
                    entity_id: Some(entity_id),
                    entity_type,
                    metadata: Some(HistoryMetadata::EcosystemsResolved(resolved.to_owned())),
                    organisation_id: Some(interaction.organisation.id()),
                    user: self.session_provider.session().user(),
                    metadata_blob_id: None,
                })
                .await;
            if let Err(err) = result {
                tracing::warn!(%err, "failed to record the resolved ecosystems");
            }
        }
    }
}

/// Only in memory. `save` writes it to the database.
fn store_ecosystem_data(
    interaction: &mut Interaction,
    ecosystem_id: &EcosystemId,
    data: Option<serde_json::Value>,
) {
    if let Some(data) = data {
        interaction
            .ecosystem_data
            .set(ecosystem_id.to_owned(), data);
    }
}

async fn ensure_permitted(
    interaction: &Interaction,
    ecosystem_id: &EcosystemId,
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
    Ok(())
}

fn with_earlier_steps(
    interaction: &Interaction,
    outcomes: &EcosystemOutcomes,
) -> EcosystemOutcomes {
    let mut resolved = interaction.ecosystem_data.outcomes().to_owned();
    resolved.merge(outcomes);
    resolved
}

fn remaining_candidates(
    interaction: &Interaction,
    configuration: &OrganisationConfiguration,
) -> Vec<EcosystemId> {
    let selected = &configuration.selected_ecosystems;

    let outcomes = interaction.ecosystem_data.outcomes();
    if outcomes.is_empty() {
        // This is the first step, so all selected ecosystems are candidates.
        return selected.to_owned();
    }

    let mut candidates = outcomes.applicable();
    candidates.retain(|ecosystem| selected.contains(ecosystem));
    candidates
}

fn history_entity(artifact: &ProtocolArtifact<'_>) -> Option<(EntityId, HistoryEntityType)> {
    match artifact {
        ProtocolArtifact::HolderIssuanceInvitation { .. } => None,
        ProtocolArtifact::HolderIssuanceCredential { credential, .. } => {
            // The event goes on the parent credential of the batch. The ecosystems write their
            // own history events there too.
            let credential_id = credential
                .parent
                .as_ref()
                .map(|parent| parent.id())
                .unwrap_or(credential.id);
            Some((credential_id.into(), HistoryEntityType::Credential))
        }
        ProtocolArtifact::HolderProof { proof_id, .. } => {
            Some(((*proof_id).into(), HistoryEntityType::Proof))
        }
        ProtocolArtifact::IssuerIssuance { credential_id, .. } => {
            Some(((*credential_id).into(), HistoryEntityType::Credential))
        }
        ProtocolArtifact::VerifierSubmission { credential, .. } => {
            Some((credential.id.into(), HistoryEntityType::Credential))
        }
    }
}

/// A failed issuance creates no credential. A failed submission still has its proof.
fn history_entity_on_failure(
    artifact: &ProtocolArtifact<'_>,
) -> Option<(EntityId, HistoryEntityType)> {
    match artifact {
        ProtocolArtifact::HolderIssuanceCredential { .. } => None,
        ProtocolArtifact::VerifierSubmission { proof_id, .. } => {
            Some(((*proof_id).into(), HistoryEntityType::Proof))
        }
        _ => history_entity(artifact),
    }
}

/// Whether the organisation enforces an ecosystem for its role in the interaction.
fn enforced(configuration: &OrganisationConfiguration, artifact: &ProtocolArtifact<'_>) -> bool {
    match artifact {
        ProtocolArtifact::HolderIssuanceInvitation { .. }
        | ProtocolArtifact::HolderIssuanceCredential { .. }
        | ProtocolArtifact::HolderProof { .. } => configuration.enforce_ecosystem_as_holder,
        ProtocolArtifact::IssuerIssuance { .. } => configuration.enforce_ecosystem_as_issuer,
        ProtocolArtifact::VerifierSubmission { .. } => configuration.enforce_ecosystem_as_verifier,
    }
}

/// Only the invitation step has a later step.
fn is_final_step(artifact: &ProtocolArtifact<'_>) -> bool {
    !matches!(artifact, ProtocolArtifact::HolderIssuanceInvitation { .. })
}
