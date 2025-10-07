use shared_types::{EntityId, OrganisationId};
use time::OffsetDateTime;
use tracing::warn;
use uuid::Uuid;

use crate::model::credential::{Credential, CredentialRole};
use crate::model::history::{History, HistoryAction, HistoryEntityType};
use crate::model::proof::{Proof, ProofRole};
use crate::repository::history_repository::HistoryRepository;

pub(crate) fn history_event(
    entity_id: impl Into<EntityId>,
    name: String,
    organisation_id: OrganisationId,
    entity_type: HistoryEntityType,
    action: HistoryAction,
    target: Option<String>,
    user: Option<String>,
) -> History {
    History {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        action,
        name,
        target,
        entity_id: Some(entity_id.into()),
        entity_type,
        metadata: None,
        organisation_id: Some(organisation_id),
        user,
    }
}

pub(crate) async fn log_history_event_credential(
    history_repository: &dyn HistoryRepository,
    credential: &Credential,
    event: HistoryAction,
    user: Option<String>,
) {
    // Try schema first, then holder_did
    let organisation_id = if let Some(id) = credential
        .schema
        .as_ref()
        .and_then(|schema| schema.organisation.as_ref().map(|org| org.id))
    {
        id
    } else if let Some(id) = credential
        .interaction
        .as_ref()
        .and_then(|interaction| interaction.organisation.as_ref().map(|org| org.id))
    {
        id
    } else if let Some(id) = credential
        .holder_identifier
        .as_ref()
        .and_then(|identifier| identifier.organisation.as_ref().map(|org| org.id))
    {
        id
    } else {
        warn!(
            "failed to create history event {event:#?} for credential {}: missing organisation_id",
            credential.id
        );
        return;
    };

    let credential_schema_name = credential
        .schema
        .as_ref()
        .map(|s| s.name.to_string())
        .unwrap_or_default();
    let result = history_repository
        .create_history(history_event(
            credential.id,
            credential_schema_name,
            organisation_id,
            HistoryEntityType::Credential,
            event,
            target_from_credential(credential),
            user,
        ))
        .await;
    if let Err(err) = result {
        warn!(
            "failed to create history event {event:#?} for credential {}: {err}",
            credential.id
        );
    }
}

pub(crate) async fn log_history_event_proof(
    history_repository: &dyn HistoryRepository,
    proof: &Proof,
    event: HistoryAction,
    user: Option<String>,
) {
    // Try schema first, then holder_did, then verifier_did
    let organisation_id = if let Some(id) = proof
        .schema
        .as_ref()
        .and_then(|schema| schema.organisation.as_ref().map(|org| org.id))
    {
        id
    } else if let Some(id) = proof
        .interaction
        .as_ref()
        .and_then(|interaction| interaction.organisation.as_ref().map(|org| org.id))
    {
        id
    } else if let Some(id) = proof
        .holder_identifier
        .as_ref()
        .and_then(|identifier| identifier.organisation.as_ref().map(|org| org.id))
    {
        id
    } else if let Some(id) = proof
        .verifier_identifier
        .as_ref()
        .and_then(|identifier| identifier.organisation.as_ref().map(|org| org.id))
    {
        id
    } else {
        warn!(
            "failed to create history event {event:#?} for proof {}: missing organisation_id",
            proof.id
        );
        return;
    };

    let result = history_repository
        .create_history(history_event(
            proof.id,
            proof
                .schema
                .as_ref()
                .map(|s| s.name.to_string())
                .unwrap_or_default(),
            organisation_id,
            HistoryEntityType::Proof,
            event,
            target_from_proof(proof),
            user,
        ))
        .await;
    if let Err(err) = result {
        warn!(
            "failed to create history event {event:#?} for proof {}: {err}",
            proof.id
        );
    }
}

fn target_from_proof(proof: &Proof) -> Option<String> {
    match proof.role {
        ProofRole::Holder => proof
            .verifier_identifier
            .as_ref()
            .map(|identifier| identifier.id.to_string()),
        ProofRole::Verifier => proof
            .holder_identifier
            .as_ref()
            .map(|identifier| identifier.id.to_string()),
    }
}

fn target_from_credential(credential: &Credential) -> Option<String> {
    match credential.role {
        CredentialRole::Holder => credential
            .issuer_identifier
            .as_ref()
            .map(|identifier| identifier.id.to_string()),
        CredentialRole::Issuer => credential
            .holder_identifier
            .as_ref()
            .map(|identifier| identifier.id.to_string()),
        CredentialRole::Verifier => None,
    }
}
