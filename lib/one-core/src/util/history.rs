use shared_types::{EntityId, OrganisationId};
use time::OffsetDateTime;
use tracing::warn;
use uuid::Uuid;

use crate::model::credential::Credential;
use crate::model::credential_schema::CredentialSchema;
use crate::model::history::{History, HistoryAction, HistoryEntityType};
use crate::model::organisation::Organisation;
use crate::model::proof::Proof;
use crate::model::proof_schema::ProofSchema;
use crate::repository::history_repository::HistoryRepository;

pub(crate) fn history_event(
    entity_id: impl Into<EntityId>,
    organisation_id: OrganisationId,
    entity_type: HistoryEntityType,
    action: HistoryAction,
) -> History {
    History {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        action,
        entity_id: Some(entity_id.into()),
        entity_type,
        metadata: None,
        organisation: Some(Organisation {
            id: organisation_id,
            created_date: OffsetDateTime::UNIX_EPOCH,
            last_modified: OffsetDateTime::UNIX_EPOCH,
        }),
    }
}

pub(crate) async fn log_history_event_credential(
    history_repository: &dyn HistoryRepository,
    credential: &Credential,
    event: HistoryAction,
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
        .holder_did
        .as_ref()
        .and_then(|did| did.organisation.as_ref().map(|org| org.id))
    {
        id
    } else {
        warn!(
            "failed to create history event {event:#?} for credential {}: missing organisation_id",
            credential.id
        );
        return;
    };

    let result = history_repository
        .create_history(history_event(
            credential.id,
            organisation_id,
            HistoryEntityType::Credential,
            event.clone(),
        ))
        .await;
    if let Err(err) = result {
        warn!(
            "failed to create history event {event:#?} for credential {}: {err}",
            credential.id
        );
    }
}

pub(crate) async fn log_history_event_credential_schema(
    history_repository: &dyn HistoryRepository,
    schema: &CredentialSchema,
    event: HistoryAction,
) {
    let Some(ref organisation) = schema.organisation else {
        warn!("failed to create history event {event:#?} for credential schema {}: missing organisation_id", schema.id);
        return;
    };

    let result = history_repository
        .create_history(history_event(
            schema.id,
            organisation.id,
            HistoryEntityType::CredentialSchema,
            event.clone(),
        ))
        .await;
    if let Err(err) = result {
        warn!(
            "failed to create history event {event:#?} for credential schema {}: {err}",
            schema.id
        );
    }
}

pub(crate) async fn log_history_event_proof(
    history_repository: &dyn HistoryRepository,
    proof: &Proof,
    event: HistoryAction,
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
        .holder_did
        .as_ref()
        .and_then(|did| did.organisation.as_ref().map(|org| org.id))
    {
        id
    } else if let Some(id) = proof
        .verifier_did
        .as_ref()
        .and_then(|did| did.organisation.as_ref().map(|org| org.id))
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
            organisation_id,
            HistoryEntityType::Proof,
            event.clone(),
        ))
        .await;
    if let Err(err) = result {
        warn!(
            "failed to create history event {event:#?} for proof {}: {err}",
            proof.id
        );
    }
}

pub(crate) async fn log_history_event_proof_schema(
    history_repository: &dyn HistoryRepository,
    proof_schema: &ProofSchema,
    event: HistoryAction,
) {
    let Some(ref organisation) = proof_schema.organisation else {
        warn!("failed to create history event {event:#?} for proof schema {}: missing organisation_id", proof_schema.id);
        return;
    };

    let result = history_repository
        .create_history(history_event(
            proof_schema.id,
            organisation.id,
            HistoryEntityType::ProofSchema,
            event.clone(),
        ))
        .await;
    if let Err(err) = result {
        warn!(
            "failed to create history event {event:#?} for proof schema {}: {err}",
            proof_schema.id
        );
    }
}
