use one_providers::revocation::model::CredentialRevocationState;
use shared_types::{EntityId, OrganisationId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::credential::Credential;
use crate::model::credential_schema::CredentialSchema;
use crate::model::did::Did;
use crate::model::history::{History, HistoryAction, HistoryEntityType};
use crate::model::organisation::Organisation;
use crate::model::proof::Proof;
use crate::model::proof_schema::ProofSchema;
use crate::repository::history_repository::HistoryRepository;
use crate::service::error::ServiceError;

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
) -> Result<(), ServiceError> {
    // Try schema first, then holder_did
    let organisation_id = if let Some(id) = credential
        .schema
        .as_ref()
        .and_then(|schema| schema.organisation.as_ref().map(|org| org.id))
    {
        id
    } else if let Some(id) = credential
        .holder_did
        .as_ref()
        .and_then(|did| did.organisation.as_ref().map(|org| org.id))
    {
        id
    } else {
        return Err(ServiceError::MappingError(
            "organisation is None".to_string(),
        ));
    };

    history_repository
        .create_history(history_event(
            credential.id,
            organisation_id,
            HistoryEntityType::Credential,
            event,
        ))
        .await?;

    Ok(())
}

pub(crate) async fn log_history_event_credential_revocation(
    history_repository: &dyn HistoryRepository,
    credential: &Credential,
    new_state: CredentialRevocationState,
) -> Result<(), ServiceError> {
    let action = match new_state {
        CredentialRevocationState::Revoked => HistoryAction::Revoked,
        CredentialRevocationState::Valid => HistoryAction::Reactivated,
        CredentialRevocationState::Suspended { .. } => HistoryAction::Suspended,
    };

    log_history_event_credential(history_repository, credential, action).await
}

pub(crate) async fn log_history_event_credential_schema(
    history_repository: &dyn HistoryRepository,
    schema: &CredentialSchema,
    event: HistoryAction,
) -> Result<(), ServiceError> {
    let organisation_id = schema
        .organisation
        .as_ref()
        .ok_or(ServiceError::MappingError(
            "organisation is None".to_string(),
        ))?
        .id;

    history_repository
        .create_history(history_event(
            schema.id,
            organisation_id,
            HistoryEntityType::CredentialSchema,
            event,
        ))
        .await?;

    Ok(())
}

pub(crate) async fn log_history_event_did(
    history_repository: &dyn HistoryRepository,
    did: &Did,
    event: HistoryAction,
) -> Result<(), ServiceError> {
    let organisation_id = did
        .organisation
        .as_ref()
        .ok_or(ServiceError::MappingError(
            "organisation is None".to_string(),
        ))?
        .id;

    history_repository
        .create_history(history_event(
            did.id,
            organisation_id,
            HistoryEntityType::Did,
            event,
        ))
        .await?;

    Ok(())
}

pub(crate) async fn log_history_event_proof(
    history_repository: &dyn HistoryRepository,
    proof: &Proof,
    event: HistoryAction,
) -> Result<(), ServiceError> {
    // Try schema first, then holder_did, then verifier_did
    let organisation_id = if let Some(id) = proof
        .schema
        .as_ref()
        .and_then(|schema| schema.organisation.as_ref().map(|org| org.id))
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
        return Err(ServiceError::MappingError(
            "organisation is None".to_string(),
        ));
    };

    history_repository
        .create_history(history_event(
            proof.id,
            organisation_id,
            HistoryEntityType::Proof,
            event,
        ))
        .await?;

    Ok(())
}

pub(crate) async fn log_history_event_proof_schema(
    history_repository: &dyn HistoryRepository,
    proof_schema: &ProofSchema,
    event: HistoryAction,
) -> Result<(), ServiceError> {
    let organisation_id = proof_schema
        .organisation
        .as_ref()
        .ok_or(ServiceError::MappingError(
            "organisation is None".to_string(),
        ))?
        .id;

    history_repository
        .create_history(history_event(
            proof_schema.id,
            organisation_id,
            HistoryEntityType::ProofSchema,
            event,
        ))
        .await?;

    Ok(())
}
