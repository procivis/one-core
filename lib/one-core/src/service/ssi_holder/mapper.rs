use shared_types::EntityId;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    model::{
        claim_schema::ClaimSchema,
        credential::Credential,
        credential_schema::{CredentialSchema, CredentialSchemaClaim},
        did::Did,
        history::{History, HistoryAction, HistoryEntityType},
        proof::Proof,
    },
    service::{
        credential::dto::DetailCredentialSchemaResponseDTO,
        credential_schema::dto::CredentialClaimSchemaDTO,
    },
};

impl From<DetailCredentialSchemaResponseDTO> for CredentialSchema {
    fn from(value: DetailCredentialSchemaResponseDTO) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            format: value.format,
            wallet_storage_type: None,
            revocation_method: value.revocation_method,
            deleted_at: value.deleted_at,
            claim_schemas: None,
            organisation: None, // response organisation is intentionally ignored (holder sets its local organisation)
        }
    }
}

impl From<CredentialClaimSchemaDTO> for CredentialSchemaClaim {
    fn from(value: CredentialClaimSchemaDTO) -> Self {
        Self {
            schema: ClaimSchema {
                id: value.id,
                key: value.key,
                data_type: value.datatype,
                created_date: value.created_date,
                last_modified: value.last_modified,
            },
            required: value.required,
        }
    }
}

pub(super) fn credential_offered_history_event(credential: &Credential) -> History {
    history_event(
        credential.id.into(),
        credential.holder_did.as_ref(),
        HistoryEntityType::Credential,
        HistoryAction::Offered,
    )
}

pub(super) fn credential_pending_history_event(credential: &Credential) -> History {
    history_event(
        credential.id.into(),
        credential.holder_did.as_ref(),
        HistoryEntityType::Credential,
        HistoryAction::Pending,
    )
}

pub(super) fn credential_accepted_history_event(credential: &Credential) -> History {
    history_event(
        credential.id.into(),
        credential.holder_did.as_ref(),
        HistoryEntityType::Credential,
        HistoryAction::Accepted,
    )
}

pub(super) fn credential_rejected_history_event(credential: &Credential) -> History {
    history_event(
        credential.id.into(),
        credential.holder_did.as_ref(),
        HistoryEntityType::Credential,
        HistoryAction::Rejected,
    )
}

pub(super) fn proof_requested_history_event(proof: &Proof) -> History {
    history_event(
        proof.id.into(),
        proof.holder_did.as_ref(),
        HistoryEntityType::Proof,
        HistoryAction::Requested,
    )
}

pub(super) fn proof_pending_history_event(proof: &Proof) -> History {
    history_event(
        proof.id.into(),
        proof.holder_did.as_ref(),
        HistoryEntityType::Proof,
        HistoryAction::Pending,
    )
}

pub(crate) fn proof_rejected_history_event(proof: &Proof) -> History {
    history_event(
        proof.id.into(),
        proof.holder_did.as_ref(),
        HistoryEntityType::Proof,
        HistoryAction::Rejected,
    )
}

pub(crate) fn proof_accepted_history_event(proof: &Proof) -> History {
    history_event(
        proof.id.into(),
        proof.holder_did.as_ref(),
        HistoryEntityType::Proof,
        HistoryAction::Accepted,
    )
}

fn history_event(
    entity_id: EntityId,
    holder_did: Option<&Did>,
    entity_type: HistoryEntityType,
    action: HistoryAction,
) -> History {
    let organisation = holder_did.and_then(|did| did.organisation.clone());

    History {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        action,
        entity_id: entity_id.into(),
        entity_type,
        organisation,
    }
}
