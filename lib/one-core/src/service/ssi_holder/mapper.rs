use dto_mapper::convert_inner;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    model::{
        claim_schema::ClaimSchema,
        credential::Credential,
        credential_schema::{CredentialSchema, CredentialSchemaClaim, LayoutType},
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
            wallet_storage_type: value.wallet_storage_type,
            revocation_method: value.revocation_method,
            deleted_at: value.deleted_at,
            claim_schemas: None,
            organisation: None, // response organisation is intentionally ignored (holder sets its local organisation)
            layout_type: value.layout_type.unwrap_or(LayoutType::Card),
            layout_properties: convert_inner(value.layout_properties),
            schema_id: value.schema_id,
            schema_type: value.schema_type.into(),
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
                array: false, //FIXME!
            },
            required: value.required,
        }
    }
}

pub(super) fn credential_offered_history_event(credential: &Credential) -> History {
    credential_history_event(credential, HistoryAction::Offered)
}

pub(super) fn credential_pending_history_event(credential: &Credential) -> History {
    credential_history_event(credential, HistoryAction::Pending)
}

pub(super) fn credential_accepted_history_event(credential: &Credential) -> History {
    credential_history_event(credential, HistoryAction::Accepted)
}

pub(super) fn credential_rejected_history_event(credential: &Credential) -> History {
    credential_history_event(credential, HistoryAction::Rejected)
}

pub(super) fn proof_requested_history_event(proof: &Proof) -> History {
    proof_history_event(proof, HistoryAction::Requested)
}

pub(super) fn proof_pending_history_event(proof: &Proof) -> History {
    proof_history_event(proof, HistoryAction::Pending)
}

pub(crate) fn proof_rejected_history_event(proof: &Proof) -> History {
    proof_history_event(proof, HistoryAction::Rejected)
}

pub(crate) fn proof_accepted_history_event(proof: &Proof) -> History {
    proof_history_event(proof, HistoryAction::Accepted)
}

pub(crate) fn proof_submit_errored_history_event(proof: &Proof) -> History {
    proof_history_event(proof, HistoryAction::Errored)
}

fn credential_history_event(credential: &Credential, action: HistoryAction) -> History {
    History {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        action,
        entity_id: Some(credential.id.into()),
        entity_type: HistoryEntityType::Credential,
        metadata: None,
        organisation: credential
            .schema
            .as_ref()
            .and_then(|schema| schema.organisation.to_owned()),
    }
}

fn proof_history_event(proof: &Proof, action: HistoryAction) -> History {
    History {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        action,
        entity_id: Some(proof.id.into()),
        entity_type: HistoryEntityType::Proof,
        metadata: None,
        organisation: proof
            .holder_did
            .as_ref()
            .and_then(|did| did.organisation.to_owned()),
    }
}
