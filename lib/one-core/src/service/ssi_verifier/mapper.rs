use dto_mapper::try_convert_inner;
use shared_types::EntityId;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::history::{History, HistoryAction, HistoryEntityType};
use crate::model::proof::Proof;
use crate::{
    model::{
        did::Did,
        proof_schema::{ProofSchema, ProofSchemaClaim},
    },
    service::error::ServiceError,
};

use super::dto::{ConnectVerifierResponseDTO, ProofRequestClaimDTO};

pub fn proof_verifier_to_connect_verifier_response(
    proof_schema: ProofSchema,
    redirect_uri: Option<String>,
    verifier_did: Did,
) -> Result<ConnectVerifierResponseDTO, ServiceError> {
    Ok(ConnectVerifierResponseDTO {
        claims: try_convert_inner(proof_schema.claim_schemas.ok_or(
            ServiceError::MappingError("claim_schemas is None".to_string()),
        )?)?,
        redirect_uri,
        verifier_did: verifier_did.did,
    })
}

impl TryFrom<ProofSchemaClaim> for ProofRequestClaimDTO {
    type Error = ServiceError;

    fn try_from(value: ProofSchemaClaim) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.schema.id,
            created_date: value.schema.created_date,
            last_modified: value.schema.last_modified,
            key: value.schema.key,
            datatype: value.schema.data_type,
            required: value.required,
            credential_schema: value
                .credential_schema
                .ok_or(ServiceError::MappingError(
                    "credential_schema is None".to_string(),
                ))?
                .into(),
        })
    }
}

pub(crate) fn proof_rejected_history_event(proof: &Proof) -> History {
    history_event(
        proof.id.into(),
        proof.verifier_did.as_ref(),
        HistoryEntityType::Proof,
        HistoryAction::Rejected,
    )
}

pub(crate) fn proof_accepted_history_event(proof: &Proof) -> History {
    history_event(
        proof.id.into(),
        proof.verifier_did.as_ref(),
        HistoryEntityType::Proof,
        HistoryAction::Accepted,
    )
}

fn history_event(
    entity_id: EntityId,
    verifier_did: Option<&Did>,
    entity_type: HistoryEntityType,
    action: HistoryAction,
) -> History {
    let organisation = verifier_did.and_then(|did| did.organisation.clone());

    History {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        action,
        entity_id: entity_id.into(),
        entity_type,
        metadata: None,
        organisation,
    }
}
