use dto_mapper::try_convert_inner;
use shared_types::EntityId;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::history::{History, HistoryAction, HistoryEntityType};
use crate::model::proof::Proof;
use crate::{
    model::{
        credential_schema::CredentialSchema,
        did::Did,
        proof_schema::{ProofInputClaimSchema, ProofSchema, ProofSchemaClaim},
    },
    service::error::ServiceError,
};

use super::dto::{ConnectVerifierResponseDTO, ProofRequestClaimDTO};

pub fn proof_verifier_to_connect_verifier_response(
    proof_schema: ProofSchema,
    redirect_uri: Option<String>,
    verifier_did: Did,
) -> Result<ConnectVerifierResponseDTO, ServiceError> {
    let claims = match (proof_schema.input_schemas, proof_schema.claim_schemas) {
        (Some(input_schemas), _) if !input_schemas.is_empty() => {
            let mut claim_schemas: Vec<ProofRequestClaimDTO> = vec![];
            for schema in input_schemas {
                let credential_schema = schema.credential_schema.ok_or(
                    ServiceError::MappingError("proof input credential schema is None".to_string()),
                )?;
                let current_claim_schemas = schema.claim_schemas.ok_or(
                    ServiceError::MappingError("proof input claim_schemas is None".to_string()),
                )?;

                let current_claim_schemas = current_claim_schemas.into_iter().map(|claim_schema| {
                    ProofRequestClaimDTO::from((claim_schema, credential_schema.clone()))
                });

                claim_schemas.extend(current_claim_schemas);
            }

            claim_schemas
        }
        // TODO: ONE-1733
        (_, Some(claim_schemas)) if !claim_schemas.is_empty() => try_convert_inner(claim_schemas)?,

        (_, _) => {
            return Err(ServiceError::MappingError(
                "input_schemas or claim_schemas is missing".to_string(),
            ));
        }
    };

    Ok(ConnectVerifierResponseDTO {
        claims,
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

impl From<(ProofInputClaimSchema, CredentialSchema)> for ProofRequestClaimDTO {
    fn from((claim_schema, credential_schema): (ProofInputClaimSchema, CredentialSchema)) -> Self {
        Self {
            id: claim_schema.schema.id,
            created_date: claim_schema.schema.created_date,
            last_modified: claim_schema.schema.last_modified,
            key: claim_schema.schema.key,
            datatype: claim_schema.schema.data_type,
            required: claim_schema.required,
            credential_schema: credential_schema.into(),
        }
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
