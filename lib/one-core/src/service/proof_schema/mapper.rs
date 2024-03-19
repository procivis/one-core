use std::collections::HashMap;

use super::dto::{
    CreateProofSchemaRequestDTO, GetProofSchemaResponseDTO, ProofClaimSchemaResponseDTO,
    ProofInputSchemaResponseDTO, ProofSchemaId,
};
use crate::model::claim_schema::ClaimSchema;
use crate::model::common::ExactColumn;
use crate::model::credential_schema::{CredentialSchema, CredentialSchemaId};
use crate::model::history::{History, HistoryAction, HistoryEntityType};
use crate::model::proof_schema::{ProofInputClaimSchema, ProofInputSchema};
use crate::service::error::BusinessLogicError;
use crate::service::proof_schema::dto::GetProofSchemaQueryDTO;
use crate::{
    model::{organisation::Organisation, proof_schema::ProofSchema},
    service::error::ServiceError,
};
use dto_mapper::{convert_inner, try_convert_inner};
use shared_types::OrganisationId;
use time::OffsetDateTime;
use uuid::Uuid;

impl TryFrom<ProofSchema> for GetProofSchemaResponseDTO {
    type Error = ServiceError;

    fn try_from(value: ProofSchema) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            organisation_id: value
                .organisation
                .ok_or(ServiceError::MappingError(
                    "organisation is None".to_string(),
                ))?
                .id,
            expire_duration: value.expire_duration,
            proof_input_schemas: try_convert_inner(value.input_schemas.ok_or(
                ServiceError::MappingError("proof_input_schemas is None".to_string()),
            )?)?,
        })
    }
}

impl TryFrom<ProofInputSchema> for ProofInputSchemaResponseDTO {
    type Error = ServiceError;

    fn try_from(value: ProofInputSchema) -> Result<Self, Self::Error> {
        let claim_schemas = value.claim_schemas.ok_or(ServiceError::MappingError(
            "claim_schemas is None".to_string(),
        ))?;
        let credential_schema = value.credential_schema.ok_or(ServiceError::MappingError(
            "credential_schema is None".to_string(),
        ))?;

        Ok(Self {
            claim_schemas: convert_inner(claim_schemas),
            credential_schema: credential_schema.into(),
            validity_constraint: value.validity_constraint,
        })
    }
}

impl From<ProofInputClaimSchema> for ProofClaimSchemaResponseDTO {
    fn from(value: ProofInputClaimSchema) -> Self {
        Self {
            id: value.schema.id,
            required: value.required,
            key: value.schema.key,
            data_type: value.schema.data_type,
        }
    }
}

pub fn create_unique_name_check_request(
    name: &str,
    organisation_id: OrganisationId,
) -> Result<GetProofSchemaQueryDTO, ServiceError> {
    Ok(GetProofSchemaQueryDTO {
        page: 0,
        page_size: 1,
        sort: None,
        sort_direction: None,
        exact: Some(vec![ExactColumn::Name]),
        name: Some(name.to_string()),
        organisation_id,
        ids: None,
    })
}

pub fn proof_schema_from_create_request(
    request: CreateProofSchemaRequestDTO,
    now: OffsetDateTime,
    claim_schemas: Vec<ClaimSchema>,
    credential_schemas: Vec<CredentialSchema>,
    organisation: Organisation,
) -> Result<ProofSchema, BusinessLogicError> {
    let mut proof_schema_claims: HashMap<CredentialSchemaId, Vec<ProofInputClaimSchema>> =
        HashMap::new();
    for proof_input_schema in &request.proof_input_schemas {
        let credential_schema_id = proof_input_schema.credential_schema_id;
        for proof_input_claim_schema in &proof_input_schema.claim_schemas {
            for (order, claim_schema) in claim_schemas.iter().enumerate() {
                if claim_schema.id == proof_input_claim_schema.id {
                    let claim = ProofInputClaimSchema {
                        schema: claim_schema.clone(),
                        required: proof_input_claim_schema.required,
                        order: order as u32,
                    };

                    proof_schema_claims
                        .entry(credential_schema_id)
                        .or_default()
                        .push(claim);
                }
            }
        }
    }

    let input_schemas = request
        .proof_input_schemas
        .into_iter()
        .map(|proof_input_schema| {
            let credential_schema_id = proof_input_schema.credential_schema_id;
            let credential_schema = credential_schemas
                .iter()
                .find(|c| c.id == credential_schema_id)
                .cloned()
                .ok_or(BusinessLogicError::MissingCredentialSchema)?;

            let proof_input_schema = ProofInputSchema {
                validity_constraint: proof_input_schema.validity_constraint,
                claim_schemas: proof_schema_claims.get(&credential_schema_id).cloned(),
                credential_schema: Some(credential_schema),
            };

            Ok::<_, BusinessLogicError>(proof_input_schema)
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(ProofSchema {
        id: Uuid::new_v4(),
        created_date: now,
        last_modified: now,
        name: request.name,
        expire_duration: request.expire_duration,
        organisation: Some(organisation),
        deleted_at: None,
        input_schemas: Some(input_schemas),
    })
}

pub(super) fn proof_schema_created_history_event(
    id: ProofSchemaId,
    organisation: Organisation,
) -> History {
    History {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        action: HistoryAction::Created,
        entity_id: Some(id.into()),
        entity_type: HistoryEntityType::ProofSchema,
        metadata: None,
        organisation: Some(organisation),
    }
}

pub(super) fn proof_schema_deleted_history_event(proof_schema: ProofSchema) -> History {
    History {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        action: HistoryAction::Deleted,
        entity_id: Some(proof_schema.id.into()),
        entity_type: HistoryEntityType::ProofSchema,
        metadata: None,
        organisation: proof_schema.organisation,
    }
}
