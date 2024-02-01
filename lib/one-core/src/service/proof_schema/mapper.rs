use super::dto::{
    CreateProofSchemaRequestDTO, GetProofSchemaResponseDTO, ProofClaimSchemaResponseDTO,
    ProofSchemaId,
};
use crate::model::common::ExactColumn;
use crate::model::history::{History, HistoryAction, HistoryEntityType};
use crate::service::proof_schema::dto::GetProofSchemaQueryDTO;
use crate::{
    model::{
        organisation::Organisation,
        organisation::OrganisationId,
        proof_schema::{ProofSchema, ProofSchemaClaim},
    },
    service::error::ServiceError,
};
use dto_mapper::try_convert_inner;
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
            claim_schemas: try_convert_inner(value.claim_schemas.ok_or(
                ServiceError::MappingError("claim_schemas is None".to_string()),
            )?)?,
        })
    }
}

impl TryFrom<ProofSchemaClaim> for ProofClaimSchemaResponseDTO {
    type Error = ServiceError;
    fn try_from(value: ProofSchemaClaim) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.schema.id,
            required: value.required,
            key: value.schema.key,
            data_type: value.schema.data_type,
            credential_schema: value
                .credential_schema
                .ok_or(ServiceError::MappingError(
                    "credential_schema is None".to_string(),
                ))?
                .into(),
        })
    }
}

pub fn create_unique_name_check_request(
    name: &str,
    organisation_id: &OrganisationId,
) -> Result<GetProofSchemaQueryDTO, ServiceError> {
    Ok(GetProofSchemaQueryDTO {
        page: 0,
        page_size: 1,
        sort: None,
        sort_direction: None,
        exact: Some(vec![ExactColumn::Name]),
        name: Some(name.to_string()),
        organisation_id: organisation_id.to_string(),
    })
}

pub fn proof_schema_from_create_request(
    request: CreateProofSchemaRequestDTO,
    now: OffsetDateTime,
    claim_schemas: Vec<ProofSchemaClaim>,
    organisation: Organisation,
) -> ProofSchema {
    ProofSchema {
        id: Uuid::new_v4(),
        created_date: now,
        last_modified: now,
        name: request.name,
        expire_duration: request.expire_duration,
        claim_schemas: Some(claim_schemas),
        organisation: Some(organisation),
        deleted_at: None,
    }
}

pub(super) fn proof_schema_created_history_event(
    id: ProofSchemaId,
    organisation: Organisation,
) -> History {
    History {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        action: HistoryAction::Created,
        entity_id: id.into(),
        entity_type: HistoryEntityType::ProofSchema,
        organisation: Some(organisation),
    }
}

pub(super) fn proof_schema_deleted_history_event(proof_schema: ProofSchema) -> History {
    History {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        action: HistoryAction::Deleted,
        entity_id: proof_schema.id.into(),
        entity_type: HistoryEntityType::ProofSchema,
        organisation: proof_schema.organisation,
    }
}
