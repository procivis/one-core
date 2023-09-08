use time::OffsetDateTime;
use uuid::Uuid;

use super::dto::{
    CreateProofSchemaRequestDTO, GetProofSchemaListItemDTO, GetProofSchemaResponseDTO,
    ProofClaimSchemaResponseDTO,
};
use crate::{
    common_mapper::vector_try_into,
    model::{
        organisation::Organisation,
        proof_schema::{ProofSchema, ProofSchemaClaim},
    },
    service::error::ServiceError,
};

impl TryFrom<ProofSchema> for GetProofSchemaResponseDTO {
    type Error = ServiceError;

    fn try_from(value: ProofSchema) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            organisation_id: value.organisation.ok_or(ServiceError::NotFound)?.id,
            expire_duration: value.expire_duration,
            claim_schemas: vector_try_into(value.claim_schemas.ok_or(ServiceError::NotFound)?)?,
        })
    }
}

impl From<ProofSchema> for GetProofSchemaListItemDTO {
    fn from(value: ProofSchema) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            expire_duration: value.expire_duration,
        }
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
                .ok_or(ServiceError::NotFound)?
                .try_into()?,
        })
    }
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
    }
}
