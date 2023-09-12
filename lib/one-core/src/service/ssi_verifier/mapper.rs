use crate::{
    common_mapper::vector_try_into,
    model::proof_schema::{ProofSchema, ProofSchemaClaim},
    service::error::ServiceError,
};

use super::dto::{ConnectVerifierResponseDTO, ProofRequestClaimDTO};

impl TryFrom<ProofSchema> for ConnectVerifierResponseDTO {
    type Error = ServiceError;

    fn try_from(value: ProofSchema) -> Result<Self, Self::Error> {
        Ok(Self {
            claims: vector_try_into(value.claim_schemas.ok_or(ServiceError::MappingError(
                "claim_schemas is None".to_string(),
            ))?)?,
        })
    }
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
                .try_into()?,
        })
    }
}
