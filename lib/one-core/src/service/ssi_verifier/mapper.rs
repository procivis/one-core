use crate::{
    common_mapper::vector_try_into,
    model::{
        did::Did,
        proof_schema::{ProofSchema, ProofSchemaClaim},
    },
    service::error::ServiceError,
};

use super::dto::{ConnectVerifierResponseDTO, ProofRequestClaimDTO};

pub fn proof_verifier_to_connect_verifier_response(
    proof_schema: ProofSchema,
    verifier_did: Did,
) -> Result<ConnectVerifierResponseDTO, ServiceError> {
    Ok(ConnectVerifierResponseDTO {
        claims: vector_try_into(
            proof_schema
                .claim_schemas
                .ok_or(ServiceError::MappingError(
                    "claim_schemas is None".to_string(),
                ))?,
        )?,
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
