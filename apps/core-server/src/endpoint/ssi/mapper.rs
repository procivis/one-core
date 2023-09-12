use super::dto::{
    ConnectIssuerResponseRestDTO, ConnectVerifierResponseRestDTO, ProofRequestClaimRestDTO,
};
use one_core::{
    common_mapper::vector_into,
    service::{
        ssi_issuer::dto::ConnectIssuerResponseDTO,
        ssi_verifier::dto::{ConnectVerifierResponseDTO, ProofRequestClaimDTO},
    },
};

impl From<ConnectVerifierResponseDTO> for ConnectVerifierResponseRestDTO {
    fn from(value: ConnectVerifierResponseDTO) -> Self {
        Self {
            claims: vector_into(value.claims),
        }
    }
}

impl From<ProofRequestClaimDTO> for ProofRequestClaimRestDTO {
    fn from(value: ProofRequestClaimDTO) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            key: value.key,
            datatype: value.datatype,
            required: value.required,
            credential_schema: value.credential_schema.into(),
        }
    }
}

impl From<ConnectIssuerResponseDTO> for ConnectIssuerResponseRestDTO {
    fn from(value: ConnectIssuerResponseDTO) -> Self {
        Self {
            credential: value.credential,
            format: value.format,
        }
    }
}
