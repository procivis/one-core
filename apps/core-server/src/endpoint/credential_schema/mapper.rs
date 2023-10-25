use crate::endpoint::credential_schema::dto::{
    CreateCredentialSchemaRequestRestDTO, CredentialSchemaResponseRestDTO,
};
use one_core::service::credential_schema::dto::{
    CreateCredentialSchemaRequestDTO, CredentialSchemaDetailResponseDTO,
};

impl From<CredentialSchemaDetailResponseDTO> for CredentialSchemaResponseRestDTO {
    fn from(value: CredentialSchemaDetailResponseDTO) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            format: value.format,
            revocation_method: value.revocation_method,
            organisation_id: value.organisation_id,
            claims: value.claims.into_iter().map(|claim| claim.into()).collect(),
        }
    }
}

impl From<CreateCredentialSchemaRequestRestDTO> for CreateCredentialSchemaRequestDTO {
    fn from(value: CreateCredentialSchemaRequestRestDTO) -> Self {
        CreateCredentialSchemaRequestDTO {
            name: value.name,
            format: value.format,
            revocation_method: value.revocation_method,
            organisation_id: value.organisation_id,
            claims: value.claims.into_iter().map(|claim| claim.into()).collect(),
        }
    }
}
