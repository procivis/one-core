use one_core::service::credential::dto::{CreateCredentialRequestDTO, CredentialDetailResponseDTO};

use crate::endpoint::credential::dto::{
    CreateCredentialRequestRestDTO, GetCredentialResponseRestDTO,
};

impl From<CredentialDetailResponseDTO> for GetCredentialResponseRestDTO {
    fn from(value: CredentialDetailResponseDTO) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            issuance_date: value.issuance_date,
            state: value.state.into(),
            revocation_date: value.revocation_date,
            last_modified: value.last_modified,
            schema: value.schema.into(),
            issuer_did: value.issuer_did,
            claims: value.claims.into_iter().map(|claim| claim.into()).collect(),
        }
    }
}

impl From<CreateCredentialRequestRestDTO> for CreateCredentialRequestDTO {
    fn from(value: CreateCredentialRequestRestDTO) -> Self {
        Self {
            credential_schema_id: value.credential_schema_id,
            issuer_did: value.issuer_did,
            transport: value.transport,
            claim_values: value
                .claim_values
                .into_iter()
                .map(|claim| claim.into())
                .collect(),
        }
    }
}
