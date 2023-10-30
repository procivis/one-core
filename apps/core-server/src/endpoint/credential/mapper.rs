use one_core::service::credential::dto::CredentialRequestClaimDTO;

use crate::endpoint::credential::dto::CredentialRequestClaimRestDTO;

impl From<CredentialRequestClaimRestDTO> for CredentialRequestClaimDTO {
    fn from(value: CredentialRequestClaimRestDTO) -> Self {
        Self {
            claim_schema_id: value.claim_id,
            value: value.value,
        }
    }
}
