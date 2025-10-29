use dto::IssueWalletUnitAttestationResponseDTO;

use crate::service::wallet_provider::dto;

#[derive(Clone, Debug)]
pub enum IssueWalletAttestationResponse {
    Active(IssueWalletUnitAttestationResponseDTO),
    Revoked,
}
