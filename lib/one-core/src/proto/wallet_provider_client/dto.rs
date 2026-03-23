use crate::service::wallet_provider::dto::IssueWalletUnitAttestationResponseDTO;

#[derive(Clone, Debug)]
pub enum IssueWalletAttestationResponse {
    Active(IssueWalletUnitAttestationResponseDTO),
    Revoked,
}
