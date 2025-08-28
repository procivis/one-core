use crate::model::wallet_unit_attestation::WalletUnitAttestation;
use crate::service::wallet_unit::dto::HolderWalletUnitAttestationResponseDTO;

impl From<WalletUnitAttestation> for HolderWalletUnitAttestationResponseDTO {
    fn from(value: WalletUnitAttestation) -> Self {
        Self {
            created_date: value.created_date,
            last_modified: value.last_modified,
            id: value.id,
            expiration_date: value.expiration_date,
            status: value.status,
            attestation: value.attestation,
            wallet_unit_id: value.wallet_unit_id,
            wallet_provider_url: value.wallet_provider_url,
            wallet_provider_type: value.wallet_provider_type,
            wallet_provider_name: value.wallet_provider_name,
        }
    }
}
