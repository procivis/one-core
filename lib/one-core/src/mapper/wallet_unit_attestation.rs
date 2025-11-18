use crate::model::wallet_unit_attestation::{
    UpdateWalletUnitAttestationRequest, WalletUnitAttestation,
};

impl From<WalletUnitAttestation> for UpdateWalletUnitAttestationRequest {
    fn from(value: WalletUnitAttestation) -> Self {
        Self {
            expiration_date: Some(value.expiration_date),
            attestation: Some(value.attestation),
        }
    }
}
