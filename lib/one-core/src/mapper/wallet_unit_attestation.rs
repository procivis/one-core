use crate::model::credential_schema::WalletStorageTypeEnum;
use crate::model::wallet_unit_attestation::{
    KeyStorageSecurityLevel, UpdateWalletUnitAttestationRequest, WalletUnitAttestation,
};

impl From<WalletUnitAttestation> for UpdateWalletUnitAttestationRequest {
    fn from(value: WalletUnitAttestation) -> Self {
        Self {
            expiration_date: Some(value.expiration_date),
            attestation: Some(value.attestation),
        }
    }
}

impl From<WalletStorageTypeEnum> for KeyStorageSecurityLevel {
    fn from(value: WalletStorageTypeEnum) -> Self {
        match value {
            WalletStorageTypeEnum::RemoteSecureElement => KeyStorageSecurityLevel::High,
            WalletStorageTypeEnum::Hardware => KeyStorageSecurityLevel::Moderate,
            WalletStorageTypeEnum::Software => KeyStorageSecurityLevel::Basic,
        }
    }
}

impl From<KeyStorageSecurityLevel> for WalletStorageTypeEnum {
    fn from(value: KeyStorageSecurityLevel) -> Self {
        match value {
            KeyStorageSecurityLevel::High => WalletStorageTypeEnum::RemoteSecureElement,
            KeyStorageSecurityLevel::Moderate | KeyStorageSecurityLevel::EnhancedBasic => {
                WalletStorageTypeEnum::Hardware
            }
            KeyStorageSecurityLevel::Basic => WalletStorageTypeEnum::Software,
        }
    }
}
