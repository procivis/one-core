use shared_types::KeyId;
use time::OffsetDateTime;

use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::model::wallet_unit_attestation::WalletUnitAttestation;
use crate::provider::key_storage::model::StorageGeneratedKey;
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

pub(super) fn key_from_generated_key(
    key_id: KeyId,
    key_storage_id: &str,
    key_type: &str,
    organisation: Organisation,
    generated_key: StorageGeneratedKey,
) -> Key {
    let now = OffsetDateTime::now_utc();

    Key {
        id: key_id,
        created_date: now,
        last_modified: now,
        public_key: generated_key.public_key,
        name: format!("Wallet unit key {key_id}"),
        key_reference: generated_key.key_reference,
        storage_type: key_storage_id.to_string(),
        key_type: key_type.to_string(),
        organisation: Some(organisation),
    }
}
