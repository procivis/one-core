use shared_types::{HolderWalletUnitId, KeyId, WalletUnitAttestationId};

use super::error::DataLayerError;
use crate::model::wallet_unit_attestation::{
    UpdateWalletUnitAttestationRequest, WalletUnitAttestation, WalletUnitAttestationRelations,
};

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait WalletUnitAttestationRepository: Send + Sync + 'static {
    async fn create_wallet_unit_attestation(
        &self,
        wallet_unit_attestation: WalletUnitAttestation,
    ) -> Result<WalletUnitAttestationId, DataLayerError>;

    async fn get_wallet_unit_attestation_by_key_id(
        &self,
        key_id: &KeyId,
    ) -> Result<Option<WalletUnitAttestation>, DataLayerError>;

    async fn get_wallet_unit_attestations_by_holder_wallet_unit(
        &self,
        holder_wallet_unit_id: &HolderWalletUnitId,
        relations: &WalletUnitAttestationRelations,
    ) -> Result<Vec<WalletUnitAttestation>, DataLayerError>;

    async fn update_wallet_attestation(
        &self,
        id: &WalletUnitAttestationId,
        request: UpdateWalletUnitAttestationRequest,
    ) -> Result<(), DataLayerError>;
}
