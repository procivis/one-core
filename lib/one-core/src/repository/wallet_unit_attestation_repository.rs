use shared_types::{OrganisationId, WalletUnitAttestationId};

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

    async fn get_wallet_unit_attestation_by_organisation(
        &self,
        organisation_id: &OrganisationId,
        relations: &WalletUnitAttestationRelations,
    ) -> Result<Option<WalletUnitAttestation>, DataLayerError>;

    async fn update_wallet_attestation(
        &self,
        id: &WalletUnitAttestationId,
        request: UpdateWalletUnitAttestationRequest,
    ) -> Result<(), DataLayerError>;
}
