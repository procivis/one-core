use shared_types::WalletAttestationId;

use super::error::DataLayerError;
use crate::model::wallet_attestation::{
    WalletAttestation, WalletAttestationList, WalletAttestationListQuery,
};

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait WalletAttestationRepository: Send + Sync + 'static {
    async fn create(
        &self,
        wallet_attestation: WalletAttestation,
    ) -> Result<WalletAttestationId, DataLayerError>;

    async fn get_attestations(
        &self,
        query: WalletAttestationListQuery,
    ) -> Result<WalletAttestationList, DataLayerError>;
}
