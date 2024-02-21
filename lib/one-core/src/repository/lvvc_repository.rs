use crate::model::credential::CredentialId;
use crate::model::lvvc::Lvvc;

use super::error::DataLayerError;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait LvvcRepository: Send + Sync + 'static {
    async fn insert(&self, lvvc: Lvvc) -> Result<(), DataLayerError>;

    async fn get_latest_by_credential_id(
        &self,
        credential_id: CredentialId,
    ) -> Result<Option<Lvvc>, DataLayerError>;

    async fn get_all_by_credential_id(
        &self,
        credential_id: CredentialId,
    ) -> Result<Vec<Lvvc>, DataLayerError>;
}
