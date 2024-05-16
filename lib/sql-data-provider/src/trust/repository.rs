use autometrics::autometrics;
use one_core::repository::{error::DataLayerError, trust_repository::TrustRepository};
use shared_types::TrustAnchorId;

use super::TrustProvider;

#[autometrics]
#[async_trait::async_trait]
impl TrustRepository for TrustProvider {
    async fn create_trust_anchor(&self) -> Result<TrustAnchorId, DataLayerError> {
        todo!()
    }
}
