pub mod error;
pub mod model;
pub mod provider;
pub mod simple_list;

use serde::Serialize;
use shared_types::DidValue;

use crate::model::trust_anchor::TrustAnchor;
use crate::model::trust_entity::TrustEntity;
use crate::provider::trust_management::error::TrustManagementError;
use crate::provider::trust_management::model::TrustEntityByDid;

#[async_trait::async_trait]
pub trait TrustManagement: Send + Sync {
    fn get_capabilities(&self) -> TrustCapabilities;
    async fn publish_entity(&self, anchor: &TrustAnchor, entity: &TrustEntity);
    fn is_enabled(&self) -> bool;
    async fn lookup_did(
        &self,
        anchor: &TrustAnchor,
        did: &DidValue,
    ) -> Result<Option<TrustEntityByDid>, TrustManagementError>;
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustCapabilities {
    operations: Vec<TrustOperations>,
    formats: Vec<String>,
    exchange: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustOperations {
    Publish,
    Lookup,
}
