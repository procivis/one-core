pub mod error;
pub mod model;
pub mod provider;
pub mod simple_list;

use std::collections::HashMap;

use serde::Serialize;
use shared_types::TrustEntityKey;

use crate::model::trust_anchor::TrustAnchor;
use crate::model::trust_entity::{TrustEntity, TrustEntityType};
use crate::provider::trust_management::error::TrustManagementError;
use crate::provider::trust_management::model::TrustEntityByEntityKey;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait TrustManagement: Send + Sync {
    fn get_capabilities(&self) -> TrustCapabilities;

    async fn publish_entity(&self, anchor: &TrustAnchor, entity: &TrustEntity);

    async fn lookup_entity_key(
        &self,
        anchor: &TrustAnchor,
        entity_key: &TrustEntityKey,
    ) -> Result<Option<TrustEntityByEntityKey>, TrustManagementError>;

    /// Look up many trust entities at once, expecting at most one result per batch.
    /// Returns a map of batch_id -> trust entity for all batches that yielded a result.
    async fn lookup_entity_keys(
        &self,
        anchor: &TrustAnchor,
        entity_key_batches: &[TrustEntityKeyBatch],
    ) -> Result<HashMap<String, TrustEntityByEntityKey>, TrustManagementError>;
}

pub struct TrustEntityKeyBatch {
    pub batch_id: String,
    pub trust_entity_keys: Vec<TrustEntityKey>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustCapabilities {
    pub operations: Vec<TrustOperation>,
    pub supported_types: Vec<TrustEntityType>,
}

#[derive(Clone, Copy, Debug, Serialize, Eq, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustOperation {
    Publish,
    Lookup,
}
