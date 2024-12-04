use serde::Deserialize;
mod model;

use std::sync::Arc;

use anyhow::Context;
use shared_types::DidValue;

use super::{TrustCapabilities, TrustManagement, TrustOperations};
use crate::model::trust_anchor::TrustAnchor;
use crate::model::trust_entity::TrustEntity;
use crate::provider::caching_loader::trust_list::TrustListCache;
use crate::provider::http_client::HttpClient;
use crate::provider::trust_management::error::TrustManagementError;
use crate::provider::trust_management::model::TrustEntityByDid;
use crate::provider::trust_management::simple_list::model::GetTrustAnchorResponseRestDTO;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    pub enable_publishing: bool,
}

pub struct SimpleList {
    pub params: Params,
    pub client: Arc<dyn HttpClient>,
    pub trust_list_cache: Arc<TrustListCache>,
}

#[async_trait::async_trait]
impl TrustManagement for SimpleList {
    fn get_capabilities(&self) -> TrustCapabilities {
        TrustCapabilities {
            operations: vec![TrustOperations::Publish],
            formats: vec![],
            exchange: vec![],
        }
    }

    async fn publish_entity(&self, _anchor: &TrustAnchor, _entity: &TrustEntity) {}

    fn is_enabled(&self) -> bool {
        self.params.enable_publishing
    }
    async fn lookup_did(
        &self,
        anchor: &TrustAnchor,
        did: &DidValue,
    ) -> Result<Option<TrustEntityByDid>, TrustManagementError> {
        let response = self
            .trust_list_cache
            .get(&anchor.publisher_reference)
            .await
            .context(format!(
                "Failed to fetch trust list from publisher reference '{}'",
                anchor.publisher_reference
            ))
            .map_err(TrustManagementError::Transport)?;

        let trust_list: GetTrustAnchorResponseRestDTO = serde_json::from_value(response)
            .context("Failed to parse trust list response")
            .map_err(TrustManagementError::MappingError)?;

        Ok(trust_list
            .entities
            .into_iter()
            .find(|entity| &entity.did == did))
    }
}
