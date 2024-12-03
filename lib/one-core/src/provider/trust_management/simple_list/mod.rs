use serde::Deserialize;
mod model;

use std::sync::Arc;

use anyhow::Context;
use shared_types::DidValue;

use super::{TrustCapabilities, TrustManagement, TrustOperations};
use crate::model::trust_anchor::TrustAnchor;
use crate::model::trust_entity::TrustEntity;
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
        // todo: use remote entity cache

        let trust_list: GetTrustAnchorResponseRestDTO = self
            .client
            .get(&anchor.publisher_reference)
            .send()
            .await
            .context(format!(
                "Failed to fetch trust list from publisher reference '{}'",
                anchor.publisher_reference
            ))
            .map_err(TrustManagementError::Transport)?
            .json()
            .context("Failed to parse trust list response")
            .map_err(TrustManagementError::MappingError)?;

        Ok(trust_list
            .entities
            .into_iter()
            .find(|entity| &entity.did == did))
    }
}
