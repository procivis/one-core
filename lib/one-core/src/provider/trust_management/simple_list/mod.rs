use std::collections::HashMap;

use serde::Deserialize;
mod model;

use std::sync::Arc;

use anyhow::Context;
use shared_types::TrustEntityKey;

use super::{TrustCapabilities, TrustEntityKeyBatch, TrustManagement, TrustOperation};
use crate::model::trust_anchor::TrustAnchor;
use crate::model::trust_entity::{TrustEntity, TrustEntityType};
use crate::provider::caching_loader::trust_list::TrustListCache;
use crate::provider::http_client::HttpClient;
use crate::provider::trust_management::error::TrustManagementError;
use crate::provider::trust_management::model::TrustEntityByEntityKey;
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
        let mut operations = vec![TrustOperation::Lookup];
        if self.params.enable_publishing {
            operations.push(TrustOperation::Publish);
        }
        TrustCapabilities {
            operations,
            supported_types: vec![TrustEntityType::Did, TrustEntityType::CertificateAuthority],
        }
    }

    async fn publish_entity(&self, _anchor: &TrustAnchor, _entity: &TrustEntity) {}

    async fn lookup_entity_key(
        &self,
        anchor: &TrustAnchor,
        entity_key: &TrustEntityKey,
    ) -> Result<Option<TrustEntityByEntityKey>, TrustManagementError> {
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
            .find(|entity| entity.entity_key == *entity_key))
    }

    async fn lookup_entity_keys(
        &self,
        anchor: &TrustAnchor,
        entity_key_batches: &[TrustEntityKeyBatch],
    ) -> Result<HashMap<String, TrustEntityByEntityKey>, TrustManagementError> {
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

        let listed_entities: HashMap<_, _> = trust_list
            .entities
            .into_iter()
            .map(|entity| (entity.entity_key.clone(), entity))
            .collect();

        let mut result = HashMap::new();
        for batch in entity_key_batches {
            let Some(entity) = batch
                .trust_entity_keys
                .iter()
                .find_map(|entity_key| listed_entities.get(entity_key))
            else {
                continue;
            };
            result.insert(batch.batch_id.clone(), entity.clone());
        }
        Ok(result)
    }
}
