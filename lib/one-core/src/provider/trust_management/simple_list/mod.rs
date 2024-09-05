use shared_types::DidValue;

use super::{TrustCapabilities, TrustManagement, TrustOperations};
use crate::model::trust_anchor::TrustAnchor;
use crate::model::trust_entity::TrustEntity;

pub struct SimpleList {}

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
    async fn lookup_did(&self, _anchor: &TrustAnchor, _did: &DidValue) {}
}
