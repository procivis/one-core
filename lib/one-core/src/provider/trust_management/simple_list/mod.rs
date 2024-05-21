use shared_types::DidValue;

use crate::model::{trust_anchor::TrustAnchor, trust_entity::TrustEntity};

use super::{TrustCapabilities, TrustManagement, TrustOperations};

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
