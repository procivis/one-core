use core_server::endpoint::trust_entity::dto::TrustEntityRoleRest;
use serde_json::json;
use shared_types::TrustEntityId;
use uuid::Uuid;

use super::{HttpClient, Response};

pub struct TrustEntitiesApi {
    client: HttpClient,
}

impl TrustEntitiesApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn create(
        &self,
        entity_id: &str,
        name: &str,
        role: TrustEntityRoleRest,
        trust_anchor_id: impl Into<Uuid>,
    ) -> Response {
        let body = json!({
          "entityId": entity_id,
          "name": name,
          "role": role,
          "trustAnchorId": trust_anchor_id.into(),
        });

        self.client.post("/api/trust-entity/v1", body).await
    }

    pub async fn delete(&self, id: TrustEntityId) -> Response {
        self.client
            .delete(&format!("/api/trust-entity/v1/{id}"))
            .await
    }
}
