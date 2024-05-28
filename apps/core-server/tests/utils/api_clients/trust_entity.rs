use core_server::endpoint::trust_entity::dto::TrustEntityRoleRest;
use one_core::model::trust_anchor::TrustAnchor;
use serde_json::json;
use shared_types::{OrganisationId, TrustAnchorId, TrustEntityId};

use super::{HttpClient, Response};

pub struct TrustEntitiesApi {
    client: HttpClient,
}

pub struct ListFilters {
    pub organisation_id: OrganisationId,
    pub anchor_id: Option<TrustAnchorId>,
    pub name: Option<String>,
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
        trust_anchor: &TrustAnchor,
    ) -> Response {
        let body = json!({
          "entityId": entity_id,
          "name": name,
          "role": role,
          "trustAnchorId": trust_anchor.id,
        });

        self.client.post("/api/trust-entity/v1", body).await
    }

    pub async fn delete(&self, id: TrustEntityId) -> Response {
        self.client
            .delete(&format!("/api/trust-entity/v1/{id}"))
            .await
    }

    pub async fn get(&self, id: TrustEntityId) -> Response {
        let url = format!("/api/trust-entity/v1/{id}");
        self.client.get(&url).await
    }

    pub async fn list(&self, page: usize, filters: ListFilters) -> Response {
        let ListFilters {
            organisation_id,
            name,
            anchor_id,
        } = filters;

        let mut url = format!(
            "/api/trust-entity/v1?pageSize=20&page={page}&organisationId={organisation_id}"
        );

        if let Some(name) = name {
            url += &format!("&name={name}")
        }

        if let Some(anchor_id) = anchor_id {
            url += &format!("&trustAnchorId={anchor_id}")
        }

        self.client.get(&url).await
    }
}
