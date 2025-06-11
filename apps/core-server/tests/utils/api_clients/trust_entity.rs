use core_server::endpoint::ssi::dto::{
    PatchTrustEntityActionRestDTO, PatchTrustEntityRequestRestDTO,
};
use core_server::endpoint::trust_entity::dto::TrustEntityRoleRest;
use one_core::model::did::Did;
use one_core::model::trust_anchor::TrustAnchor;
use serde_json::json;
use shared_types::{DidId, TrustAnchorId, TrustEntityId};

use super::{HttpClient, Response};

pub struct TrustEntitiesApi {
    client: HttpClient,
}

#[derive(Default)]
pub struct ListFilters {
    pub role: Option<TrustEntityRoleRest>,
    pub anchor_id: Option<TrustAnchorId>,
    pub name: Option<String>,
    pub did_id: Option<DidId>,
}

impl TrustEntitiesApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn create(
        &self,
        name: &str,
        role: TrustEntityRoleRest,
        trust_anchor: &TrustAnchor,
        did: &Did,
    ) -> Response {
        let body = json!({
          "name": name,
          "role": role,
          "trustAnchorId": trust_anchor.id,
          "didId": did.id,
        });

        self.client.post("/api/trust-entity/v1", body).await
    }

    pub async fn patch(
        &self,
        id: TrustEntityId,
        action: PatchTrustEntityActionRestDTO,
    ) -> Response {
        let body = json!({
          "action": action,
        });
        self.client
            .patch(&format!("/api/trust-entity/v1/{id}"), body)
            .await
    }

    pub async fn get(&self, id: TrustEntityId) -> Response {
        let url = format!("/api/trust-entity/v1/{id}");
        self.client.get(&url).await
    }

    pub async fn list(&self, page: usize, filters: ListFilters) -> Response {
        let ListFilters {
            role,
            name,
            anchor_id,
            did_id,
        } = filters;

        let mut url = format!("/api/trust-entity/v1?pageSize=20&page={page}");

        if let Some(role) = role {
            let role = match role {
                TrustEntityRoleRest::Issuer => "ISSUER",
                TrustEntityRoleRest::Verifier => "VERIFIER",
                TrustEntityRoleRest::Both => "BOTH",
            };
            url += &format!("&role={role}")
        }

        if let Some(name) = name {
            url += &format!("&name={name}")
        }

        if let Some(anchor_id) = anchor_id {
            url += &format!("&trustAnchorId={anchor_id}")
        }

        if let Some(did_id) = did_id {
            url += &format!("&didId={did_id}")
        }

        self.client.get(&url).await
    }

    pub async fn create_remote(
        &self,
        name: &str,
        role: TrustEntityRoleRest,
        trust_anchor: Option<TrustAnchor>,
        did: &Did,
        logo: Option<String>,
    ) -> Response {
        let mut body = json!({
          "name": name,
          "role": role,
          "trustAnchorId": trust_anchor.map(|anchor| anchor.id),
          "didId": did.id,
        });

        if let Some(logo) = logo {
            body["logo"] = json!(logo);
        }

        self.client.post("/api/trust-entity/remote/v1", body).await
    }

    pub async fn update(
        &self,
        id: TrustEntityId,
        request: PatchTrustEntityRequestRestDTO,
    ) -> Response {
        let body = json!(request);
        self.client
            .patch(&format!("/api/trust-entity/v1/{}", id), body)
            .await
    }

    pub async fn update_remote(
        &self,
        did: &Did,
        request: PatchTrustEntityRequestRestDTO,
    ) -> Response {
        let body = json!(request);
        self.client
            .patch(&format!("/api/trust-entity/remote/v1/{}", did.id), body)
            .await
    }

    pub async fn get_remote(&self, did: &Did) -> Response {
        self.client
            .get(&format!("/api/trust-entity/remote/v1/{}", did.id))
            .await
    }
}
