use core_server::endpoint::trust_anchor::dto::TrustAnchorRoleRest;
use one_core::model::organisation::Organisation;
use serde_json::json;
use shared_types::OrganisationId;
use uuid::Uuid;

use super::{HttpClient, Response};

pub struct TrustAnchorsApi {
    client: HttpClient,
}

pub struct ListFilters {
    pub organisation_id: OrganisationId,
    pub name: Option<String>,
}

impl TrustAnchorsApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn create(
        &self,
        name: &str,
        organisation: &Organisation,
        type_: &str,
        role: TrustAnchorRoleRest,
    ) -> Response {
        let body = json!({
          "name": name,
          "type": type_,
          "publisherReference": "",
          "role": role,
          "priority": 10,
          "organisationId": organisation.id
        });

        self.client.post("/api/trust-anchor/v1", body).await
    }

    pub async fn get(&self, trust_anchor: impl Into<Uuid>) -> Response {
        let url = format!("/api/trust-anchor/v1/{}", trust_anchor.into());
        self.client.get(&url).await
    }

    pub async fn list(&self, page: usize, filters: ListFilters) -> Response {
        let ListFilters {
            organisation_id,
            name,
        } = filters;

        let mut url = format!(
            "/api/trust-anchor/v1?pageSize=20&page={page}&organisationId={organisation_id}"
        );

        if let Some(name) = name {
            url += &format!("&name={name}")
        }

        self.client.get(&url).await
    }

    pub async fn delete(&self, trust_anchor: impl Into<Uuid>) -> Response {
        let url = format!("/api/trust-anchor/v1/{}", trust_anchor.into());
        self.client.delete(&url).await
    }
}
