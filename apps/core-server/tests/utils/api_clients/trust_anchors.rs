use core_server::endpoint::trust_anchor::dto::TrustAnchorRoleRest;
use serde_json::json;
use uuid::Uuid;

use super::{HttpClient, Response};

pub struct TrustAnchorsApi {
    client: HttpClient,
}

impl TrustAnchorsApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn create(
        &self,
        name: &str,
        organisation_id: impl Into<Uuid>,
        type_: &str,
        role: TrustAnchorRoleRest,
    ) -> Response {
        let body = json!({
          "name": name,
          "type": type_,
          "publisherReference": "",
          "role": role,
          "priority": 10,
          "organisationId": organisation_id.into()
        });

        self.client.post("/api/trust-anchor/v1", body).await
    }
}
