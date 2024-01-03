use serde_json::json;
use uuid::Uuid;

use super::{HttpClient, Response};

pub struct InteractionsApi {
    client: HttpClient,
}

impl InteractionsApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn handle_invitation(&self, did_id: impl Into<Uuid>, url: &str) -> Response {
        let body = json!({
          "didId": did_id.into(),
          "url": url,
        });

        self.client
            .post("/api/interaction/v1/handle-invitation", body)
            .await
    }

    pub async fn issuance_reject(&self, interaction_id: impl Into<Uuid>) -> Response {
        let body = json!({
          "interactionId": interaction_id.into(),
        });

        self.client
            .post("/api/interaction/v1/issuance-reject", body)
            .await
    }
}
