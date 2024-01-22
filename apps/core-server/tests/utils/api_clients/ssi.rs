use std::fmt::Display;

use serde_json::json;

use super::{HttpClient, Response};

pub struct SSIApi {
    client: HttpClient,
}

impl SSIApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn temporary_connect(&self, credential_id: impl Display) -> Response {
        let url = format!(
            "/ssi/temporary-issuer/v1/connect?protocol=PROCIVIS_TEMPORARY&credential={credential_id}"
        );

        let body = json!({
          "did": "did:key:test"
        });

        self.client.post(&url, body).await
    }
}
