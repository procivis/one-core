use shared_types::{IdentifierId, KeyId};

use crate::utils::api_clients::{HttpClient, Response};

pub struct SignaturesApi {
    client: HttpClient,
}

impl SignaturesApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn create(
        &self,
        issuer: IdentifierId,
        issuer_key: Option<KeyId>,
        signer: String,
        data: serde_json::Value,
    ) -> Response {
        let request = serde_json::json!({
            "issuer": issuer,
            "issuer_key": issuer_key,
            "issuer_certificate": null,
            "signer": signer,
            "data": data
        });
        self.client.post("/api/signature/v1", request).await
    }
}
