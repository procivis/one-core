use serde::Serialize;
use serde_with::skip_serializing_none;
use shared_types::{CertificateId, IdentifierId, KeyId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::utils::api_clients::{HttpClient, Response};

pub struct SignaturesApi {
    client: HttpClient,
}

#[skip_serializing_none]
#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TestCreateSignatureRequest {
    pub issuer: IdentifierId,
    pub issuer_key: Option<KeyId>,
    pub issuer_certificate: Option<CertificateId>,
    pub signer: String,
    pub data: serde_json::Value,
    #[serde(with = "time::serde::rfc3339::option")]
    pub validity_start: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub validity_end: Option<OffsetDateTime>,
}

impl SignaturesApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn create(
        &self,
        request: TestCreateSignatureRequest,
        bearer_token: Option<String>,
    ) -> Response {
        const URL: &str = "/api/signature/v1";
        let request = serde_json::to_value(request).unwrap();
        if let Some(bearer_token) = bearer_token {
            return self
                .client
                .post_custom_bearer_auth(URL, &bearer_token, request)
                .await;
        }
        self.client.post(URL, request).await
    }

    pub async fn revoke(&self, entry_id: Uuid, bearer_token: Option<String>) -> Response {
        let url = format!("/api/signature/v1/{}/revoke", entry_id);
        if let Some(bearer_token) = bearer_token {
            return self
                .client
                .post_custom_bearer_auth(url.as_str(), &bearer_token, None)
                .await;
        }
        self.client.post(url.as_str(), None).await
    }

    pub async fn revocation_check(&self, ids: Vec<Uuid>) -> Response {
        let request = serde_json::json!({ "signatureIds": ids });
        self.client
            .post("/api/signature/v1/revocation-check", request)
            .await
    }
}
