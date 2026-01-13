use serde::Serialize;
use serde_with::skip_serializing_none;
use shared_types::{CertificateId, IdentifierId, KeyId};
use time::OffsetDateTime;

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

    pub async fn create(&self, request: TestCreateSignatureRequest) -> Response {
        let request = serde_json::to_value(request).unwrap();
        self.client.post("/api/signature/v1", request).await
    }
}
