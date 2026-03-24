use serde_json::json;
use shared_types::OrganisationId;

use crate::utils::api_clients::{HttpClient, Response};

pub struct VerifierIntanceApi {
    client: HttpClient,
}

#[derive(Debug)]
pub struct TestRegisterRequest {
    pub organisation_id: OrganisationId,
    pub provider_url: String,
    pub r#type: String,
}

impl VerifierIntanceApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn register_instance(&self, request: TestRegisterRequest) -> Response {
        let body = json!({
            "organisationId": request.organisation_id,
            "verifierProviderUrl": request.provider_url,
            "type": request.r#type
        });

        self.client.post("/api/verifier-instance/v1", body).await
    }
}
