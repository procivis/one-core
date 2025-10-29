use serde_json::json;
use shared_types::OrganisationId;

use crate::utils::api_clients::{HttpClient, Response};

pub struct HolderWalletUnitsApi {
    client: HttpClient,
}

#[derive(Debug, Default)]
pub struct TestHolderRegisterRequest {
    pub organization_id: Option<OrganisationId>,
    pub wallet_provider_url: Option<String>,
    pub wallet_provider_type: Option<String>,
    pub key_type: Option<String>,
}

impl HolderWalletUnitsApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn holder_register(&self, request: TestHolderRegisterRequest) -> Response {
        let body = json!(
            {
            "organisationId": request.organization_id,
            "walletProvider": {
                "url": request.wallet_provider_url.unwrap_or("http://localhost:3000".to_string()),
                "type": request.wallet_provider_type.unwrap_or("PROCIVIS_ONE".to_string()),
            },
            "keyType": request.key_type.unwrap_or("ECDSA".to_string()),
            }
        );

        self.client.post("/api/holder-wallet-unit/v1", body).await
    }
}
