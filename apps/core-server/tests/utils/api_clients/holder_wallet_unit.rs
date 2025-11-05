use serde_json::json;
use shared_types::{HolderWalletUnitId, OrganisationId};

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

    pub async fn holder_get_wallet_unit_details(
        &self,
        wallet_unit_id: &HolderWalletUnitId,
    ) -> Response {
        self.client
            .get(&format!("/api/holder-wallet-unit/v1/{}", wallet_unit_id))
            .await
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

    pub async fn holder_wallet_unit_status(&self, wallet_unit_id: &HolderWalletUnitId) -> Response {
        self.client
            .post(
                &format!("/api/holder-wallet-unit/v1/{}/status", wallet_unit_id),
                None,
            )
            .await
    }
}
