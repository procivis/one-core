use std::fmt::Display;

use serde_json::json;
use shared_types::OrganisationId;

use super::{HttpClient, Response};

pub struct WalletUnitsApi {
    client: HttpClient,
}

#[derive(Debug, Default)]
pub struct TestHolderRegisterRequest {
    pub organization_id: Option<OrganisationId>,
    pub wallet_provider_url: Option<String>,
    pub wallet_provider_type: Option<String>,
    pub wallet_provider_name: Option<String>,
    pub key_type: Option<String>,
}

#[derive(Debug, Default)]
pub struct TestHolderRefreshRequest {
    pub organization_id: Option<OrganisationId>,
}

impl WalletUnitsApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn list(&self) -> Response {
        // Wallet unit list requires query parameters, so provide minimal defaults
        let url = "/api/wallet-unit/v1?page=0&pageSize=50";
        self.client.get(url).await
    }

    pub async fn get(&self, id: &impl Display) -> Response {
        let url = format!("/api/wallet-unit/v1/{id}");
        self.client.get(&url).await
    }

    pub async fn holder_register(&self, request: TestHolderRegisterRequest) -> Response {
        let body = json!(
            {
            "organisationId": request.organization_id,
            "walletProvider": {
                "url": request.wallet_provider_url.unwrap_or("http://localhost:3000".to_string()),
                "type": request.wallet_provider_type.unwrap_or("PROCIVIS_ONE".to_string()),
                "name": request.wallet_provider_name.unwrap_or("PROCIVIS_ONE".to_string()),
                "appIntegrityCheckRequired": false,
            },
            "keyType": request.key_type.unwrap_or("ECDSA".to_string()),
            }
        );

        self.client
            .post("/api/wallet-unit/v1/holder-register", body)
            .await
    }

    pub async fn holder_refresh(&self, request: TestHolderRefreshRequest) -> Response {
        let body = json!(
            {
            "organisationId": request.organization_id
            }
        );

        self.client
            .post("/api/wallet-unit/v1/holder-refresh", body)
            .await
    }

    pub async fn holder_attestations(&self, organisation_id: OrganisationId) -> Response {
        self.client
            .get(&format!(
                "/api/wallet-unit/v1/holder-attestation?organisationId={organisation_id}"
            ))
            .await
    }
}
