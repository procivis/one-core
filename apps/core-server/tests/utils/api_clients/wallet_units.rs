use std::fmt::Display;

use super::{HttpClient, Response};

pub struct WalletUnitsApi {
    client: HttpClient,
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
}
