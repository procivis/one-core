use one_core::model::key::PublicKeyJwk;
use serde_json::json;
use shared_types::WalletUnitId;

use crate::utils::api_clients::{HttpClient, Response};

pub struct WalletProviderApi {
    client: HttpClient,
}

impl WalletProviderApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn register_wallet(
        &self,
        wallet_provider: &str,
        os: &str,
        jwk: &PublicKeyJwk,
        proof: &str,
    ) -> Response {
        let body = json!( {
            "walletProvider": wallet_provider,
            "os": os,
            "publicKey": jwk,
            "proof": proof
        });

        self.client.post("/ssi/wallet-unit/v1", body).await
    }

    pub async fn activate_wallet(
        &self,
        wallet_unit_id: WalletUnitId,
        attestation: &str,
        nonce: &str,
    ) -> Response {
        let body = json!( {
            "attestation": attestation,
            "nonce": nonce,
        });

        self.client
            .post(
                &format!("/ssi/wallet-unit/v1/{wallet_unit_id}/activate"),
                body,
            )
            .await
    }

    pub async fn refresh_wallet(&self, wallet_unit_id: WalletUnitId, proof: String) -> Response {
        let body = json!( {
            "proof": proof
        });
        self.client
            .post(
                &format!("/ssi/wallet-unit/v1/{wallet_unit_id}/refresh"),
                body,
            )
            .await
    }
}
