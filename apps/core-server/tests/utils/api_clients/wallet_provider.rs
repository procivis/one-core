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
        jwk: Option<&PublicKeyJwk>,
        proof: Option<&str>,
    ) -> Response {
        let mut body = json!( {
            "walletProvider": wallet_provider,
            "os": os,
        });
        if let Some(jwk) = jwk {
            body["publicKey"] = json!(jwk);
        }
        if let Some(proof) = proof {
            body["proof"] = json!(proof);
        }

        self.client.post("/ssi/wallet-unit/v1", body).await
    }

    pub async fn activate_wallet(
        &self,
        wallet_unit_id: WalletUnitId,
        attestation: &str,
        proof: &str,
    ) -> Response {
        let body = json!( {
            "attestation": attestation,
            "attestationKeyProof": proof,
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

    pub async fn revoke_wallet_unit(&self, wallet_unit_id: WalletUnitId) -> Response {
        self.client
            .post(
                &format!("/api/wallet-unit/v1/{wallet_unit_id}/revoke"),
                None,
            )
            .await
    }

    pub async fn delete_wallet_unit(&self, wallet_unit_id: WalletUnitId) -> Response {
        self.client
            .delete(&format!("/api/wallet-unit/v1/{wallet_unit_id}"))
            .await
    }
}
