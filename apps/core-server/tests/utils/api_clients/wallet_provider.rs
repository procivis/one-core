use one_core::provider::issuance_protocol::model::KeyStorageSecurityLevel;
use serde_json::json;
use shared_types::WalletUnitId;
use standardized_types::jwk::PublicJwk;

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
        jwk: Option<&PublicJwk>,
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

    pub async fn issue_attestation(
        &self,
        wallet_unit_id: WalletUnitId,
        bearer: &str,
        waa_proofs: Vec<String>,
        wua_proofs: Vec<(String, KeyStorageSecurityLevel)>,
    ) -> Response {
        let mut properties = serde_json::Map::new();
        if !waa_proofs.is_empty() {
            properties.insert(
                "waa".to_string(),
                waa_proofs
                    .into_iter()
                    .map(|proof| json!({"proof": proof}))
                    .collect(),
            );
        }
        if !wua_proofs.is_empty() {
            properties.insert(
                "wua".to_string(),
                wua_proofs
                    .into_iter()
                    .map(|(proof, security_level)| json!({"proof": proof, "securityLevel": security_level}))
                    .collect(),
            );
        }
        self.client
            .post_custom_bearer_auth(
                &format!("/ssi/wallet-unit/v1/{wallet_unit_id}/issue-attestation"),
                bearer,
                serde_json::Value::Object(properties),
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
