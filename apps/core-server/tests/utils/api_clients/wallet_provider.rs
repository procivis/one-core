use serde_json::json;
use shared_types::ManagedInstanceId;
use standardized_types::jwk::PublicJwk;
use standardized_types::openid4vci::SecurityLevel;

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

    pub async fn register_instance(
        &self,
        provider: &str,
        role: &str,
        os: &str,
        jwk: Option<&PublicJwk>,
        proof: Option<&str>,
    ) -> Response {
        let mut body = json!( {
            "provider": provider,
            "role": role,
            "os": os,
        });
        if let Some(jwk) = jwk {
            body["publicKey"] = json!(jwk);
        }
        if let Some(proof) = proof {
            body["proof"] = json!(proof);
        }

        self.client.post("/ssi/instance/v1", body).await
    }

    pub async fn activate_wallet(
        &self,
        wallet_unit_id: ManagedInstanceId,
        attestation: &str,
        proof: &str,
        user_id_token: Option<&str>,
    ) -> Response {
        let mut body = json!( {
            "attestation": attestation,
            "attestationKeyProof": proof,
        });
        if let Some(token) = user_id_token {
            body["userIdToken"] = json!(token);
        }
        self.client
            .post(
                &format!("/ssi/wallet-unit/v1/{wallet_unit_id}/activate"),
                body,
            )
            .await
    }

    pub async fn activate_instance(
        &self,
        instance_id: ManagedInstanceId,
        body: serde_json::Value,
    ) -> Response {
        self.client
            .post(&format!("/ssi/instance/v1/{instance_id}/activate"), body)
            .await
    }

    pub async fn issue_attestation(
        &self,
        wallet_unit_id: ManagedInstanceId,
        bearer: &str,
        wia_proofs: Vec<String>,
        wua_proofs: Vec<(String, SecurityLevel)>,
    ) -> Response {
        let mut properties = serde_json::Map::new();
        if !wia_proofs.is_empty() {
            properties.insert(
                "wia".to_string(),
                wia_proofs
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

    pub async fn revoke_managed_instance(
        &self,
        managed_instance_id: ManagedInstanceId,
    ) -> Response {
        self.client
            .post(
                &format!("/api/managed-instance/v1/{managed_instance_id}/revoke"),
                None,
            )
            .await
    }

    pub async fn delete_managed_instance(
        &self,
        managed_instance_id: ManagedInstanceId,
    ) -> Response {
        self.client
            .delete(&format!("/api/managed-instance/v1/{managed_instance_id}"))
            .await
    }
}
