use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub(super) struct AzureHsmGenerateKeyRequest {
    #[serde(rename = "kty")]
    pub key_type: String,
    #[serde(rename = "crv")]
    pub curve_name: String,
    #[serde(rename = "key_ops")]
    pub key_operations: Vec<String>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub(super) struct AzureHsmGenerateKeyResponse {
    pub key: AzureHsmGenerateKeyResponseKey,
    pub attributes: AzureHsmGenerateKeyResponseAttributes,
    pub tags: Option<HashMap<String, String>>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub(super) struct AzureHsmGenerateKeyResponseKey {
    #[serde(rename = "kid")]
    pub key_id: String,
    #[serde(rename = "kty")]
    pub key_type: String,
    #[serde(rename = "key_ops")]
    pub key_operations: Vec<String>,
    #[serde(rename = "x")]
    pub x_component: String,
    #[serde(rename = "y")]
    pub y_component: String,

    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct AzureHsmGenerateKeyResponseAttributes {
    pub enabled: bool,
    pub created: u64,
    pub updated: u64,
    pub recovery_level: String,
}

#[derive(Serialize)]
pub(super) struct AzureHsmGetTokenRequest {
    pub client_id: String,
    pub client_secret: String,
    pub grant_type: String,
    pub scope: String,
}

#[derive(Deserialize, Serialize)]
pub(super) struct AzureHsmGetTokenResponse {
    pub token_type: String,
    pub expires_in: i64,
    pub access_token: String,
}

#[derive(Debug, Serialize)]
pub(super) struct AzureHsmSignRequest {
    #[serde(rename = "alg")]
    pub algorithm: String,
    pub value: String,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub(super) struct AzureHsmSignResponse {
    #[serde(rename = "kid")]
    pub key_id: String,
    pub value: String,
}
