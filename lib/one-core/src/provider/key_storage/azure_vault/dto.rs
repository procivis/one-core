use std::collections::HashMap;

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use standardized_types::jwk::PrivateJwk;

use crate::mapper::secret_string;
use crate::model::key::PrivateJwkExt;
use crate::provider::key_storage::error::KeyStorageError;

#[derive(Serialize)]
pub(super) struct AzureHsmGenerateKeyRequest {
    #[serde(rename = "kty")]
    pub key_type: String,
    #[serde(rename = "crv")]
    pub curve_name: String,
    #[serde(rename = "key_ops")]
    pub key_operations: Vec<String>,
}

#[derive(Serialize)]
pub(super) struct AzureHsmImportKeyRequest {
    #[serde(rename = "key")]
    pub key: AzureHsmJWKRequest,
    #[serde(rename = "Hsm")]
    pub is_hsm: bool,
}

#[derive(Serialize)]
pub(super) struct AzureHsmJWKRequest {
    #[serde(rename = "kty")]
    pub key_type: String,
    #[serde(rename = "crv")]
    pub curve_name: String,
    #[serde(rename = "x")]
    pub x_component: String,
    #[serde(rename = "y")]
    pub y_component: Option<String>,
    #[serde(rename = "d")]
    #[serde(with = "secret_string")]
    pub d_component: SecretString,
}

impl TryFrom<PrivateJwk> for AzureHsmJWKRequest {
    type Error = KeyStorageError;

    fn try_from(value: PrivateJwk) -> Result<Self, Self::Error> {
        match value {
            PrivateJwk::Ec(jwk) => Ok(Self {
                key_type: "EC-HSM".to_string(),
                curve_name: jwk.crv,
                x_component: jwk.x,
                y_component: jwk.y,
                d_component: jwk.d,
            }),
            PrivateJwk::Okp(_) | PrivateJwk::Akp(_) => Err(KeyStorageError::UnsupportedKeyType {
                key_type: value.supported_key_type().to_string(),
            }),
        }
    }
}

#[expect(dead_code)]
#[derive(Deserialize)]
pub(super) struct AzureHsmKeyResponse {
    pub key: AzureHsmGenerateKeyResponseKey,
    pub attributes: AzureHsmGenerateKeyResponseAttributes,
    pub tags: Option<HashMap<String, String>>,
}

#[expect(dead_code)]
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

#[expect(dead_code)]
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
    #[serde(with = "secret_string")]
    pub access_token: SecretString,
}

#[derive(Debug, Serialize)]
pub(super) struct AzureHsmSignRequest {
    #[serde(rename = "alg")]
    pub algorithm: String,
    pub value: String,
}

#[expect(dead_code)]
#[derive(Deserialize)]
pub(super) struct AzureHsmSignResponse {
    #[serde(rename = "kid")]
    pub key_id: String,
    pub value: String,
}
