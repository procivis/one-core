use std::sync::Arc;

use anyhow::anyhow;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use one_crypto::{CryptoProvider, SignerError};

use super::dto::{
    AzureHsmGenerateKeyRequest, AzureHsmGenerateKeyResponseKey, AzureHsmGetTokenRequest,
    AzureHsmSignRequest,
};
use crate::provider::key_storage::error::KeyStorageError;

pub(super) fn create_get_token_request(
    client_id: &str,
    client_secret: &str,
) -> AzureHsmGetTokenRequest {
    AzureHsmGetTokenRequest {
        client_id: client_id.to_string(),
        client_secret: client_secret.to_string(),
        grant_type: "client_credentials".to_string(),
        scope: "https://vault.azure.net/.default".to_string(),
    }
}

pub(super) fn create_generate_key_request() -> AzureHsmGenerateKeyRequest {
    AzureHsmGenerateKeyRequest {
        key_type: "EC-HSM".to_string(),
        curve_name: "P-256".to_string(),
        key_operations: vec!["sign".to_string(), "verify".to_string()],
    }
}

pub(super) fn create_sign_request(
    value: &[u8],
    crypto: Arc<dyn CryptoProvider>,
) -> Result<AzureHsmSignRequest, SignerError> {
    let hasher = crypto
        .get_hasher("sha-256")
        .map_err(SignerError::CryptoError)?;
    let value = hasher
        .hash_base64(value)
        .map_err(|e| SignerError::CouldNotSign(e.to_string()))?;

    Ok(AzureHsmSignRequest {
        algorithm: "ES256".to_string(),
        value,
    })
}

pub(super) fn public_key_from_components(
    key: &AzureHsmGenerateKeyResponseKey,
) -> Result<Vec<u8>, KeyStorageError> {
    let mut x_component =
        Base64UrlSafeNoPadding::decode_to_vec(&key.x_component, None).map_err(|e| {
            KeyStorageError::Failed(
                anyhow!(e)
                    .context("could not decode x component")
                    .to_string(),
            )
        })?;
    let mut y_component =
        Base64UrlSafeNoPadding::decode_to_vec(&key.y_component, None).map_err(|e| {
            KeyStorageError::Failed(
                anyhow!(e)
                    .context("could not decode y component")
                    .to_string(),
            )
        })?;

    const PUBLIC_KEY_FULL: u8 = 0x04;
    let mut result = vec![PUBLIC_KEY_FULL];
    result.append(&mut x_component);
    result.append(&mut y_component);

    Ok(result)
}
