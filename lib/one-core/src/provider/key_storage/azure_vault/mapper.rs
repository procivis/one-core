use ct_codecs::{Base64UrlSafeNoPadding, Decoder};

use super::dto::{
    AzureHsmGenerateKeyRequest, AzureHsmGenerateKeyResponseKey, AzureHsmGetTokenRequest,
};

use crate::service::error::ServiceError;

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

pub(super) fn public_key_from_components(
    key: &AzureHsmGenerateKeyResponseKey,
) -> Result<Vec<u8>, ServiceError> {
    let mut x_component = Base64UrlSafeNoPadding::decode_to_vec(&key.x_component, None)
        .map_err(|e| ServiceError::GeneralRuntimeError(e.to_string()))?;
    let mut y_component = Base64UrlSafeNoPadding::decode_to_vec(&key.y_component, None)
        .map_err(|e| ServiceError::GeneralRuntimeError(e.to_string()))?;

    const PUBLIC_KEY_FULL: u8 = 0x04;
    let mut result = vec![PUBLIC_KEY_FULL];
    result.append(&mut x_component);
    result.append(&mut y_component);

    Ok(result)
}
