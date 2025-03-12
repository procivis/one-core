use secrecy::{ExposeSecret, SecretSlice, SecretString};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};

use crate::provider::credential_formatter::error::FormatterError;

pub fn convert_params<T, R>(input: T) -> Result<R, FormatterError>
where
    T: Serialize,
    R: DeserializeOwned,
{
    let result = serde_json::to_value(input).map_err(|e| FormatterError::Failed(e.to_string()))?;
    serde_json::from_value(result).map_err(|e| FormatterError::Failed(e.to_string()))
}

pub fn deserialize_encryption_key<'de, D>(deserializer: D) -> Result<SecretSlice<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    const ERROR_MSG: &str = "Invalid encryption key: needs to be hex encoded 32 byte value";
    let s = SecretString::deserialize(deserializer)?;
    let secret = s.expose_secret();
    if secret.len() != 64 {
        return Err(serde::de::Error::custom(ERROR_MSG));
    }
    Ok(SecretSlice::from(
        hex::decode(secret).map_err(|_| serde::de::Error::custom(ERROR_MSG))?,
    ))
}
