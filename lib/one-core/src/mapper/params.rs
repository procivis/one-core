use secrecy::{ExposeSecret, SecretSlice, SecretString};
use serde::{Deserialize, Deserializer};

pub(crate) fn deserialize_encryption_key<'de, D>(
    deserializer: D,
) -> Result<SecretSlice<u8>, D::Error>
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
