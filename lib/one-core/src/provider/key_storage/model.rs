//! `struct`s and `enum`s for key storage provider.

use serde::Serialize;

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KeySecurity {
    Hardware,
    Software,
    RemoteSecureElement,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct KeyStorageCapabilities {
    pub features: Vec<Features>,
    pub algorithms: Vec<String>,
    pub security: Vec<KeySecurity>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Features {
    Exportable,
}

pub struct StorageGeneratedKey {
    pub public_key: Vec<u8>,
    pub key_reference: Vec<u8>,
}
