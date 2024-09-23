//! `struct`s and `enum`s for key storage provider.

use serde::Serialize;

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum KeySecurity {
    Hardware,
    Software,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct KeyStorageCapabilities {
    pub features: Vec<String>,
    pub algorithms: Vec<String>,
    pub security: Vec<KeySecurity>,
}

pub struct StorageGeneratedKey {
    pub public_key: Vec<u8>,
    pub key_reference: Vec<u8>,
}
