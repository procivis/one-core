//! `struct`s and `enum`s for key storage provider.

use serde::Serialize;
use strum::Display;

use crate::config::core_config::KeyAlgorithmType;

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
    pub algorithms: Vec<KeyAlgorithmType>,
    pub security: Vec<KeySecurity>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq, Display)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Features {
    #[strum(serialize = "EXPORTABLE")]
    Exportable,
    #[strum(serialize = "IMPORTABLE")]
    Importable,
}

pub struct StorageGeneratedKey {
    // todo: add KeyHandle here?
    pub public_key: Vec<u8>,
    pub key_reference: Option<Vec<u8>>,
}
