//! `struct`s for key algorithm provider.

use serde::Serialize;
use zeroize::Zeroizing;

use crate::provider::key_algorithm::key::KeyHandle;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedPublicKeyJwk {
    pub public_key_bytes: Vec<u8>,
    pub signer_algorithm_id: String,
}

#[derive(Clone)]
pub struct GeneratedKey {
    pub key: KeyHandle,

    // to be used for DB (Internal key storage)
    pub public: Vec<u8>,
    pub private: Zeroizing<Vec<u8>>,
}

#[derive(Serialize, Clone, Default)]
pub struct KeyAlgorithmCapabilities {
    pub features: Vec<Features>,
}

#[derive(Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Features {
    #[serde(rename = "GENERATE_CSR")]
    GenerateCSR,
}
