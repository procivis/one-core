//! `struct`s for key algorithm provider.

use serde::Serialize;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedPublicKeyJwk {
    pub public_key_bytes: Vec<u8>,
    pub signer_algorithm_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeneratedKey {
    pub public: Vec<u8>,
    pub private: Vec<u8>,
}

#[derive(Serialize, Clone, Default)]
pub struct KeyAlgorithmCapabilities {
    pub features: Vec<String>,
}
