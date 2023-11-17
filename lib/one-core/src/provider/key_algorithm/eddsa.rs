use did_key::{Fingerprint, Generate, KeyMaterial};

use super::KeyAlgorithm;
use crate::config::ConfigParseError;
use crate::provider::key_algorithm::GeneratedKey;

pub struct Eddsa;

impl KeyAlgorithm for Eddsa {
    fn fingerprint(&self, public_key: &[u8]) -> String {
        let key = did_key::Ed25519KeyPair::from_public_key(public_key);
        key.fingerprint()
    }

    fn generate_key_pair(&self) -> GeneratedKey {
        let key_pair = did_key::Ed25519KeyPair::new();
        GeneratedKey {
            public: key_pair.public_key_bytes(),
            private: key_pair.private_key_bytes(),
        }
    }
}

impl Eddsa {
    pub fn new(algorithm: &str) -> Result<Self, ConfigParseError> {
        match algorithm {
            "Ed25519" => Ok(Self {}),
            _ => Err(ConfigParseError::InvalidType(
                "EDDSA".to_string(),
                algorithm.to_string(),
            )),
        }
    }
}
