use did_key::{Fingerprint, Generate, KeyMaterial};

use super::KeyAlgorithm;
use crate::config::ConfigParseError;
use crate::provider::key_algorithm::GeneratedKey;

pub struct Es256;

impl KeyAlgorithm for Es256 {
    fn fingerprint(&self, public_key: &[u8]) -> String {
        let key = did_key::P256KeyPair::from_public_key(public_key);
        key.fingerprint()
    }

    fn generate_key_pair(&self) -> GeneratedKey {
        let key_pair = did_key::P256KeyPair::new();
        GeneratedKey {
            public: key_pair.public_key_bytes(),
            private: key_pair.private_key_bytes(),
        }
    }
}

impl Es256 {
    pub fn new(algorithm: &str) -> Result<Self, ConfigParseError> {
        match algorithm {
            "ES256" => Ok(Self {}),
            _ => Err(ConfigParseError::InvalidType(
                "ES256".to_string(),
                algorithm.to_string(),
            )),
        }
    }
}
