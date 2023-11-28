use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use did_key::{Fingerprint, Generate, KeyMaterial};
use serde::Deserialize;

use crate::provider::key_algorithm::GeneratedKey;
use crate::service::did::dto::PublicKeyJwkResponseDTO;
use crate::service::error::ServiceError;

use super::KeyAlgorithm;

pub struct Eddsa;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EddsaParams {
    algorithm: Algorithm,
}

#[derive(Deserialize)]
enum Algorithm {
    #[serde(rename = "Ed25519")]
    Ed25519,
}

impl Eddsa {
    pub fn new(params: EddsaParams) -> Self {
        _ = params.algorithm;
        Self
    }
}

impl KeyAlgorithm for Eddsa {
    fn get_signer_algorithm_id(&self) -> String {
        "Ed25519".to_string()
    }

    fn get_multibase(&self, public_key: &[u8]) -> String {
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

    fn bytes_to_jwk(&self, bytes: &[u8]) -> Result<PublicKeyJwkResponseDTO, ServiceError> {
        Ok(PublicKeyJwkResponseDTO {
            kty: "OKP".to_string(),
            crv: "Ed25519".to_string(),
            x: Base64UrlSafeNoPadding::encode_to_string(bytes)
                .map_err(|e| ServiceError::MappingError(e.to_string()))?,
            y: None,
        })
    }
}
