use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use ed25519_compact::{KeyPair, PublicKey};
use serde::Deserialize;

use crate::crypto::signer::error::SignerError;
use crate::provider::did_method::dto::{PublicKeyJwkDTO, PublicKeyJwkEllipticDataDTO};
use crate::provider::key_algorithm::GeneratedKey;
use crate::service::error::ServiceError;

use super::KeyAlgorithm;

pub struct Eddsa;

#[cfg(test)]
mod test;

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

    fn get_multibase(&self, public_key: &[u8]) -> Result<String, SignerError> {
        let codec = &[0xed, 0x1];
        let key = PublicKey::from_slice(public_key).unwrap();
        let data = [codec, key.as_ref()].concat();
        Ok(format!("z{}", bs58::encode(data).into_string()))
    }

    fn generate_key_pair(&self) -> GeneratedKey {
        let key_pair = KeyPair::generate();

        GeneratedKey {
            public: key_pair.pk.to_vec(),
            private: key_pair.sk.to_vec(),
        }
    }

    fn bytes_to_jwk(&self, bytes: &[u8]) -> Result<PublicKeyJwkDTO, ServiceError> {
        Ok(PublicKeyJwkDTO::Okp(PublicKeyJwkEllipticDataDTO {
            r#use: None,
            crv: "Ed25519".to_string(),
            x: Base64UrlSafeNoPadding::encode_to_string(bytes)
                .map_err(|e| ServiceError::MappingError(e.to_string()))?,
            y: None,
        }))
    }

    fn jwk_to_bytes(&self, jwk: &PublicKeyJwkDTO) -> Result<Vec<u8>, ServiceError> {
        if let PublicKeyJwkDTO::Okp(data) = jwk {
            let x = Base64UrlSafeNoPadding::decode_to_vec(&data.x, None)
                .map_err(|e| ServiceError::KeyAlgorithmError(e.to_string()))?;

            Ok(x)
        } else {
            Err(ServiceError::KeyAlgorithmError("invalid kty".to_string()))
        }
    }
}
