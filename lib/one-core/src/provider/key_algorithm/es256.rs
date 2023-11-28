use did_key::{Fingerprint, Generate, KeyMaterial};
use serde::Deserialize;

use super::KeyAlgorithm;
use crate::provider::key_algorithm::GeneratedKey;
use crate::service::did::dto::PublicKeyJwkResponseDTO;
use crate::service::error::ServiceError;
use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use p256::elliptic_curve::sec1::ToEncodedPoint;
pub struct Es256;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Es256Params {
    algorithm: Algorithm,
}

#[derive(Deserialize)]
enum Algorithm {
    #[serde(rename = "ES256")]
    Es256,
}

impl Es256 {
    pub fn new(params: Es256Params) -> Self {
        _ = params.algorithm;
        Self
    }
}

impl KeyAlgorithm for Es256 {
    fn get_signer_algorithm_id(&self) -> String {
        "ES256".to_string()
    }

    fn get_multibase(&self, public_key: &[u8]) -> String {
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
    fn bytes_to_jwk(&self, bytes: &[u8]) -> Result<PublicKeyJwkResponseDTO, ServiceError> {
        let pk = p256::PublicKey::from_sec1_bytes(bytes)
            .map_err(|e| ServiceError::KeyAlgorithmError(e.to_string()))?;
        let encoded_point = pk.to_encoded_point(false);
        let x = encoded_point
            .x()
            .ok_or(ServiceError::KeyAlgorithmError("X is missing".to_string()))?;
        let y = encoded_point
            .y()
            .ok_or(ServiceError::KeyAlgorithmError("Y is missing".to_string()))?;
        Ok(PublicKeyJwkResponseDTO {
            kty: "EC".to_string(),
            crv: "P-256".to_string(),
            x: Base64UrlSafeNoPadding::encode_to_string(x)
                .map_err(|e| ServiceError::KeyAlgorithmError(e.to_string()))?,
            y: Some(
                Base64UrlSafeNoPadding::encode_to_string(y)
                    .map_err(|e| ServiceError::KeyAlgorithmError(e.to_string()))?,
            ),
        })
    }
}
