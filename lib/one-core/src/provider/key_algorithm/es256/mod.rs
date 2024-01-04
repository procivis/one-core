use did_key::{Fingerprint, Generate, KeyMaterial};
use elliptic_curve::{generic_array::GenericArray, sec1::EncodedPoint};
use serde::Deserialize;

use super::KeyAlgorithm;
use crate::provider::did_method::dto::PublicKeyJwkEllipticDataDTO;
use crate::provider::{did_method::dto::PublicKeyJwkDTO, key_algorithm::GeneratedKey};
use crate::service::error::ServiceError;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use p256::elliptic_curve::sec1::ToEncodedPoint;
pub struct Es256;

#[cfg(test)]
mod test;

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
    fn bytes_to_jwk(&self, bytes: &[u8]) -> Result<PublicKeyJwkDTO, ServiceError> {
        let pk = p256::PublicKey::from_sec1_bytes(bytes)
            .map_err(|e| ServiceError::KeyAlgorithmError(e.to_string()))?;
        let encoded_point = pk.to_encoded_point(false);
        let x = encoded_point
            .x()
            .ok_or(ServiceError::KeyAlgorithmError("X is missing".to_string()))?;
        let y = encoded_point
            .y()
            .ok_or(ServiceError::KeyAlgorithmError("Y is missing".to_string()))?;
        Ok(PublicKeyJwkDTO::Ec(PublicKeyJwkEllipticDataDTO {
            r#use: None,
            crv: "P-256".to_string(),
            x: Base64UrlSafeNoPadding::encode_to_string(x)
                .map_err(|e| ServiceError::KeyAlgorithmError(e.to_string()))?,
            y: Some(
                Base64UrlSafeNoPadding::encode_to_string(y)
                    .map_err(|e| ServiceError::KeyAlgorithmError(e.to_string()))?,
            ),
        }))
    }

    fn jwk_to_bytes(&self, jwk: &PublicKeyJwkDTO) -> Result<Vec<u8>, ServiceError> {
        if let PublicKeyJwkDTO::Ec(data) = jwk {
            let x = Base64UrlSafeNoPadding::decode_to_vec(&data.x, None)
                .map_err(|e| ServiceError::KeyAlgorithmError(e.to_string()))?;
            let y = Base64UrlSafeNoPadding::decode_to_vec(
                data.y
                    .as_ref()
                    .ok_or(ServiceError::KeyAlgorithmError("Y is missing".to_string()))?,
                None,
            )
            .map_err(|e| ServiceError::KeyAlgorithmError(e.to_string()))?;

            let encoded_point = EncodedPoint::<p256::NistP256>::from_affine_coordinates(
                GenericArray::from_slice(&x),
                GenericArray::from_slice(&y),
                true,
            );

            Ok(encoded_point.as_bytes().to_owned())
        } else {
            Err(ServiceError::KeyAlgorithmError("invalid kty".to_string()))
        }
    }
}
