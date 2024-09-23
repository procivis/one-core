use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use one_crypto::signer::es256::ES256Signer;
use p256::elliptic_curve::generic_array::GenericArray;
use p256::elliptic_curve::sec1::{EncodedPoint, ToEncodedPoint};
use p256::pkcs8::DecodePublicKey;
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::model::key::{PublicKeyJwk, PublicKeyJwkEllipticData};
use crate::provider::key_algorithm::error::KeyAlgorithmError;
use crate::provider::key_algorithm::model::{GeneratedKey, KeyAlgorithmCapabilities};
use crate::provider::key_algorithm::KeyAlgorithm;

pub struct Es256;

#[cfg(test)]
mod test;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Es256Params {
    pub algorithm: Algorithm,
}

#[derive(Deserialize)]
pub enum Algorithm {
    #[serde(rename = "ES256")]
    Es256,
}

impl Es256 {
    pub fn new(params: Es256Params) -> Self {
        _ = params.algorithm;
        Self
    }

    pub fn decompress_public_key(public_key: &[u8]) -> Result<Vec<u8>, KeyAlgorithmError> {
        let public_key = p256::PublicKey::from_sec1_bytes(public_key)
            .map_err(|e| KeyAlgorithmError::Failed(e.to_string()))?;

        Ok(public_key.to_encoded_point(false).to_bytes().into())
    }
}

impl KeyAlgorithm for Es256 {
    fn get_signer_algorithm_id(&self) -> String {
        "ES256".to_string()
    }

    fn get_multibase(&self, public_key: &[u8]) -> Result<String, KeyAlgorithmError> {
        let codec = &[0x80, 0x24];
        let key = ES256Signer::to_bytes(public_key)?;
        let data = [codec, key.as_slice()].concat();
        Ok(format!("z{}", bs58::encode(data).into_string()))
    }

    fn generate_key_pair(&self) -> GeneratedKey {
        let (private, public) = ES256Signer::random();

        GeneratedKey { public, private }
    }

    fn bytes_to_jwk(
        &self,
        bytes: &[u8],
        r#use: Option<String>,
    ) -> Result<PublicKeyJwk, KeyAlgorithmError> {
        let pk = p256::PublicKey::from_sec1_bytes(bytes)
            .map_err(|e| KeyAlgorithmError::Failed(e.to_string()))?;
        let encoded_point = pk.to_encoded_point(false);
        let x = encoded_point
            .x()
            .ok_or(KeyAlgorithmError::Failed("X is missing".to_string()))?;
        let y = encoded_point
            .y()
            .ok_or(KeyAlgorithmError::Failed("Y is missing".to_string()))?;
        Ok(PublicKeyJwk::Ec(PublicKeyJwkEllipticData {
            r#use,
            crv: "P-256".to_string(),
            x: Base64UrlSafeNoPadding::encode_to_string(x)
                .map_err(|e| KeyAlgorithmError::Failed(e.to_string()))?,
            y: Some(
                Base64UrlSafeNoPadding::encode_to_string(y)
                    .map_err(|e| KeyAlgorithmError::Failed(e.to_string()))?,
            ),
        }))
    }

    fn jwk_to_bytes(&self, jwk: &PublicKeyJwk) -> Result<Vec<u8>, KeyAlgorithmError> {
        if let PublicKeyJwk::Ec(data) = jwk {
            let x = Base64UrlSafeNoPadding::decode_to_vec(&data.x, None)
                .map_err(|e| KeyAlgorithmError::Failed(e.to_string()))?;
            let y = Base64UrlSafeNoPadding::decode_to_vec(
                data.y
                    .as_ref()
                    .ok_or(KeyAlgorithmError::Failed("Y is missing".to_string()))?,
                None,
            )
            .map_err(|e| KeyAlgorithmError::Failed(e.to_string()))?;

            let encoded_point = EncodedPoint::<p256::NistP256>::from_affine_coordinates(
                GenericArray::from_slice(&x),
                GenericArray::from_slice(&y),
                true,
            );

            Ok(encoded_point.as_bytes().to_owned())
        } else {
            Err(KeyAlgorithmError::Failed("invalid kty".to_string()))
        }
    }

    fn private_key_as_jwk(
        &self,
        secret_key: Zeroizing<Vec<u8>>,
    ) -> Result<Zeroizing<String>, KeyAlgorithmError> {
        let secret_key = p256::SecretKey::from_slice(&secret_key).map_err(|err| {
            KeyAlgorithmError::Failed(format!("Failed parsing key from bytes {err}"))
        })?;

        Ok(secret_key.to_jwk_string())
    }

    fn public_key_from_der(&self, public_key_der: &[u8]) -> Result<Vec<u8>, KeyAlgorithmError> {
        let pk = p256::PublicKey::from_public_key_der(public_key_der)
            .map_err(|e| KeyAlgorithmError::Failed(e.to_string()))?;

        Ok(pk.to_encoded_point(true).to_bytes().into())
    }

    fn get_capabilities(&self) -> KeyAlgorithmCapabilities {
        KeyAlgorithmCapabilities {
            features: vec!["GENERATE_CSR".to_string()],
        }
    }
}
