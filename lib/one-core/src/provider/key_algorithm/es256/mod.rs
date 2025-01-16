use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use one_crypto::signer::es256::ES256Signer;
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::model::key::{PublicKeyJwk, PublicKeyJwkEllipticData};
use crate::provider::key_algorithm::error::KeyAlgorithmError;
use crate::provider::key_algorithm::model::{Features, GeneratedKey, KeyAlgorithmCapabilities};
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
}

impl KeyAlgorithm for Es256 {
    fn get_signer_algorithm_id(&self) -> String {
        "ES256".to_string()
    }

    fn jose_alg(&self) -> Vec<String> {
        vec!["ES256".to_string()]
    }

    fn get_multibase(&self, public_key: &[u8]) -> Result<String, KeyAlgorithmError> {
        let codec = &[0x80, 0x24];
        let key = ES256Signer::parse_public_key(public_key, true)?;
        let data = [codec, key.as_slice()].concat();
        Ok(format!("z{}", bs58::encode(data).into_string()))
    }

    fn generate_key_pair(&self) -> GeneratedKey {
        let (private, public) = ES256Signer::generate_key_pair();

        GeneratedKey {
            public,
            private: private.to_vec(),
        }
    }

    fn bytes_to_jwk(
        &self,
        bytes: &[u8],
        r#use: Option<String>,
    ) -> Result<PublicKeyJwk, KeyAlgorithmError> {
        let (x, y) = ES256Signer::get_public_key_coordinates(bytes)?;
        Ok(PublicKeyJwk::Ec(PublicKeyJwkEllipticData {
            r#use,
            kid: None,
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

            Ok(ES256Signer::parse_public_key_coordinates(&x, &y, true)?)
        } else {
            Err(KeyAlgorithmError::Failed("invalid kty".to_string()))
        }
    }

    fn private_key_as_jwk(
        &self,
        secret_key: Zeroizing<Vec<u8>>,
    ) -> Result<Zeroizing<String>, KeyAlgorithmError> {
        Ok(ES256Signer::private_key_as_jwk(&secret_key)?)
    }

    fn public_key_from_der(&self, public_key_der: &[u8]) -> Result<Vec<u8>, KeyAlgorithmError> {
        Ok(ES256Signer::parse_public_key_from_der(
            public_key_der,
            true,
        )?)
    }

    fn get_capabilities(&self) -> KeyAlgorithmCapabilities {
        KeyAlgorithmCapabilities {
            features: vec![Features::GenerateCSR],
        }
    }
}
