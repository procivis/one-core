use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use one_crypto::signer::eddsa::EDDSASigner;
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::model::key::{PublicKeyJwk, PublicKeyJwkEllipticData};
use crate::provider::key_algorithm::error::KeyAlgorithmError;
use crate::provider::key_algorithm::model::{Features, GeneratedKey, KeyAlgorithmCapabilities};
use crate::provider::key_algorithm::KeyAlgorithm;

pub struct Eddsa;

#[cfg(test)]
mod test;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EddsaParams {
    pub algorithm: Algorithm,
}

#[derive(Deserialize)]
pub enum Algorithm {
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

    fn jose_alg(&self) -> Vec<String> {
        vec!["EdDSA".to_string(), "EDDSA".to_string()]
    }

    fn get_multibase(&self, public_key: &[u8]) -> Result<String, KeyAlgorithmError> {
        let codec = &[0xed, 0x1];
        let key = EDDSASigner::check_public_key(public_key)?;
        let data = [codec, key.as_slice()].concat();
        Ok(format!("z{}", bs58::encode(data).into_string()))
    }

    fn generate_key_pair(&self) -> GeneratedKey {
        let key_pair = EDDSASigner::generate_key_pair();

        GeneratedKey {
            public: key_pair.public,
            private: key_pair.private.to_vec(),
        }
    }

    fn bytes_to_jwk(
        &self,
        bytes: &[u8],
        r#use: Option<String>,
    ) -> Result<PublicKeyJwk, KeyAlgorithmError> {
        Ok(PublicKeyJwk::Okp(PublicKeyJwkEllipticData {
            r#use,
            kid: None,
            crv: "Ed25519".to_string(),
            x: Base64UrlSafeNoPadding::encode_to_string(bytes)
                .map_err(|e| KeyAlgorithmError::Failed(e.to_string()))?,
            y: None,
        }))
    }

    fn jwk_to_bytes(&self, jwk: &PublicKeyJwk) -> Result<Vec<u8>, KeyAlgorithmError> {
        if let PublicKeyJwk::Okp(data) = jwk {
            let x = Base64UrlSafeNoPadding::decode_to_vec(&data.x, None)
                .map_err(|e| KeyAlgorithmError::Failed(e.to_string()))?;

            Ok(x)
        } else {
            Err(KeyAlgorithmError::Failed("invalid kty".to_string()))
        }
    }

    fn private_key_as_jwk(
        &self,
        secret_key: Zeroizing<Vec<u8>>,
    ) -> Result<Zeroizing<String>, KeyAlgorithmError> {
        let key_pair = EDDSASigner::parse_private_key(&secret_key)?;

        let x = Base64UrlSafeNoPadding::encode_to_string(key_pair.public.as_slice())
            .map_err(|err| KeyAlgorithmError::Failed(err.to_string()))?;

        let d = Base64UrlSafeNoPadding::encode_to_string(key_pair.private.as_slice())
            .map(Zeroizing::new)
            .map_err(|err| KeyAlgorithmError::Failed(err.to_string()))?;

        let jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": x,
            "d": d,
        })
        .to_string();

        Ok(Zeroizing::new(jwk))
    }

    fn public_key_from_der(&self, public_key_der: &[u8]) -> Result<Vec<u8>, KeyAlgorithmError> {
        Ok(EDDSASigner::public_key_from_der(public_key_der)?)
    }

    fn get_capabilities(&self) -> KeyAlgorithmCapabilities {
        KeyAlgorithmCapabilities {
            features: vec![Features::GenerateCSR],
        }
    }
}
