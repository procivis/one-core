use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use one_crypto::signer::eddsa::EDDSASigner;
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::model::key::{PublicKeyJwk, PublicKeyJwkEllipticData};
use crate::provider::key_algorithm::error::KeyAlgorithmError;
use crate::provider::key_algorithm::model::{GeneratedKey, KeyAlgorithmCapabilities};
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
            features: vec!["GENERATE_CSR".to_string()],
        }
    }
}

pub trait JwkEddsaExt {
    fn into_x25519(self) -> Result<Self, anyhow::Error>
    where
        Self: Sized;
}

impl JwkEddsaExt for josekit::jwk::Jwk {
    fn into_x25519(mut self) -> Result<Self, anyhow::Error> {
        if let Some("Ed25519") = self.curve() {
            self.set_curve("X25519");

            if let Some(x) = self.parameter("x").and_then(|x| x.as_str()) {
                let key = Base64UrlSafeNoPadding::decode_to_vec(x, None)?;
                let key = EDDSASigner::public_key_into_x25519(&key)?;
                let key = Base64UrlSafeNoPadding::encode_to_string(key.as_slice())?;
                self.set_parameter("x", Some(key.into()))?;
            }

            if let Some(d) = self.parameter("d").and_then(|d| d.as_str()) {
                let key =
                    Base64UrlSafeNoPadding::decode_to_vec(d, None).map(zeroize::Zeroizing::new)?;
                let key = EDDSASigner::private_key_into_x25519(&key)?;
                let key = Base64UrlSafeNoPadding::encode_to_string(key.as_slice())
                    .map(zeroize::Zeroizing::new)?;

                let key = serde_json::to_value(key)?;

                self.set_parameter("d", Some(key))?;
            };
        }

        Ok(self)
    }
}
