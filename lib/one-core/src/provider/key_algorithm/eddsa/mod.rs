use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use ed25519_compact::{KeyPair, PublicKey};
use serde::Deserialize;
use zeroize::Zeroizing;

use super::KeyAlgorithm;
use crate::crypto::signer::error::SignerError;
use crate::provider::did_method::dto::{PublicKeyJwkDTO, PublicKeyJwkEllipticDataDTO};
use crate::provider::key_algorithm::GeneratedKey;
use crate::service::error::ServiceError;

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
        let key = PublicKey::from_slice(public_key).map_err(|_| SignerError::MissingKey)?;
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

    fn bytes_to_jwk(
        &self,
        bytes: &[u8],
        r#use: Option<String>,
    ) -> Result<PublicKeyJwkDTO, ServiceError> {
        Ok(PublicKeyJwkDTO::Okp(PublicKeyJwkEllipticDataDTO {
            r#use,
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

    fn private_key_as_jwk(
        &self,
        secret_key: Zeroizing<Vec<u8>>,
    ) -> Result<Zeroizing<String>, ServiceError> {
        // automatically gets zeroized when dropped
        let secret_key = ed25519_compact::SecretKey::from_slice(&secret_key)
            .map_err(|_err| ServiceError::KeyAlgorithmError("Invalid secret key".to_string()))?;
        let public_key = secret_key.public_key();

        let x = Base64UrlSafeNoPadding::encode_to_string(public_key.as_slice())
            .map_err(|err| ServiceError::KeyAlgorithmError(err.to_string()))?;

        let d = Base64UrlSafeNoPadding::encode_to_string(secret_key.as_slice())
            .map(Zeroizing::new)
            .map_err(|err| ServiceError::KeyAlgorithmError(err.to_string()))?;

        let jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": x,
            "d": d,
        })
        .to_string();

        Ok(Zeroizing::new(jwk))
    }

    fn public_key_from_der(&self, public_key_der: &[u8]) -> Result<Vec<u8>, ServiceError> {
        let pk = ed25519_compact::PublicKey::from_der(public_key_der)
            .map_err(|e| ServiceError::KeyAlgorithmError(e.to_string()))?;

        Ok(pk.to_vec())
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
                let key = ed25519_compact::PublicKey::from_slice(&key)?;
                let key = ed25519_compact::x25519::PublicKey::from_ed25519(&key)?;
                let key = Base64UrlSafeNoPadding::encode_to_string(key.as_slice())?;

                self.set_parameter("x", Some(key.into()))?;
            }

            if let Some(d) = self.parameter("d").and_then(|d| d.as_str()) {
                let key =
                    Base64UrlSafeNoPadding::decode_to_vec(d, None).map(zeroize::Zeroizing::new)?;

                let key = ed25519_compact::SecretKey::from_slice(&key)?;
                let key = ed25519_compact::x25519::SecretKey::from_ed25519(&key)?;
                let key = Base64UrlSafeNoPadding::encode_to_string(key.as_slice())
                    .map(zeroize::Zeroizing::new)?;

                let key = serde_json::to_value(key)?;

                self.set_parameter("d", Some(key))?;
            };
        }

        Ok(self)
    }
}
