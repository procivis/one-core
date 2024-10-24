use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use one_crypto::signer::bbs::BBSSigner;

use crate::model::key::{PublicKeyJwk, PublicKeyJwkEllipticData};
use crate::provider::key_algorithm::error::KeyAlgorithmError;
use crate::provider::key_algorithm::model::{GeneratedKey, KeyAlgorithmCapabilities};
use crate::provider::key_algorithm::KeyAlgorithm;

pub struct BBS;

#[cfg(test)]
mod test;

impl KeyAlgorithm for BBS {
    fn get_signer_algorithm_id(&self) -> String {
        "BBS".to_string()
    }

    fn get_multibase(&self, public_key: &[u8]) -> Result<String, KeyAlgorithmError> {
        let codec = &[0xeb, 0x01];
        let data = [codec, public_key].concat();
        Ok(format!("z{}", bs58::encode(data).into_string()))
    }

    fn generate_key_pair(&self) -> GeneratedKey {
        let key_pair = BBSSigner::generate_key_pair();
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
        let (x, y) = BBSSigner::get_public_key_coordinates(bytes)?;
        Ok(PublicKeyJwk::Okp(PublicKeyJwkEllipticData {
            r#use,
            crv: "Bls12381G2".to_string(),
            x: Base64UrlSafeNoPadding::encode_to_string(x)
                .map_err(|e| KeyAlgorithmError::Failed(e.to_string()))?,
            y: Some(
                Base64UrlSafeNoPadding::encode_to_string(y)
                    .map_err(|e| KeyAlgorithmError::Failed(e.to_string()))?,
            ),
        }))
    }

    fn jwk_to_bytes(&self, jwk: &PublicKeyJwk) -> Result<Vec<u8>, KeyAlgorithmError> {
        if let PublicKeyJwk::Okp(data) = jwk {
            let x = Base64UrlSafeNoPadding::decode_to_vec(&data.x, None)
                .map_err(|e| KeyAlgorithmError::Failed(e.to_string()))?;
            let y = Base64UrlSafeNoPadding::decode_to_vec(
                data.y
                    .as_ref()
                    .ok_or(KeyAlgorithmError::Failed("Y is missing".to_string()))?,
                None,
            )
            .map_err(|e| KeyAlgorithmError::Failed(e.to_string()))?;

            Ok(BBSSigner::parse_public_key(&x, &y, true)?)
        } else {
            Err(KeyAlgorithmError::Failed("invalid kty".to_string()))
        }
    }

    fn public_key_from_der(&self, _public_key_der: &[u8]) -> Result<Vec<u8>, KeyAlgorithmError> {
        unimplemented!()
    }
    fn get_capabilities(&self) -> KeyAlgorithmCapabilities {
        KeyAlgorithmCapabilities { features: vec![] }
    }
}
