use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use pqc_dilithium::Keypair;
use serde::Deserialize;

use one_providers::common_models::{PublicKeyJwk, PublicKeyJwkMlweData};
use one_providers::key_algorithm::error::KeyAlgorithmError;
use one_providers::key_algorithm::model::GeneratedKey;
use one_providers::key_algorithm::KeyAlgorithm;

pub struct MlDsa;

#[cfg(test)]
mod test;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MlDsaParams {
    algorithm: Algorithm,
}

#[derive(Deserialize)]
enum Algorithm {
    #[serde(rename = "CRYDI3")]
    Crydi3,
}

impl MlDsa {
    pub fn new(params: MlDsaParams) -> Self {
        _ = params.algorithm;
        Self
    }
}

impl KeyAlgorithm for MlDsa {
    fn get_signer_algorithm_id(&self) -> String {
        "CRYDI3".to_string()
    }

    fn get_multibase(&self, _public_key: &[u8]) -> Result<String, KeyAlgorithmError> {
        // TODO ONE-1452
        unimplemented!()
    }

    fn generate_key_pair(&self) -> GeneratedKey {
        let keys = Keypair::generate();
        GeneratedKey {
            private: keys.expose_secret().to_owned(),
            public: keys.public.to_vec(),
        }
    }

    fn bytes_to_jwk(
        &self,
        bytes: &[u8],
        r#use: Option<String>,
    ) -> Result<PublicKeyJwk, KeyAlgorithmError> {
        Ok(PublicKeyJwk::Mlwe(PublicKeyJwkMlweData {
            r#use,
            alg: self.get_signer_algorithm_id(),
            x: Base64UrlSafeNoPadding::encode_to_string(bytes)
                .map_err(|e| KeyAlgorithmError::Failed(e.to_string()))?,
        }))
    }

    fn jwk_to_bytes(&self, jwk: &PublicKeyJwk) -> Result<Vec<u8>, KeyAlgorithmError> {
        if let PublicKeyJwk::Mlwe(data) = jwk {
            if data.alg != self.get_signer_algorithm_id() {
                return Err(KeyAlgorithmError::Failed(format!(
                    "unsupported key algorithm variant: {}",
                    data.alg
                )));
            }
            let x = Base64UrlSafeNoPadding::decode_to_vec(&data.x, None)
                .map_err(|e| KeyAlgorithmError::Failed(e.to_string()))?;

            Ok(x)
        } else {
            Err(KeyAlgorithmError::Failed("invalid kty".to_string()))
        }
    }

    fn public_key_from_der(&self, _public_key_der: &[u8]) -> Result<Vec<u8>, KeyAlgorithmError> {
        unimplemented!()
    }
}
