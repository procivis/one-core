use pqc_dilithium::Keypair;
use serde::Deserialize;

use super::KeyAlgorithm;
use crate::crypto::signer::error::SignerError;
use crate::provider::did_method::dto::PublicKeyJwkMlweDataDTO;
use crate::provider::{did_method::dto::PublicKeyJwkDTO, key_algorithm::GeneratedKey};
use crate::service::error::ServiceError;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};

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

    fn get_multibase(&self, _public_key: &[u8]) -> Result<String, SignerError> {
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
    ) -> Result<PublicKeyJwkDTO, ServiceError> {
        Ok(PublicKeyJwkDTO::Mlwe(PublicKeyJwkMlweDataDTO {
            r#use,
            alg: self.get_signer_algorithm_id(),
            x: Base64UrlSafeNoPadding::encode_to_string(bytes)
                .map_err(|e| ServiceError::KeyAlgorithmError(e.to_string()))?,
        }))
    }

    fn jwk_to_bytes(&self, jwk: &PublicKeyJwkDTO) -> Result<Vec<u8>, ServiceError> {
        if let PublicKeyJwkDTO::Mlwe(data) = jwk {
            if data.alg != self.get_signer_algorithm_id() {
                return Err(ServiceError::KeyAlgorithmError(format!(
                    "unsupported key algorithm variant: {}",
                    data.alg
                )));
            }
            let x = Base64UrlSafeNoPadding::decode_to_vec(&data.x, None)
                .map_err(|e| ServiceError::KeyAlgorithmError(e.to_string()))?;

            Ok(x)
        } else {
            Err(ServiceError::KeyAlgorithmError("invalid kty".to_string()))
        }
    }

    fn public_key_from_der(&self, _public_key_der: &[u8]) -> Result<Vec<u8>, ServiceError> {
        unimplemented!()
    }
}
