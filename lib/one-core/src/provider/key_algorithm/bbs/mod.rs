use super::KeyAlgorithm;
use crate::crypto::signer::error::SignerError;
use crate::provider::did_method::dto::PublicKeyJwkEllipticDataDTO;
use crate::provider::{did_method::dto::PublicKeyJwkDTO, key_algorithm::GeneratedKey};
use crate::service::error::ServiceError;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use pairing_crypto::bbs::ciphersuites::bls12_381::KeyPair;
use rand::thread_rng;

pub struct BBS;

#[cfg(test)]
mod test;

impl KeyAlgorithm for BBS {
    fn get_signer_algorithm_id(&self) -> String {
        "BBS".to_string()
    }

    fn get_multibase(&self, public_key: &[u8]) -> Result<String, SignerError> {
        let codec = &[0xeb, 0x01];
        let data = [codec, public_key].concat();
        Ok(format!("z{}", bs58::encode(data).into_string()))
    }

    fn generate_key_pair(&self) -> GeneratedKey {
        // There is not much to break hence default on failure should be good enough.
        let key_pair = KeyPair::random(&mut thread_rng(), b"").unwrap_or_default();
        let private = key_pair.secret_key.to_bytes().to_vec();
        let public = key_pair.public_key.to_octets().to_vec();
        GeneratedKey { public, private }
    }

    fn bytes_to_jwk(
        &self,
        bytes: &[u8],
        r#use: Option<String>,
    ) -> Result<PublicKeyJwkDTO, ServiceError> {
        let public = blstrs::G2Affine::from_compressed(bytes.try_into().map_err(|_| {
            ServiceError::KeyAlgorithmError("Couldn't parse public key".to_string())
        })?);
        let public = if public.is_some().into() {
            public.unwrap()
        } else {
            return Err(ServiceError::KeyAlgorithmError(
                "Couldn't parse public key".to_string(),
            ));
        };
        let pk_uncompressed = public.to_uncompressed();
        let x = &pk_uncompressed[..96];
        let y = &pk_uncompressed[96..];
        Ok(PublicKeyJwkDTO::Okp(PublicKeyJwkEllipticDataDTO {
            r#use,
            crv: "Bls12381G2".to_string(),
            x: Base64UrlSafeNoPadding::encode_to_string(x)
                .map_err(|e| ServiceError::KeyAlgorithmError(e.to_string()))?,
            y: Some(
                Base64UrlSafeNoPadding::encode_to_string(y)
                    .map_err(|e| ServiceError::KeyAlgorithmError(e.to_string()))?,
            ),
        }))
    }

    fn jwk_to_bytes(&self, jwk: &PublicKeyJwkDTO) -> Result<Vec<u8>, ServiceError> {
        if let PublicKeyJwkDTO::Okp(data) = jwk {
            let x = Base64UrlSafeNoPadding::decode_to_vec(&data.x, None)
                .map_err(|e| ServiceError::KeyAlgorithmError(e.to_string()))?;
            let y = Base64UrlSafeNoPadding::decode_to_vec(
                data.y
                    .as_ref()
                    .ok_or(ServiceError::KeyAlgorithmError("Y is missing".to_string()))?,
                None,
            )
            .map_err(|e| ServiceError::KeyAlgorithmError(e.to_string()))?;

            let uncompressed: [u8; 192] = [x, y].concat().try_into().map_err(|_| {
                ServiceError::KeyAlgorithmError("Couldn't parse public key".to_string())
            })?;
            let public = blstrs::G2Affine::from_uncompressed(&uncompressed);
            let public = if public.is_some().into() {
                public.unwrap()
            } else {
                return Err(ServiceError::KeyAlgorithmError(
                    "Couldn't parse public key".to_string(),
                ));
            };

            Ok(public.to_compressed().to_vec())
        } else {
            Err(ServiceError::KeyAlgorithmError("invalid kty".to_string()))
        }
    }
}
