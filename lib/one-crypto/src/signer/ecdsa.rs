use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use p256::ecdh::diffie_hellman;
use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::generic_array::GenericArray;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::elliptic_curve::{JwkEcKey, SecretKey};
use p256::pkcs8::DecodePublicKey;
use p256::{AffinePoint, EncodedPoint, NistP256, PublicKey};
use secrecy::{ExposeSecret, SecretSlice, SecretString};
use standardized_types::jwk::{PublicJwk, PublicJwkEc};

use crate::encryption::EncryptionError;
use crate::jwe::decode_b64;
use crate::utilities::get_rng;
use crate::{Signer, SignerError};

pub struct ECDSASigner;

impl ECDSASigner {
    fn from_bytes(public_key: &[u8]) -> Result<VerifyingKey, SignerError> {
        let point = EncodedPoint::from_bytes(public_key).map_err(|err| {
            SignerError::CouldNotExtractPublicKey(format!(
                "couldn't initialize verifying key: {err}"
            ))
        })?;
        VerifyingKey::from_encoded_point(&point).map_err(|err| {
            SignerError::CouldNotExtractPublicKey(format!(
                "couldn't initialize verifying key: {err}"
            ))
        })
    }

    pub fn parse_public_key(public_key: &[u8], compressed: bool) -> Result<Vec<u8>, SignerError> {
        let vk = Self::from_bytes(public_key)?;
        Ok(vk.to_encoded_point(compressed).to_bytes().into())
    }

    pub fn parse_public_key_coordinates(
        x: &[u8],
        y: &[u8],
        compressed: bool,
    ) -> Result<Vec<u8>, SignerError> {
        let encoded_point = EncodedPoint::from_affine_coordinates(
            GenericArray::from_slice(x),
            GenericArray::from_slice(y),
            false,
        );

        let key = VerifyingKey::from_encoded_point(&encoded_point).map_err(|err| {
            SignerError::CouldNotExtractPublicKey(format!(
                "couldn't initialize verifying key: {err}"
            ))
        })?;

        Ok(key.to_encoded_point(compressed).to_bytes().into())
    }

    pub fn parse_private_key_coordinates(
        d: &SecretSlice<u8>,
        compressed: bool,
    ) -> Result<(SecretSlice<u8>, Vec<u8>), SignerError> {
        let sk = SigningKey::from_slice(d.expose_secret()).map_err(|err| {
            SignerError::CouldNotExtractPrivateKey(format!(
                "couldn't initialize signing key: {err}"
            ))
        })?;
        let vk = sk.verifying_key();
        Ok((
            sk.to_bytes().to_vec().into(),
            vk.to_encoded_point(compressed).to_bytes().into(),
        ))
    }

    pub fn parse_public_key_from_der(
        public_key_der: &[u8],
        compressed: bool,
    ) -> Result<Vec<u8>, SignerError> {
        let pk = p256::PublicKey::from_public_key_der(public_key_der)
            .map_err(|e| SignerError::CouldNotExtractPublicKey(e.to_string()))?;

        Ok(pk.to_encoded_point(compressed).to_bytes().into())
    }

    pub fn get_public_key_coordinates(
        public_key: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), SignerError> {
        let vk = Self::from_bytes(public_key)?;
        let point = vk.to_encoded_point(false);
        Ok((
            point
                .x()
                .ok_or(SignerError::CouldNotExtractPublicKey(
                    "X is missing".to_string(),
                ))?
                .to_vec(),
            point
                .y()
                .ok_or(SignerError::CouldNotExtractPublicKey(
                    "Y is missing".to_string(),
                ))?
                .to_vec(),
        ))
    }

    pub fn generate_key_pair() -> (SecretSlice<u8>, Vec<u8>) {
        let sk = SigningKey::random(&mut get_rng());
        let pk = VerifyingKey::from(&sk);
        (
            sk.to_bytes().to_vec().into(),
            pk.to_encoded_point(true).to_bytes().into(),
        )
    }

    pub fn private_key_as_jwk(secret_key: &SecretSlice<u8>) -> Result<SecretString, SignerError> {
        let secret_key = p256::SecretKey::from_slice(secret_key.expose_secret())
            .map_err(|_| SignerError::CouldNotExtractKeyPair)?;

        Ok(SecretString::from(secret_key.to_jwk_string().to_string()))
    }

    pub fn shared_secret_p256(
        private_key: &SecretSlice<u8>,
        recipient_jwk: &PublicJwk,
    ) -> Result<SecretSlice<u8>, EncryptionError> {
        let PublicJwk::Ec(recipient_jwk) = recipient_jwk else {
            return Err(EncryptionError::Crypto(format!(
                "Expected elliptic curve jwk, got {recipient_jwk:?}"
            )));
        };
        let x = decode_b64(recipient_jwk.x.as_str(), "x coordinate")?;
        let y_encoded = recipient_jwk
            .y
            .clone()
            .ok_or(EncryptionError::Crypto("Missing y coordinate".to_string()))?;
        let y = decode_b64(y_encoded.as_str(), "y coordinate")?;
        let peer_affine_point =
            AffinePoint::from_encoded_point(&EncodedPoint::from_affine_coordinates(
                GenericArray::from_slice(&x),
                GenericArray::from_slice(&y),
                false,
            ))
            .into_option()
            .ok_or(EncryptionError::Crypto(
                "Invalid JWK coordinates".to_string(),
            ))?;

        let secret_key: SecretKey<NistP256> = SecretKey::from_slice(private_key.expose_secret())
            .map_err(|e| EncryptionError::Crypto(e.to_string()))?;

        let shared_secret: Vec<u8> =
            diffie_hellman(secret_key.to_nonzero_scalar(), peer_affine_point)
                .raw_secret_bytes()
                .to_vec();
        Ok(SecretSlice::from(shared_secret))
    }

    pub fn bytes_as_jwk(public_key: &[u8]) -> Result<PublicJwk, EncryptionError> {
        let verifying_key = ECDSASigner::from_bytes(public_key)
            .map_err(|e| EncryptionError::Crypto(e.to_string()))?;
        let public_key = PublicKey::from(verifying_key);
        ec_key_to_public_jwk(public_key.to_jwk())
    }
}

impl Signer for ECDSASigner {
    fn sign(
        &self,
        input: &[u8],
        public_key: &[u8],
        private_key: &SecretSlice<u8>,
    ) -> Result<Vec<u8>, SignerError> {
        let sk = SigningKey::from_bytes(private_key.expose_secret().into()).map_err(|err| {
            SignerError::CouldNotExtractPublicKey(format!("couldn't initialize secret key: {err}"))
        })?;
        let pk = VerifyingKey::from(&sk);

        if pk.to_encoded_point(true).as_bytes() != public_key {
            return Err(SignerError::CouldNotExtractKeyPair);
        }
        let signature: Signature = sk.sign(input);
        Ok(signature.to_vec())
    }

    fn verify(&self, input: &[u8], signature: &[u8], public_key: &[u8]) -> Result<(), SignerError> {
        let vk = Self::from_bytes(public_key)?;

        let signature =
            Signature::try_from(signature).map_err(|_| SignerError::InvalidSignature)?;

        vk.verify(input, &signature)
            .map_err(|err| SignerError::CouldNotVerify(format!("couldn't verify: {err}")))
    }
}

fn ec_key_to_public_jwk(key: JwkEcKey) -> Result<PublicJwk, EncryptionError> {
    let point = key.to_encoded_point::<NistP256>().map_err(|e| {
        EncryptionError::Crypto(format!("failed to convert JWK to encoded point: {e}"))
    })?;
    let x = Base64UrlSafeNoPadding::encode_to_string(
        point
            .x()
            .ok_or(EncryptionError::Crypto("missing x coordinate".to_string()))?,
    )
    .map_err(|e| EncryptionError::Crypto(format!("failed to encode x coordinate: {e}")))?;
    let y = Base64UrlSafeNoPadding::encode_to_string(
        point
            .y()
            .ok_or(EncryptionError::Crypto("missing y coordinate".to_string()))?,
    )
    .map_err(|e| EncryptionError::Crypto(format!("failed to encode x coordinate: {e}")))?;
    Ok(PublicJwk::Ec(PublicJwkEc {
        alg: None,
        r#use: None,
        kid: None,
        crv: key.crv().to_string(),
        x,
        y: Some(y),
    }))
}
