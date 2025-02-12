use p256::ecdh::diffie_hellman;
use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::generic_array::GenericArray;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::elliptic_curve::SecretKey;
use p256::pkcs8::DecodePublicKey;
use p256::{AffinePoint, EncodedPoint, NistP256, PublicKey};
use rand::thread_rng;
use zeroize::Zeroizing;

use crate::encryption::EncryptionError;
use crate::jwe::{decode_b64, RemoteJwk};
use crate::{Signer, SignerError};

pub struct ES256Signer {}

impl ES256Signer {
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

    pub fn generate_key_pair() -> (Zeroizing<Vec<u8>>, Vec<u8>) {
        let sk = SigningKey::random(&mut thread_rng());
        let pk = VerifyingKey::from(&sk);
        (
            sk.to_bytes().to_vec().into(),
            pk.to_encoded_point(true).to_bytes().into(),
        )
    }

    pub fn private_key_as_jwk(secret_key: &[u8]) -> Result<Zeroizing<String>, SignerError> {
        let secret_key = p256::SecretKey::from_slice(secret_key)
            .map_err(|_| SignerError::CouldNotExtractKeyPair)?;

        Ok(secret_key.to_jwk_string())
    }

    pub fn shared_secret_p256(
        private_key: &[u8],
        recipient_jwk: &RemoteJwk,
    ) -> Result<Zeroizing<Vec<u8>>, EncryptionError> {
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

        let secret_key: SecretKey<NistP256> = SecretKey::from_slice(private_key)
            .map_err(|e| EncryptionError::Crypto(e.to_string()))?;

        let shared_secret: [u8; 32] =
            diffie_hellman(secret_key.to_nonzero_scalar(), peer_affine_point)
                .raw_secret_bytes()
                .as_slice()
                .try_into()
                .map_err(|e| {
                    EncryptionError::Crypto(format!("failed to convert to array: {}", e))
                })?;
        Ok(Zeroizing::new(shared_secret.to_vec()))
    }

    pub fn bytes_as_jwk(public_key: &[u8]) -> Result<RemoteJwk, EncryptionError> {
        let verifying_key = ES256Signer::from_bytes(public_key)
            .map_err(|e| EncryptionError::Crypto(e.to_string()))?;
        let public_key = PublicKey::from(verifying_key);
        public_key.to_jwk().try_into()
    }
}

impl Signer for ES256Signer {
    fn sign(
        &self,
        input: &[u8],
        public_key: &[u8],
        private_key: &[u8],
    ) -> Result<Vec<u8>, SignerError> {
        let sk = SigningKey::from_bytes(private_key.into()).map_err(|err| {
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
