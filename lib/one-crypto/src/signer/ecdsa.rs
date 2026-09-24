use p256::ecdh::diffie_hellman;
use p256::ecdsa::signature::{Signer as _, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::{FromSec1Point, ToSec1Point};
use p256::elliptic_curve::{Generate, SecretKey};
use p256::pkcs8::{DecodePublicKey, EncodePublicKey};
use p256::{AffinePoint, NistP256, Sec1Point};
use secrecy::{ExposeSecret, SecretSlice};
use standardized_types::jwk::PublicJwk;

use crate::encryption::EncryptionError;
use crate::jwe::decode_b64;
use crate::utilities::get_rng;
use crate::{Signer, SignerError};

pub struct ECDSASigner;

impl ECDSASigner {
    fn from_bytes(public_key: &[u8]) -> Result<VerifyingKey, SignerError> {
        VerifyingKey::from_sec1_bytes(public_key).map_err(|err| {
            SignerError::CouldNotExtractPublicKey(format!(
                "couldn't initialize verifying key: {err}"
            ))
        })
    }

    pub fn parse_public_key(public_key: &[u8], compressed: bool) -> Result<Vec<u8>, SignerError> {
        let vk = Self::from_bytes(public_key)?;
        Ok(vk.to_sec1_point(compressed).to_bytes().into())
    }

    pub fn parse_public_key_coordinates(
        x: &[u8],
        y: &[u8],
        compressed: bool,
    ) -> Result<Vec<u8>, SignerError> {
        let point = Self::point_from_public_key_coordinates(x, y)?;

        let key = VerifyingKey::from_sec1_point(&point).map_err(|err| {
            SignerError::CouldNotExtractPublicKey(format!(
                "couldn't initialize verifying key: {err}"
            ))
        })?;

        Ok(key.to_sec1_point(compressed).to_bytes().into())
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
            vk.to_sec1_point(compressed).to_bytes().into(),
        ))
    }

    pub fn parse_public_key_from_der(
        public_key_der: &[u8],
        compressed: bool,
    ) -> Result<Vec<u8>, SignerError> {
        let pk = p256::PublicKey::from_public_key_der(public_key_der)
            .map_err(|e| SignerError::CouldNotExtractPublicKey(e.to_string()))?;

        Ok(pk.to_sec1_point(compressed).to_bytes().into())
    }

    pub fn public_key_to_der(public_key_raw: &[u8]) -> Result<Vec<u8>, SignerError> {
        let vk = Self::from_bytes(public_key_raw)?;
        Ok(vk
            .to_public_key_der()
            .map_err(|e| SignerError::CouldNotExtractPublicKey(e.to_string()))?
            .as_bytes()
            .to_vec())
    }

    pub fn get_public_key_coordinates(
        public_key: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), SignerError> {
        let vk = Self::from_bytes(public_key)?;
        let point = vk.to_sec1_point(false);
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

    pub fn generate_key_pair() -> Result<(SecretSlice<u8>, Vec<u8>), SignerError> {
        let mut rng = get_rng();

        let sk = SigningKey::try_generate_from_rng(&mut rng)
            .map_err(|e| SignerError::CouldNotGenerateKeyPair(e.to_string()))?;
        let pk = VerifyingKey::from(&sk);
        Ok((
            sk.to_bytes().to_vec().into(),
            pk.to_sec1_point(true).to_bytes().into(),
        ))
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

        let point = Self::point_from_public_key_coordinates(&x, &y)
            .map_err(|e| EncryptionError::Crypto(e.to_string()))?;

        let peer_affine_point =
            AffinePoint::from_sec1_point(&point)
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

    pub fn public_key_coordinates(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), SignerError> {
        let verifying_key = ECDSASigner::from_bytes(public_key)?;
        let point = verifying_key.to_sec1_point(false);
        let x = point.x().ok_or(SignerError::CouldNotExtractPublicKey(
            "Missing X coordinate".to_string(),
        ))?;
        let y = point.y().ok_or(SignerError::CouldNotExtractPublicKey(
            "Missing Y coordinate".to_string(),
        ))?;
        Ok((x.to_vec(), y.to_vec()))
    }

    fn point_from_public_key_coordinates(x: &[u8], y: &[u8]) -> Result<Sec1Point, SignerError> {
        if x.len() != 32 {
            return Err(SignerError::CouldNotExtractPublicKey(format!(
                "Couldn't initialize verifying key, invalid x length: {}",
                x.len()
            )));
        };

        if y.len() != 32 {
            return Err(SignerError::CouldNotExtractPublicKey(format!(
                "Couldn't initialize verifying key, invalid y length: {}",
                y.len()
            )));
        };

        Ok(Sec1Point::from_affine_coordinates(
            &x.try_into().map_err(|err| {
                SignerError::CouldNotExtractPublicKey(format!(
                    "Couldn't initialize verifying key, invalid x length: {err}"
                ))
            })?,
            &y.try_into().map_err(|err| {
                SignerError::CouldNotExtractPublicKey(format!(
                    "Couldn't initialize verifying key, invalid y length: {err}"
                ))
            })?,
            false,
        ))
    }
}

impl Signer for ECDSASigner {
    fn sign(
        &self,
        input: &[u8],
        public_key: &[u8],
        private_key: &SecretSlice<u8>,
    ) -> Result<Vec<u8>, SignerError> {
        let sk = SigningKey::from_slice(private_key.expose_secret()).map_err(|err| {
            SignerError::CouldNotExtractPublicKey(format!("couldn't initialize secret key: {err}"))
        })?;
        let pk = VerifyingKey::from(&sk);

        if pk.to_sec1_point(true).as_bytes() != public_key {
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
