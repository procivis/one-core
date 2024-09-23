use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::EncodedPoint;
use rand::thread_rng;

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

    pub fn to_bytes(public_key: &[u8]) -> Result<Vec<u8>, SignerError> {
        let vk = Self::from_bytes(public_key)?;
        Ok(vk.to_encoded_point(true).to_bytes().into())
    }

    pub fn random() -> (Vec<u8>, Vec<u8>) {
        let sk = SigningKey::random(&mut thread_rng());
        let pk = VerifyingKey::from(&sk);
        (
            sk.to_bytes().to_vec(),
            pk.to_encoded_point(true).to_bytes().into(),
        )
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
