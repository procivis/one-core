use crate::util::p_256::{p_256_sk_vk_pair_from_bytes, p_256_vk_from_bytes};

use super::{Signer, SignerError};
use p256::ecdsa::{
    signature::{Signer as _, Verifier as _},
    Signature,
};

pub struct ES256Signer {}

impl Signer for ES256Signer {
    fn sign(
        &self,
        input: &str,
        public_key: &[u8],
        private_key: &[u8],
    ) -> Result<Vec<u8>, SignerError> {
        let (sk, pk) = p_256_sk_vk_pair_from_bytes(private_key).ok_or_else(|| {
            SignerError::CouldNotExtractPublicKey("couldn't initialize secret key".into())
        })?;

        if pk.to_encoded_point(true).as_bytes() != public_key {
            return Err(SignerError::CouldNotExtractKeyPair);
        }
        let signature: Signature = sk.sign(input.as_bytes());
        Ok(signature.to_vec())
    }

    fn verify(&self, input: &str, signature: &[u8], public_key: &[u8]) -> Result<(), SignerError> {
        let vk = p_256_vk_from_bytes(public_key).ok_or_else(|| {
            SignerError::CouldNotExtractPublicKey("couldn't initialize verifying key".into())
        })?;

        let signature =
            Signature::try_from(signature).map_err(|_| SignerError::InvalidSignature)?;

        vk.verify(input.as_bytes(), &signature)
            .map_err(|err| SignerError::CouldNotVerify(format!("couldn't verify: {err}")))
    }
}
