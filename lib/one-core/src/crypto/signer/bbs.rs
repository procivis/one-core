use super::{Signer, SignerError};
use pairing_crypto::bbs::{
    ciphersuites::{
        bls12_381::{PublicKey, SecretKey},
        bls12_381_g1_sha_256::{sign, verify},
    },
    BbsSignRequest, BbsVerifyRequest,
};

pub struct BBSSigner {}

impl Signer for BBSSigner {
    fn sign(
        &self,
        input: &[u8],
        public_key: &[u8],
        private_key: &[u8],
    ) -> Result<Vec<u8>, SignerError> {
        let secret_key = SecretKey::from_vec(&private_key.to_vec())
            .map_err(|_| SignerError::CouldNotExtractKeyPair)?;
        let public_key = PublicKey::from_vec(&public_key.to_vec())
            .map_err(|e| SignerError::CouldNotExtractPublicKey(e.to_string()))?;

        let signature = sign(&BbsSignRequest {
            secret_key: &secret_key.to_bytes(),
            public_key: &public_key.to_octets(),
            header: None,

            // TODO: BBS signs an array of messages, proabably a serialization will need to be added in the interface to support JSON-LD
            messages: Some(&[input.to_vec()]),
        })
        .map_err(|e| SignerError::CouldNotSign(e.to_string()))?;

        Ok(signature.to_vec())
    }

    fn verify(&self, input: &[u8], signature: &[u8], public_key: &[u8]) -> Result<(), SignerError> {
        let public_key = PublicKey::from_vec(&public_key.to_vec())
            .map_err(|e| SignerError::CouldNotExtractPublicKey(e.to_string()))?;

        let result = verify(&BbsVerifyRequest {
            public_key: &public_key.to_octets(),
            header: None,
            messages: Some(&[input.to_vec()]), // TODO: similar issue here
            signature: signature
                .try_into()
                .map_err(|_| SignerError::InvalidSignature)?,
        })
        .map_err(|err| SignerError::CouldNotVerify(format!("couldn't verify: {err}")))?;

        if !result {
            return Err(SignerError::InvalidSignature);
        }

        Ok(())
    }
}
