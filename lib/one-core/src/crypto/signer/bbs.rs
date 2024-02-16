use super::{Signer, SignerError};
use pairing_crypto::bbs::{
    ciphersuites::{
        bls12_381::{PublicKey, SecretKey},
        bls12_381_g1_sha_256::{sign, verify},
    },
    BbsSignRequest, BbsVerifyRequest,
};
use serde::{Deserialize, Serialize};

pub struct BBSSigner {}

#[derive(Serialize, Deserialize)]
pub struct BbsInput {
    pub header: Vec<u8>,
    pub messages: Vec<Vec<u8>>,
}

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

        // Here we accept BbsInput if serialization succeeded or try to use the input
        // just as plain key. The latter is used for e.g. revocation lists signature.
        let input: BbsInput = if let Ok(parsed_input) = serde_json::from_slice(input) {
            parsed_input
        } else {
            BbsInput {
                header: input.to_owned(),
                messages: vec![],
            }
        };

        let signature = sign(&BbsSignRequest {
            secret_key: &secret_key.to_bytes(),
            public_key: &public_key.to_octets(),
            header: Some(input.header),
            messages: Some(&input.messages),
        })
        .map_err(|e| SignerError::CouldNotSign(e.to_string()))?;

        Ok(signature.to_vec())
    }

    fn verify(&self, input: &[u8], signature: &[u8], public_key: &[u8]) -> Result<(), SignerError> {
        let public_key = PublicKey::from_vec(&public_key.to_vec())
            .map_err(|e| SignerError::CouldNotExtractPublicKey(e.to_string()))?;

        // TODO: deserialize input for JSONLD or just status list.

        let result = verify(&BbsVerifyRequest {
            public_key: &public_key.to_octets(),
            header: Some(input.to_vec()),
            messages: None,
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
