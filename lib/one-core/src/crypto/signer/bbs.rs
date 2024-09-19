use pairing_crypto::bbs::ciphersuites::bls12_381::{
    PublicKey, SecretKey, BBS_BLS12381G1_SIGNATURE_LENGTH,
};
use pairing_crypto::bbs::ciphersuites::bls12_381_g1_sha_256::{
    proof_gen, proof_verify, sign, verify,
};
use pairing_crypto::bbs::{
    BbsProofGenRequest, BbsProofGenRevealMessageRequest, BbsProofVerifyRequest, BbsSignRequest,
    BbsVerifyRequest,
};
use serde::{Deserialize, Serialize};

use crate::crypto::{Signer, SignerError};

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

#[derive(Serialize, Deserialize)]
pub struct BbsDeriveInput {
    pub header: Vec<u8>,
    pub messages: Vec<(Vec<u8>, bool)>,
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct BbsProofInput {
    pub header: Vec<u8>,
    pub presentation_header: Option<Vec<u8>>,
    pub proof: Vec<u8>,
    pub messages: Vec<(usize, Vec<u8>)>,
}

impl BBSSigner {
    pub fn derive_proof(input: &BbsDeriveInput, public_key: &[u8]) -> Result<Vec<u8>, SignerError> {
        let public_key = PublicKey::from_vec(&public_key.to_vec())
            .map_err(|e| SignerError::CouldNotExtractPublicKey(e.to_string()))?;

        let header = input.header.clone();

        let messages: Vec<BbsProofGenRevealMessageRequest<Vec<u8>>> = input
            .messages
            .iter()
            .map(|(value, disclosed)| BbsProofGenRevealMessageRequest {
                reveal: *disclosed,
                value: value.clone(),
            })
            .collect();

        let signature: [u8; BBS_BLS12381G1_SIGNATURE_LENGTH] = {
            let mut array = [0; BBS_BLS12381G1_SIGNATURE_LENGTH];
            let len = std::cmp::min(input.signature.len(), array.len());
            array[..len].copy_from_slice(&input.signature[..len]);
            array
        };

        let signature = proof_gen(&BbsProofGenRequest {
            public_key: &public_key.to_octets(),
            header: Some(header),
            messages: Some(messages.as_slice()),
            signature: &signature,
            presentation_header: None,
            verify_signature: Some(true),
        })
        .map_err(|e| SignerError::CouldNotSign(e.to_string()))?;

        Ok(signature.to_vec())
    }

    pub fn verify_proof(input: &BbsProofInput, public_key: &[u8]) -> Result<(), SignerError> {
        let public_key = PublicKey::from_vec(&public_key.to_vec())
            .map_err(|e| SignerError::CouldNotExtractPublicKey(e.to_string()))?;

        let header = input.header.clone();

        let verified = proof_verify(&BbsProofVerifyRequest {
            public_key: &public_key.to_octets(),
            proof: &input.proof,
            header: Some(header),
            messages: Some(input.messages.as_slice()),
            presentation_header: None,
        })
        .map_err(|e| SignerError::CouldNotVerify(e.to_string()))?;

        if !verified {
            return Err(SignerError::CouldNotVerify(
                "Bbs proof verification error".to_owned(),
            ));
        }

        Ok(())
    }
}
