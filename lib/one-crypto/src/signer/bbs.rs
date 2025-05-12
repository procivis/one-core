use blstrs::G2Affine;
use pairing_crypto::bbs::ciphersuites::bls12_381::{
    BBS_BLS12381G1_SIGNATURE_LENGTH, KeyPair, PublicKey, SecretKey,
};
use pairing_crypto::bbs::ciphersuites::bls12_381_g1_sha_256::{
    proof_gen, proof_verify, sign, verify,
};
use pairing_crypto::bbs::{
    BbsProofGenRequest, BbsProofGenRevealMessageRequest, BbsProofVerifyRequest, BbsSignRequest,
    BbsVerifyRequest,
};
use secrecy::{ExposeSecret, SecretSlice};
use serde::{Deserialize, Serialize};

use crate::utilities::get_rng;
use crate::{Signer, SignerError};

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
        private_key: &SecretSlice<u8>,
    ) -> Result<Vec<u8>, SignerError> {
        let secret_key = SecretKey::from_vec(private_key.expose_secret())
            .map_err(|_| SignerError::CouldNotExtractKeyPair)?;
        let public_key = PublicKey::from_vec(public_key)
            .map_err(|e| SignerError::CouldNotExtractPublicKey(e.to_string()))?;

        let input = parse_bbs_input(input);
        let signature = sign(&BbsSignRequest {
            secret_key: &secret_key.to_bytes(),
            public_key: &public_key.to_octets(),
            header: Some(input.header.clone()),
            messages: Some(&input.messages),
        })
        .map_err(|e| SignerError::CouldNotSign(e.to_string()))?;
        Ok(signature.to_vec())
    }

    fn verify(&self, input: &[u8], signature: &[u8], public_key: &[u8]) -> Result<(), SignerError> {
        let input = parse_bbs_input(input);
        BBSSigner::verify_bbs(input.header, input.messages, signature, public_key)
    }
}

/// The BBS signature input is structured. Try to parse it, otherwise use the input
/// just as plain key. The latter is used for e.g. revocation lists signature.
pub fn parse_bbs_input(input: &[u8]) -> BbsInput {
    if let Ok(parsed_input) = serde_json::from_slice(input) {
        parsed_input
    } else {
        BbsInput {
            header: input.to_owned(),
            messages: vec![],
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct BbsDeriveInput {
    pub header: Vec<u8>,
    pub messages: Vec<(Vec<u8>, bool)>,
    pub signature: Vec<u8>,
    pub presentation_header: Option<Vec<u8>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BbsProofInput {
    pub header: Vec<u8>,
    pub presentation_header: Option<Vec<u8>>,
    pub proof: Vec<u8>,
    pub messages: Vec<(usize, Vec<u8>)>,
}

pub struct GeneratedKey {
    pub public: Vec<u8>,
    pub private: SecretSlice<u8>,
}

impl BBSSigner {
    pub fn generate_key_pair() -> GeneratedKey {
        // There is not much to break hence default on failure should be good enough.
        let key_pair = KeyPair::random(&mut get_rng(), b"").unwrap_or_default();
        let private = key_pair.secret_key.to_bytes().to_vec().into();
        let public = key_pair.public_key.to_octets().to_vec();
        GeneratedKey { public, private }
    }

    pub fn derive_proof(input: BbsDeriveInput, public_key: &[u8]) -> Result<Vec<u8>, SignerError> {
        let public_key = PublicKey::from_vec(public_key)
            .map_err(|e| SignerError::CouldNotExtractPublicKey(e.to_string()))?;

        let header = input.header;

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
            presentation_header: input.presentation_header,
            verify_signature: Some(true),
        })
        .map_err(|e| SignerError::CouldNotSign(e.to_string()))?;

        Ok(signature)
    }

    pub fn verify_proof(input: &BbsProofInput, public_key: &[u8]) -> Result<(), SignerError> {
        let public_key = PublicKey::from_vec(public_key)
            .map_err(|e| SignerError::CouldNotExtractPublicKey(e.to_string()))?;

        let header = input.header.clone();

        let verified = proof_verify(&BbsProofVerifyRequest {
            public_key: &public_key.to_octets(),
            proof: &input.proof,
            header: Some(header),
            messages: Some(input.messages.as_slice()),
            presentation_header: input.presentation_header.clone(),
        })
        .map_err(|e| SignerError::CouldNotVerify(e.to_string()));

        if !(verified?) {
            return Err(SignerError::CouldNotVerify(
                "Bbs proof verification error".to_owned(),
            ));
        }

        Ok(())
    }

    pub fn parse_public_key(
        x: &[u8],
        y: &[u8],
        extract_compressed: bool,
    ) -> Result<Vec<u8>, SignerError> {
        if x.len() != 96 || y.len() != 96 {
            return Err(SignerError::CouldNotExtractPublicKey(
                "Invalid key size".to_string(),
            ));
        }

        let affine = Self::extract_affine(&[x, y].concat())?;
        Ok(if extract_compressed {
            affine.to_compressed().to_vec()
        } else {
            affine.to_uncompressed().to_vec()
        })
    }

    pub fn get_public_key_coordinates(
        public_key: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), SignerError> {
        let point = Self::extract_affine(public_key)?.to_uncompressed();
        let x = &point[..96];
        let y = &point[96..];
        Ok((x.to_vec(), y.to_vec()))
    }

    fn extract_affine(public_key: &[u8]) -> Result<G2Affine, SignerError> {
        let public = match public_key.len() {
            96 => blstrs::G2Affine::from_compressed(public_key.try_into().map_err(|_| {
                SignerError::CouldNotExtractPublicKey("Invalid key size".to_string())
            })?),
            192 => blstrs::G2Affine::from_uncompressed(public_key.try_into().map_err(|_| {
                SignerError::CouldNotExtractPublicKey("Invalid key size".to_string())
            })?),
            _ => {
                return Err(SignerError::CouldNotExtractPublicKey(
                    "Invalid key size".to_string(),
                ));
            }
        };

        Option::from(public)
            .ok_or_else(|| SignerError::CouldNotExtractPublicKey("Invalid key value".to_string()))
    }

    pub fn sign_bbs(
        header: Vec<u8>,
        messages: Vec<Vec<u8>>,
        private_key: &SecretSlice<u8>,
        public_key: &[u8],
    ) -> Result<Vec<u8>, SignerError> {
        let secret_key = SecretKey::from_vec(private_key.expose_secret())
            .map_err(|_| SignerError::CouldNotExtractKeyPair)?;
        let public_key = PublicKey::from_vec(public_key)
            .map_err(|e| SignerError::CouldNotExtractPublicKey(e.to_string()))?;

        let signature = sign(&BbsSignRequest {
            secret_key: &secret_key.to_bytes(),
            public_key: &public_key.to_octets(),
            header: Some(header),
            messages: Some(&messages),
        })
        .map_err(|e| SignerError::CouldNotSign(e.to_string()))?;
        Ok(signature.to_vec())
    }

    pub fn verify_bbs(
        header: Vec<u8>,
        messages: Vec<Vec<u8>>,
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<(), SignerError> {
        let public_key = PublicKey::from_vec(public_key)
            .map_err(|e| SignerError::CouldNotExtractPublicKey(e.to_string()))?;

        let result = verify(&BbsVerifyRequest {
            public_key: &public_key.to_octets(),
            header: Some(header),
            messages: Some(&messages),
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
