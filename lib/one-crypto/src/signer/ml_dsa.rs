use ml_dsa::signature::{Signer as MlDsaSignerTrait, Verifier};
use ml_dsa::{
    B32, EncodedSignature, EncodedVerifyingKey, KeyGen, MlDsa65, Signature, VerifyingKey,
};
use rand_chacha_new::ChaCha20Rng;
use rand_new::SeedableRng;
use rand_new::rngs::SysRng;
use secrecy::{ExposeSecret, SecretSlice};

use crate::{Signer, SignerError};

pub struct MlDsaSigner;

pub struct KeyPair {
    pub public: Vec<u8>,
    pub seed: SecretSlice<u8>,
}

impl MlDsaSigner {
    pub fn generate_key_pair() -> Result<KeyPair, SignerError> {
        let mut rng = ChaCha20Rng::try_from_rng(&mut SysRng)
            .map_err(|err| SignerError::CouldNotGenerateKeyPair(err.to_string()))?;
        let kp = MlDsa65::key_gen(&mut rng);
        Ok(KeyPair {
            public: kp.verifying_key().encode().to_vec(),
            seed: SecretSlice::from(kp.to_seed().to_vec()),
        })
    }

    pub fn parse_key_pair(
        pub_bytes: &[u8],
        sec_bytes: &SecretSlice<u8>,
    ) -> Result<KeyPair, SignerError> {
        let seed = B32::try_from(sec_bytes.expose_secret())
            .map_err(|_| SignerError::CouldNotExtractKeyPair)?;
        let keys = MlDsa65::from_seed(&seed);
        let public = keys.verifying_key().encode().to_vec();
        if public != pub_bytes {
            return Err(SignerError::CouldNotExtractKeyPair);
        }
        Ok(KeyPair {
            seed: sec_bytes.clone(),
            public,
        })
    }
}

impl Signer for MlDsaSigner {
    fn sign(
        &self,
        input: &[u8],
        _public: &[u8],
        private_key: &SecretSlice<u8>,
    ) -> Result<Vec<u8>, SignerError> {
        let seed = B32::try_from(private_key.expose_secret())
            .map_err(|_| SignerError::CouldNotExtractKeyPair)?;
        let key_pair = MlDsa65::from_seed(&seed);
        let sig = key_pair.signing_key().sign(input);
        Ok(sig.encode().to_vec())
    }

    fn verify(&self, input: &[u8], signature: &[u8], public_key: &[u8]) -> Result<(), SignerError> {
        let encoded_key = EncodedVerifyingKey::<MlDsa65>::try_from(public_key)
            .map_err(|err| SignerError::CouldNotExtractPublicKey(format!("{err}")))?;
        let encoded_signature =
            EncodedSignature::<MlDsa65>::try_from(signature).map_err(|err| {
                SignerError::CouldNotVerify(format!("Invalid signature length: {err}"))
            })?;
        let sig = Signature::<MlDsa65>::decode(&encoded_signature).ok_or(
            SignerError::CouldNotVerify("Failed to decode signature".to_string()),
        )?;
        VerifyingKey::<MlDsa65>::decode(&encoded_key)
            .verify(input, &sig)
            .map_err(|_| SignerError::InvalidSignature)
    }
}
