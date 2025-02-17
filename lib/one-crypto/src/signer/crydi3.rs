use pqc_dilithium::*;
use secrecy::{ExposeSecret, SecretSlice};

use crate::{Signer, SignerError};
pub struct CRYDI3Signer {}

pub struct KeyPair {
    pub public: Vec<u8>,
    pub private: SecretSlice<u8>,
}

impl CRYDI3Signer {
    pub fn generate_key_pair() -> KeyPair {
        let keys = pqc_dilithium::Keypair::generate();
        KeyPair {
            private: keys.expose_secret().to_vec().into(),
            public: keys.public.to_vec(),
        }
    }
}

impl Signer for CRYDI3Signer {
    fn sign(
        &self,
        input: &[u8],
        public_key: &[u8],
        private_key: &SecretSlice<u8>,
    ) -> Result<Vec<u8>, SignerError> {
        // TODO ONE-4671: KeyPair is _not_ zeroizing!
        let key_pair = Keypair::new(public_key.to_vec(), private_key.expose_secret().to_vec())
            .map_err(|_| SignerError::CouldNotExtractKeyPair)?;

        Ok(key_pair.sign(input).to_vec())
    }

    fn verify(&self, input: &[u8], signature: &[u8], public_key: &[u8]) -> Result<(), SignerError> {
        verify(signature, input, public_key).map_err(|_| SignerError::InvalidSignature)
    }
}
