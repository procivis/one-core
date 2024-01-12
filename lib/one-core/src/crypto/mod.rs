use std::{collections::HashMap, sync::Arc};

use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use rand::distributions::{Alphanumeric, DistString};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

use self::error::CryptoProviderError;
use self::{hasher::Hasher, signer::Signer};

pub mod error;
pub mod hasher;
pub mod signer;

#[cfg(test)]
mod test;

#[cfg_attr(test, mockall::automock)]
pub trait CryptoProvider: Send + Sync {
    fn get_hasher(&self, hasher: &str) -> Result<Arc<dyn Hasher>, CryptoProviderError>;

    fn get_signer(&self, signer: &str) -> Result<Arc<dyn Signer>, CryptoProviderError>;

    fn generate_salt_base64(&self) -> String;

    fn generate_alphanumeric(&self, length: usize) -> String;
}

#[derive(Clone)]
pub struct CryptoProviderImpl {
    hashers: HashMap<String, Arc<dyn Hasher>>,
    signers: HashMap<String, Arc<dyn Signer>>,
}

impl CryptoProviderImpl {
    pub fn new(
        hashers: HashMap<String, Arc<dyn Hasher>>,
        signers: HashMap<String, Arc<dyn Signer>>,
    ) -> Self {
        Self { hashers, signers }
    }
}

impl CryptoProvider for CryptoProviderImpl {
    fn get_hasher(&self, hasher: &str) -> Result<Arc<dyn Hasher>, CryptoProviderError> {
        Ok(self
            .hashers
            .get(hasher)
            .ok_or(CryptoProviderError::MissingHasher(hasher.to_owned()))?
            .clone())
    }

    fn get_signer(&self, signer: &str) -> Result<Arc<dyn Signer>, CryptoProviderError> {
        Ok(self
            .signers
            .get(signer)
            .ok_or(CryptoProviderError::MissingHasher(signer.to_owned()))?
            .clone())
    }

    fn generate_salt_base64(&self) -> String {
        let mut rng = ChaCha20Rng::from_entropy();
        let mut data = [0u8; 16];
        rng.fill_bytes(&mut data);

        //This operation should be safe as we control the input.
        Base64UrlSafeNoPadding::encode_to_string(data).unwrap_or_default()
    }

    fn generate_alphanumeric(&self, length: usize) -> String {
        Alphanumeric.sample_string(&mut rand::thread_rng(), length)
    }
}
