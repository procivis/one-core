use std::{collections::HashMap, sync::Arc};

use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use rand::distributions::{Alphanumeric, DistString, Uniform};
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

use hmac::{Hmac, Mac};
use sha2::Sha256;

use self::error::CryptoProviderError;
use self::{hasher::Hasher, signer::Signer};

pub mod error;
pub mod hasher;
pub mod signer;

type HmacSha256 = Hmac<Sha256>;

#[cfg(test)]
mod test;

#[cfg_attr(test, mockall::automock)]
pub trait CryptoProvider: Send + Sync {
    fn get_hasher(&self, hasher: &str) -> Result<Arc<dyn Hasher>, CryptoProviderError>;

    fn get_signer(&self, signer: &str) -> Result<Arc<dyn Signer>, CryptoProviderError>;

    fn generate_salt_base64(&self) -> String;

    fn generate_alphanumeric(&self, length: usize) -> String;

    fn generate_bytes(&self, length: usize) -> Vec<u8>;

    fn create_hmac(&self, key: &[u8], message: &[u8]) -> Option<Vec<u8>>;
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

    fn generate_bytes(&self, length: usize) -> Vec<u8> {
        let byte_range = Uniform::new_inclusive(0, 255);
        let data: Vec<u8> = rand::thread_rng()
            .sample_iter(byte_range)
            .take(length)
            .collect();
        data
    }

    fn create_hmac(&self, key: &[u8], message: &[u8]) -> Option<Vec<u8>> {
        let mut mac = HmacSha256::new_from_slice(key).ok()?;
        mac.update(message);
        let result = mac.finalize();
        Some(result.into_bytes().to_vec())
    }
}
