use std::{collections::HashMap, sync::Arc};

use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use rand::distributions::{Alphanumeric, DistString};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

use self::{hasher::Hasher, signer::Signer};

pub mod hasher;
pub mod signer;

#[derive(Clone, Default)]
pub struct Crypto {
    pub hashers: HashMap<String, Arc<dyn Hasher + Send + Sync>>,
    pub signers: HashMap<String, Arc<dyn Signer + Send + Sync>>,
}

impl Crypto {
    pub fn generate_salt_base64() -> String {
        let mut rng = ChaCha20Rng::from_entropy();
        let mut data = [0u8; 16];
        rng.fill_bytes(&mut data);

        //This operation should be safe as we control the input.
        Base64UrlSafeNoPadding::encode_to_string(data).unwrap_or_default()
    }

    pub fn generate_alphanumeric(length: usize) -> String {
        Alphanumeric.sample_string(&mut rand::thread_rng(), length)
    }
}

pub trait Key {
    fn generate();
    fn get_private() -> Vec<u8>;
    fn get_public() -> Vec<u8>;
}
