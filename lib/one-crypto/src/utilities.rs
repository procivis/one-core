use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use hmac::Mac;
use rand::distributions::{Alphanumeric, DistString};
use rand::rngs::ThreadRng;
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Deserializer};

use super::HmacSha256;

pub fn generate_salt_base64_16() -> String {
    let seed = generate_random_seed_16();

    //This operation should be safe as we control the input.
    Base64UrlSafeNoPadding::encode_to_string(seed).unwrap_or_default()
}

pub fn generate_alphanumeric(length: usize) -> String {
    Alphanumeric.sample_string(&mut rand::thread_rng(), length)
}

pub fn create_hmac(key: &[u8], message: &[u8]) -> Option<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(key).ok()?;
    mac.update(message);
    let result = mac.finalize();
    Some(result.into_bytes().to_vec())
}

pub fn generate_random_seed_32() -> [u8; 32] {
    let mut rng = ChaCha20Rng::from_entropy();
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    seed
}

pub fn generate_random_seed_16() -> [u8; 16] {
    let mut rng = ChaCha20Rng::from_entropy();
    let mut seed = [0u8; 16];
    rng.fill_bytes(&mut seed);
    seed
}

// TODO Try to use ChaCha20Rng here
pub fn get_rng() -> ThreadRng {
    rand::thread_rng()
}

pub fn generate_nonce() -> String {
    let mut rng = ChaCha20Rng::from_entropy();
    rng.gen::<[u8; 32]>().map(char::from).into_iter().collect()
}

pub fn deserialize_base64<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;

    Base64UrlSafeNoPadding::decode_to_vec(s, None).map_err(serde::de::Error::custom)
}
