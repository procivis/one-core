use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use hmac::Mac;
use rand::distributions::{Alphanumeric, DistString};
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Deserializer};

use super::HmacSha256;

pub fn generate_salt_base64_16() -> String {
    let seed = generate_random_bytes::<16>();

    //This operation should be safe as we control the input.
    Base64UrlSafeNoPadding::encode_to_string(seed).unwrap_or_default()
}

pub fn generate_alphanumeric(length: usize) -> String {
    Alphanumeric.sample_string(&mut get_rng(), length)
}

pub fn create_hmac(key: &[u8], message: &[u8]) -> Option<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(key).ok()?;
    mac.update(message);
    let result = mac.finalize();
    Some(result.into_bytes().to_vec())
}

pub fn build_hmac_sha256(key: &[u8]) -> Option<impl FnMut(&[u8]) -> Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(key).ok()?;
    Some(move |message: &[u8]| {
        mac.update(message);
        mac.finalize_reset().into_bytes().to_vec()
    })
}

pub fn generate_random_bytes<const N: usize>() -> [u8; N] {
    let mut res = [0u8; N];
    get_rng().fill_bytes(&mut res);
    res
}

pub fn get_rng() -> impl RngCore + CryptoRng {
    ChaCha20Rng::from_entropy()
}

pub fn deserialize_base64<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;

    Base64UrlSafeNoPadding::decode_to_vec(s, None).map_err(serde::de::Error::custom)
}
