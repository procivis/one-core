use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use sha2::{Digest, Sha256};

use super::{Hasher, HasherError};

pub struct SHA256 {}

impl Hasher for SHA256 {
    fn hash_base64(&self, input: &[u8]) -> Result<String, HasherError> {
        let mut hasher = Sha256::new();
        hasher.update(input);
        let result = hasher.finalize();

        Base64UrlSafeNoPadding::encode_to_string(result).map_err(|_| HasherError::CouldNotHash)
    }
}
