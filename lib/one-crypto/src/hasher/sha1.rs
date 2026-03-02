use std::io::Read;

use ct_codecs::{Base64, Base64UrlSafeNoPadding, Encoder};
use sha1::{Digest, Sha1};

use crate::{Hasher, HasherError};

pub struct SHA1;

impl SHA1 {
    pub fn hash_reader(reader: &mut impl Read) -> Result<Vec<u8>, HasherError> {
        let mut hasher = Sha1::new();
        std::io::copy(reader, &mut hasher).map_err(|_| HasherError::CouldNotHash)?;
        Ok(hasher.finalize().to_vec())
    }
}

impl Hasher for SHA1 {
    fn hash_base64(&self, input: &[u8]) -> Result<String, HasherError> {
        let mut hasher = Sha1::new();
        hasher.update(input);
        let result = hasher.finalize();

        Base64::encode_to_string(result).map_err(|_| HasherError::CouldNotHash)
    }

    fn hash_base64_url(&self, input: &[u8]) -> Result<String, HasherError> {
        let mut hasher = Sha1::new();
        hasher.update(input);
        let result = hasher.finalize();

        Base64UrlSafeNoPadding::encode_to_string(result).map_err(|_| HasherError::CouldNotHash)
    }

    fn hash(&self, input: &[u8]) -> Result<Vec<u8>, HasherError> {
        let mut hasher = Sha1::new();
        hasher.update(input);
        Ok(hasher.finalize().to_vec())
    }
}
