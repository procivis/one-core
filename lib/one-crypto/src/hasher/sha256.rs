use std::io::Read;

use ct_codecs::{Base64, Base64UrlSafeNoPadding, Encoder};
use secrecy::zeroize::Zeroizing;
use sha2::{Digest, Sha256};

use crate::{Hasher, HasherError};

pub struct SHA256;

impl SHA256 {
    pub fn hash_reader(reader: &mut impl Read) -> Result<Vec<u8>, HasherError> {
        let mut hasher = Sha256::new();
        let mut buffer = Zeroizing::new([0u8; 4096]);

        loop {
            let bytes_read = reader
                .read(buffer.as_mut_slice())
                .map_err(|_| HasherError::CouldNotHash)?;
            if bytes_read == 0 {
                break; // EoF reached
            }
            hasher.update(buffer.get(..bytes_read).ok_or(HasherError::CouldNotHash)?);
        }

        Ok(hasher.finalize_reset().to_vec())
    }
}

impl Hasher for SHA256 {
    fn hash_base64(&self, input: &[u8]) -> Result<String, HasherError> {
        let mut hasher = Sha256::new();
        hasher.update(input);
        let result = hasher.finalize_reset().to_vec();

        Base64::encode_to_string(result).map_err(|_| HasherError::CouldNotHash)
    }

    fn hash_base64_url(&self, input: &[u8]) -> Result<String, HasherError> {
        let mut hasher = Sha256::new();
        hasher.update(input);
        let result = hasher.finalize_reset().to_vec();

        Base64UrlSafeNoPadding::encode_to_string(result).map_err(|_| HasherError::CouldNotHash)
    }

    fn hash(&self, input: &[u8]) -> Result<Vec<u8>, HasherError> {
        let mut hasher = Sha256::new();
        hasher.update(input);
        Ok(hasher.finalize_reset().to_vec())
    }
}
