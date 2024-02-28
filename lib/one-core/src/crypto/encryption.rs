use std::io::Read;

use chacha20poly1305::{aead::Aead, AeadCore, ChaCha20Poly1305, KeyInit};
use rand::rngs::OsRng;

use super::password::derive_key;

#[derive(Debug, thiserror::Error)]
pub enum EncryptionError {
    #[error("file system error: {0}")]
    FsError(#[from] std::io::Error),
    #[error("crypto error: {0}")]
    Crypto(String),
}

pub fn encrypt_file(
    password: &str,
    output_path: &str,
    zip_file: impl Read,
) -> Result<(), EncryptionError> {
    let key = derive_key(password);

    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|err| EncryptionError::Crypto(err.to_string()))?;

    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let zip_data = std::io::read_to_string(zip_file)?;
    let ciphertext = cipher
        .encrypt(&nonce, zip_data.as_bytes())
        .map_err(|err| EncryptionError::Crypto(err.to_string()))?;
    std::fs::write(output_path, ciphertext)?;

    Ok(())
}
