use std::{
    fs::File,
    io::{Cursor, Read, Seek, SeekFrom, Write},
};

use chacha20poly1305::{
    aead::{Aead, Nonce},
    AeadCore, ChaCha20Poly1305, KeyInit,
};
use rand::rngs::OsRng;

use super::password::{derive_key, derive_key_with_salt};

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
    mut input_file: impl Read,
) -> Result<(), EncryptionError> {
    let key = derive_key(password);

    let cipher = ChaCha20Poly1305::new_from_slice(&key.key)
        .map_err(|err| EncryptionError::Crypto(err.to_string()))?;

    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

    let mut content = vec![];
    input_file.read_to_end(&mut content)?;

    let ciphertext = cipher
        .encrypt(&nonce, content.as_slice())
        .map_err(|err| EncryptionError::Crypto(err.to_string()))?;

    let mut file = File::create(output_path)?;

    file.write_all(&key.salt)?;
    file.write_all(&nonce)?;
    file.write_all(&ciphertext)?;

    Ok(())
}

pub fn decrypt_file<T: Write + Seek>(
    password: &str,
    mut encrypted_file: impl Read,
    output_file: &mut T,
) -> Result<(), EncryptionError> {
    let mut key_salt = [0; 32];
    encrypted_file.read_exact(&mut key_salt)?;

    let key = derive_key_with_salt(password, &key_salt);

    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|err| EncryptionError::Crypto(err.to_string()))?;

    let mut nonce = Nonce::<ChaCha20Poly1305>::default();
    encrypted_file.read_exact(&mut nonce)?;

    let mut content = vec![];
    encrypted_file.read_to_end(&mut content)?;

    let decrypted = cipher
        .decrypt(&nonce, content.as_slice())
        .map_err(|err| EncryptionError::Crypto(err.to_string()))?;

    std::io::copy(&mut Cursor::new(decrypted), output_file)?;
    output_file.seek(SeekFrom::Start(0))?;

    Ok(())
}
