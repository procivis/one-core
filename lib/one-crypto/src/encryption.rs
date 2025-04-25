use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};

use chacha20poly1305::aead::{Aead, Nonce};
use chacha20poly1305::{AeadCore, ChaCha20Poly1305, KeyInit};
use cocoon::MiniCocoon;
use secrecy::{ExposeSecret, SecretSlice, SecretString};

use super::password::{derive_key, derive_key_with_salt};
use crate::utilities::{self, get_rng};

#[derive(Debug, thiserror::Error)]
pub enum EncryptionError {
    #[error("file system error: {0}")]
    FsError(#[from] std::io::Error),
    #[error("crypto error: {0}")]
    Crypto(String),
}

pub fn encrypt_file(
    password: &SecretString,
    output_path: &str,
    mut input_file: impl Read,
) -> Result<(), EncryptionError> {
    let key = derive_key(password);

    let cipher = ChaCha20Poly1305::new_from_slice(key.key.expose_secret())
        .map_err(|err| EncryptionError::Crypto(err.to_string()))?;

    let nonce = ChaCha20Poly1305::generate_nonce(get_rng());

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
    password: &SecretString,
    mut encrypted_file: impl Read,
    output_file: &mut T,
) -> Result<(), EncryptionError> {
    let mut key_salt = [0; 32];
    encrypted_file.read_exact(&mut key_salt)?;

    let key = derive_key_with_salt(password, &key_salt);

    let cipher = ChaCha20Poly1305::new_from_slice(key.expose_secret())
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

pub fn encrypt_string(
    data: &SecretString,
    encryption_key: &SecretSlice<u8>,
) -> Result<Vec<u8>, EncryptionError> {
    encrypt_data(
        &SecretSlice::from(data.expose_secret().as_bytes().to_vec()),
        encryption_key,
    )
}

pub fn encrypt_data(
    data: &SecretSlice<u8>,
    encryption_key: &SecretSlice<u8>,
) -> Result<Vec<u8>, EncryptionError> {
    let mut cocoon = MiniCocoon::from_key(
        encryption_key.expose_secret(),
        &utilities::generate_random_bytes::<32>(),
    );
    cocoon
        .wrap(data.expose_secret())
        .map_err(|err| EncryptionError::Crypto(format!("failed to encrypt: {:?}", err)))
}

pub fn decrypt_string(
    data: &[u8],
    encryption_key: &SecretSlice<u8>,
) -> Result<SecretString, EncryptionError> {
    let decrypted = decrypt_data(data, encryption_key)?;
    Ok(SecretString::from(
        String::from_utf8(decrypted.expose_secret().to_vec()).map_err(|err| {
            EncryptionError::Crypto(format!("failed to decrypt string data: {:?}", err))
        })?,
    ))
}

pub fn decrypt_data(
    data: &[u8],
    encryption_key: &SecretSlice<u8>,
) -> Result<SecretSlice<u8>, EncryptionError> {
    // seed is not used for decryption, so passing dummy value
    let cocoon = MiniCocoon::from_key(encryption_key.expose_secret(), &[0u8; 32]);
    cocoon
        .unwrap(data)
        .map(SecretSlice::from)
        .map_err(|err| EncryptionError::Crypto(format!("failed to decrypt: {:?}", err)))
}
