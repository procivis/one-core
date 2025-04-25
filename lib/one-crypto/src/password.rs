use pbkdf2::pbkdf2_hmac;
use secrecy::{ExposeSecret, ExposeSecretMut, SecretSlice, SecretString};
use sha2::Sha256;

use crate::utilities::generate_random_bytes;

#[derive(Default, Clone)]
pub struct Key {
    pub key: SecretSlice<u8>,
    pub salt: [u8; 32],
}

pub fn derive_key(password: &SecretString) -> Key {
    let mut key = SecretSlice::from(vec![0u8; 32]);
    let salt = generate_random_bytes::<32>();

    pbkdf2_hmac::<Sha256>(
        password.expose_secret().as_bytes(),
        &salt,
        600_000,
        key.expose_secret_mut(),
    );
    Key { key, salt }
}

pub fn derive_key_with_salt(password: &SecretString, salt: &[u8; 32]) -> SecretSlice<u8> {
    let mut key = SecretSlice::from(vec![0u8; 32]);
    pbkdf2_hmac::<Sha256>(
        password.expose_secret().as_bytes(),
        salt,
        600_000,
        key.expose_secret_mut(),
    );
    key
}
