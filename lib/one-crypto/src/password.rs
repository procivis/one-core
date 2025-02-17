use pbkdf2::password_hash::rand_core::OsRng;
use pbkdf2::pbkdf2_hmac;
use rand::Rng;
use secrecy::{ExposeSecret, ExposeSecretMut, SecretSlice, SecretString};
use sha2::Sha256;

#[derive(Default, Clone)]
pub struct Key {
    pub key: SecretSlice<u8>,
    pub salt: [u8; 32],
}

pub fn derive_key(password: &SecretString) -> Key {
    let mut key = SecretSlice::from(vec![0u8; 32]);
    let salt: [u8; 32] = OsRng.gen();

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
