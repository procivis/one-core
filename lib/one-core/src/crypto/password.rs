use pbkdf2::{password_hash::rand_core::OsRng, pbkdf2_hmac};
use rand::Rng;
use sha2::Sha256;

pub struct Key {
    pub key: [u8; 32],
    pub salt: [u8; 32],
}

pub fn derive_key(password: &str) -> Key {
    let mut key = [0u8; 32];
    let salt: [u8; 32] = OsRng.gen();

    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, 600_000, &mut key);
    Key { key, salt }
}

pub fn derive_key_with_salt(password: &str, salt: &[u8; 32]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, 600_000, &mut key);
    key
}
