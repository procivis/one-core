use pbkdf2::password_hash::rand_core::OsRng;
use pbkdf2::pbkdf2_hmac;
use rand::Rng;
use sha2::Sha256;
use zeroize::{DefaultIsZeroes, Zeroizing};

#[derive(Default, Copy, Clone)]
pub struct Key {
    pub key: [u8; 32],
    pub salt: [u8; 32],
}
impl DefaultIsZeroes for Key {}

pub fn derive_key(password: &str) -> Zeroizing<Key> {
    let mut key = [0u8; 32];
    let salt: [u8; 32] = OsRng.gen();

    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, 600_000, &mut key);
    Zeroizing::new(Key { key, salt })
}

pub fn derive_key_with_salt(password: &str, salt: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, 600_000, key.as_mut_slice());
    key
}
