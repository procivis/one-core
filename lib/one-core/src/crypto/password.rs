use pbkdf2::{
    password_hash::{rand_core::OsRng, SaltString},
    pbkdf2_hmac,
};
use sha2::Sha256;

pub fn derive_key(password: &str) -> [u8; 32] {
    let mut key = [0u8; 32];

    pbkdf2_hmac::<Sha256>(
        password.as_bytes(),
        SaltString::generate(&mut OsRng).as_str().as_bytes(),
        600_000,
        &mut key,
    );

    key
}
