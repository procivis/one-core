use std::io::Write;

use age::secrecy::Secret;
use ssh_key::{Algorithm, LineEnding, PrivateKey};

use crate::{
    config::data_structure::KeyStorageInternalParams,
    key_storage::{GeneratedKey, KeyStorage},
    service::error::ServiceError,
};

#[derive(Default)]
pub struct InternalKeyProvider {
    pub params: KeyStorageInternalParams,
}

impl KeyStorage for InternalKeyProvider {
    fn generate(&self, algorithm: &str) -> Result<GeneratedKey, ServiceError> {
        // Note: RSA private key generation takes around a minute in debug mode
        let algorithm = get_algorithm_from_string(algorithm)?;

        let private_key = PrivateKey::random(&mut rand::thread_rng(), algorithm)
            .map_err(|e| ServiceError::Other(e.to_string()))?;

        let passphrase = self.params.encryption.as_ref().map(|value| &value.value);

        let private_key_openssh_format = private_key
            .to_openssh(LineEnding::LF)
            .map_err(|e| ServiceError::Other(e.to_string()))?
            .to_string();
        let public_key_openssh_format = private_key
            .public_key()
            .to_openssh()
            .map_err(|e| ServiceError::Other(e.to_string()))?;

        Ok(GeneratedKey {
            public: public_key_openssh_format,
            private: encrypt_if_password_is_provided(&private_key_openssh_format, passphrase)?,
        })
    }
}

fn encrypt_if_password_is_provided(
    text: &str,
    passphrase: Option<&String>,
) -> Result<Vec<u8>, ServiceError> {
    match passphrase {
        None => Ok(text.as_bytes().to_vec()),
        Some(passphrase) => {
            let encryptor =
                age::Encryptor::with_user_passphrase(Secret::new(passphrase.to_string()));

            let mut encrypted = vec![];
            let mut writer = encryptor
                .wrap_output(&mut encrypted)
                .map_err(|e| ServiceError::Other(e.to_string()))?;
            writer
                .write_all(text.as_ref())
                .map_err(|e| ServiceError::Other(e.to_string()))?;
            writer
                .finish()
                .map_err(|e| ServiceError::Other(e.to_string()))?;

            Ok(encrypted)
        }
    }
}

fn get_algorithm_from_string(value: &str) -> Result<Algorithm, ServiceError> {
    // TODO: use crypto module to search these dynamically
    match value {
        "Ed25519" => Ok(Algorithm::Ed25519),
        _ => Err(ServiceError::IncorrectParameters),
    }
}
