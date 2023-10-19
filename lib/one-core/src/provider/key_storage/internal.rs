use std::io::{Read, Write};

use age::secrecy::Secret;
use did_key::{Fingerprint, Generate, KeyMaterial};

use crate::{
    config::data_structure::KeyStorageInternalParams,
    provider::key_storage::{GeneratedKey, KeyStorage},
    service::error::ServiceError,
};

#[derive(Default)]
pub struct InternalKeyProvider {
    pub params: KeyStorageInternalParams,
}

impl KeyStorage for InternalKeyProvider {
    fn decrypt_private_key(&self, private_key: &[u8]) -> Result<Vec<u8>, ServiceError> {
        let passphrase = self.params.encryption.as_ref().map(|value| &value.value);
        decrypt_if_password_is_provided(private_key, passphrase)
    }

    fn fingerprint(&self, public_key: &[u8]) -> String {
        let key = did_key::Ed25519KeyPair::from_public_key(public_key);
        key.fingerprint()
    }

    fn generate(&self, algorithm: &str) -> Result<GeneratedKey, ServiceError> {
        // Note: RSA private key generation takes around a minute in debug mode
        let key_pair = get_key_pair_from_algorithm_string(algorithm)?;
        let passphrase = self.params.encryption.as_ref().map(|value| &value.value);

        Ok(GeneratedKey {
            public: key_pair.public,
            private: encrypt_if_password_is_provided(&key_pair.private, passphrase)?,
        })
    }
}

fn decrypt_if_password_is_provided(
    data: &[u8],
    passphrase: Option<&String>,
) -> Result<Vec<u8>, ServiceError> {
    match passphrase {
        None => Ok(data.to_vec()),
        Some(passphrase) => {
            let decryptor =
                match age::Decryptor::new(data).map_err(|e| ServiceError::Other(e.to_string()))? {
                    age::Decryptor::Passphrase(d) => Ok(d),
                    _ => Err(ServiceError::Other(
                        "Failed to create decryptor".to_string(),
                    )),
                }?;

            let mut decrypted = vec![];
            let mut reader = decryptor
                .decrypt(&Secret::new(passphrase.to_owned()), None)
                .map_err(|e| ServiceError::Other(e.to_string()))?;
            reader
                .read_to_end(&mut decrypted)
                .map_err(|e| ServiceError::Other(e.to_string()))?;

            Ok(decrypted)
        }
    }
}

fn encrypt_if_password_is_provided(
    buffer: &[u8],
    passphrase: Option<&String>,
) -> Result<Vec<u8>, ServiceError> {
    match passphrase {
        None => Ok(buffer.to_vec()),
        Some(passphrase) => {
            let encryptor =
                age::Encryptor::with_user_passphrase(Secret::new(passphrase.to_string()));

            let mut encrypted = vec![];
            let mut writer = encryptor
                .wrap_output(&mut encrypted)
                .map_err(|e| ServiceError::Other(e.to_string()))?;
            writer
                .write_all(buffer.as_ref())
                .map_err(|e| ServiceError::Other(e.to_string()))?;
            writer
                .finish()
                .map_err(|e| ServiceError::Other(e.to_string()))?;

            Ok(encrypted)
        }
    }
}

fn get_key_pair_from_algorithm_string(value: &str) -> Result<GeneratedKey, ServiceError> {
    // TODO: use crypto module to search these dynamically
    match value {
        "Ed25519" => {
            let key_pair = did_key::Ed25519KeyPair::new();
            Ok(GeneratedKey {
                public: key_pair.public_key_bytes(),
                private: key_pair.private_key_bytes(),
            })
        }
        _ => Err(ServiceError::IncorrectParameters),
    }
}
