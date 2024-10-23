use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit};
use anyhow::Context;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PeerEncryption {
    sender_aes_key: [u8; 32],
    receiver_aes_key: [u8; 32],
    nonce: [u8; 12],
}

impl PeerEncryption {
    pub fn new(sender_aes_key: [u8; 32], receiver_aes_key: [u8; 32], nonce: [u8; 12]) -> Self {
        Self {
            sender_aes_key,
            receiver_aes_key,
            nonce,
        }
    }

    pub fn encrypt<T>(&self, data: &T) -> anyhow::Result<Vec<u8>>
    where
        T: Serialize,
    {
        let cipher = Aes256Gcm::new(&self.sender_aes_key.into());
        let plaintext = serde_json::to_vec(data).context("serialization error")?;

        // https://openid.bitbucket.io/connect/openid-4-verifiable-presentations-over-ble-1_0.html#section-6.1
        // The IV is the random nonce generated by the wallet
        // The AAD used as input for the GCM function MUST be an empty string
        cipher
            .encrypt(
                &self.nonce.into(),
                Payload {
                    aad: &[],
                    msg: &plaintext,
                },
            )
            .context("AES encryption error")
    }

    pub fn decrypt<T>(&self, ciphertext: &[u8]) -> anyhow::Result<T>
    where
        T: DeserializeOwned,
    {
        let cipher = Aes256Gcm::new(&self.receiver_aes_key.into());
        let decrypted_payload = cipher
            .decrypt(&self.nonce.into(), ciphertext)
            .context("AES decryption error");

        serde_json::from_slice(&decrypted_payload?).context("deserialization error")
    }
}
