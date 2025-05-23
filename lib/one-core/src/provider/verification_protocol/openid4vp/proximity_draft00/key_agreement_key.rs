use anyhow::Context;
use hkdf::Hkdf;
use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use one_crypto::utilities::get_rng;
use secrecy::{ExposeSecretMut, SecretSlice};
use x25519_dalek::{PublicKey, ReusableSecret};

// Ephemeral x25519 key pair, discarded after the symmetric keys are derived
#[derive(Clone)]
pub(super) struct KeyAgreementKey {
    secret_key: ReusableSecret,
}

impl KeyAgreementKey {
    pub(crate) fn new_random() -> Self {
        Self {
            secret_key: ReusableSecret::random_from_rng(get_rng()),
        }
    }

    // https://openid.bitbucket.io/connect/openid-4-verifiable-presentations-over-ble-1_0.html#name-session-key-computation
    // Two keys need to be derived
    // Messages to the wallet are encrypted using the session key SKWallet
    // Messages to the verifier are encrypted using the session key SKVerifier
    pub(crate) fn derive_session_secrets(
        self,
        their_public_key: [u8; 32],
        nonce: [u8; 12],
    ) -> anyhow::Result<(SecretSlice<u8>, SecretSlice<u8>)> {
        let their_public_key = x25519_dalek::PublicKey::from(their_public_key);
        let z_ab = self.secret_key.diffie_hellman(&their_public_key);
        let hasher = SHA256 {};

        // See https://github.com/openid/openid4vp_ble/issues/47#issuecomment-1991006348
        let salt = hasher.hash(&nonce).context("Failed to generate salt")?;

        let mut wallet_key = SecretSlice::from(vec![0; 32]);
        let mut verifier_key = SecretSlice::from(vec![0; 32]);

        Hkdf::<sha2::Sha256>::new(Some(&salt), z_ab.as_bytes())
            .expand("SKWallet".as_bytes(), wallet_key.expose_secret_mut())
            .context("Failed to expand SKWallet session key")?;

        Hkdf::<sha2::Sha256>::new(Some(&salt), z_ab.as_bytes())
            .expand("SKVerifier".as_bytes(), verifier_key.expose_secret_mut())
            .context("Failed to expand SKVerifier session key")?;

        Ok((wallet_key, verifier_key))
    }

    pub(crate) fn public_key_bytes(&self) -> [u8; 32] {
        PublicKey::from(&self.secret_key).to_bytes()
    }
}
