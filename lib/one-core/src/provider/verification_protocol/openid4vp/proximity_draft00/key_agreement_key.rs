use anyhow::Context;
use hkdf::Hkdf;
use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use one_crypto::signer::eddsa::EDDSASigner;
use secrecy::{ExposeSecret, ExposeSecretMut, SecretSlice};

// Ephemeral x25519 key pair, discarded after the symmetric keys are derived
#[derive(Clone)]
pub(crate) struct KeyAgreementKey {
    private_key: SecretSlice<u8>,
    public_key: [u8; 32],
}

impl KeyAgreementKey {
    pub(crate) fn generate() -> anyhow::Result<Self> {
        let key = EDDSASigner::generate_key_pair();
        let public_key = EDDSASigner::public_key_into_x25519(&key.public)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to convert public key"))?;
        Ok(Self {
            private_key: key.private,
            public_key,
        })
    }

    // https://openid.bitbucket.io/connect/openid-4-verifiable-presentations-over-ble-1_0.html#name-session-key-computation
    // Two keys need to be derived
    // Messages to the wallet are encrypted using the session key SKWallet
    // Messages to the verifier are encrypted using the session key SKVerifier
    pub(crate) fn derive_session_secrets(
        &self,
        their_public_key: [u8; 32],
        nonce: [u8; 12],
    ) -> anyhow::Result<(SecretSlice<u8>, SecretSlice<u8>)> {
        let z_ab = EDDSASigner::shared_secret_x25519_bytes(&self.private_key, &their_public_key)?;

        // See https://github.com/openid/openid4vp_ble/issues/47#issuecomment-1991006348
        let salt = SHA256.hash(&nonce).context("Failed to generate salt")?;

        let mut wallet_key = SecretSlice::from(vec![0; 32]);
        let mut verifier_key = SecretSlice::from(vec![0; 32]);

        Hkdf::<sha2::Sha256>::new(Some(&salt), z_ab.expose_secret())
            .expand("SKWallet".as_bytes(), wallet_key.expose_secret_mut())
            .context("Failed to expand SKWallet session key")?;

        Hkdf::<sha2::Sha256>::new(Some(&salt), z_ab.expose_secret())
            .expand("SKVerifier".as_bytes(), verifier_key.expose_secret_mut())
            .context("Failed to expand SKVerifier session key")?;

        Ok((wallet_key, verifier_key))
    }

    pub(crate) fn public_key_bytes(&self) -> [u8; 32] {
        self.public_key
    }
}
