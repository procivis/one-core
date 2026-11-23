//! Hybrid Public Key Encryption ([RFC 9180]) — recipient side.
//!
//! Only the single-shot Base mode with the ciphersuite
//! `DHKEM(P-256, HKDF-SHA256)` / `HKDF-SHA256` / `AES-128-GCM` is supported.
//!
//! The recipient private key is never accessed directly: the Diffie-Hellman step is delegated
//! to a [`PrivateKeyAgreementHandle`], which allows decryption with keys held in
//! a key storage that doesn't expose the private key material.
//!
//! [RFC 9180]: https://www.rfc-editor.org/rfc/rfc9180.html

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, KeyInit};
use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use hkdf::{Hkdf, HkdfExtract};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretSlice};
use sha2::Sha256;
use standardized_types::jwk::{PublicJwk, PublicJwkEc};

use crate::encryption::EncryptionError;
use crate::jwe::PrivateKeyAgreementHandle;
use crate::signer::ecdsa::ECDSASigner;
use crate::utilities::HybridArrayExt;

const VERSION_LABEL: &[u8] = b"HPKE-v1";
const MODE_BASE: u8 = 0x00;

/// `"KEM" || I2OSP(kem_id, 2)`, kem_id `0x0010` = DHKEM(P-256, HKDF-SHA256) (RFC 9180 §4.1)
const KEM_SUITE_ID: &[u8] = b"KEM\x00\x10";
/// `"HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) || I2OSP(aead_id, 2)` (RFC 9180 §5.1),
/// kdf_id `0x0001` = HKDF-SHA256, aead_id `0x0001` = AES-128-GCM
const HPKE_SUITE_ID: &[u8] = b"HPKE\x00\x10\x00\x01\x00\x01";

/// Size of the KEM shared secret (`Nsecret`)
const N_SECRET: usize = 32;
/// Size of the encapsulated key (`Nenc`) — uncompressed SEC1 P-256 point
const N_ENC: usize = 65;
/// Size of the P-256 Diffie-Hellman output (x-coordinate)
const N_DH: usize = 32;
/// Size of the AEAD key (`Nk`)
const N_K: usize = 16;
/// Size of the AEAD nonce (`Nn`)
const N_N: usize = 12;

/// Single-shot HPKE open (RFC 9180 §6.1) in Base mode,
/// ciphersuite `DHKEM(P-256, HKDF-SHA256)` / `HKDF-SHA256` / `AES-128-GCM`.
///
/// * `private_key` — recipient key, used only for the Diffie-Hellman step
/// * `recipient_public_key` — SEC1 encoded (compressed or uncompressed) public key of the recipient
/// * `encapsulated_key` — `enc` produced by the sender (uncompressed SEC1 point)
pub async fn open_p256_sha256_aes128gcm(
    private_key: &dyn PrivateKeyAgreementHandle,
    recipient_public_key: &[u8],
    encapsulated_key: &[u8],
    info: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    let shared_secret = decap(private_key, recipient_public_key, encapsulated_key).await?;
    let (key, base_nonce) = key_schedule_base(&shared_secret, info)?;

    // single-shot open uses sequence number 0, so the nonce equals base_nonce
    Aes128Gcm::new(key.as_hybrid_array()?)
        .decrypt(
            base_nonce.as_hybrid_array()?,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|e| EncryptionError::Crypto(format!("HPKE: failed to decrypt: {e}")))
}

/// DHKEM `Decap(enc, skR)` (RFC 9180 §4.1)
async fn decap(
    private_key: &dyn PrivateKeyAgreementHandle,
    recipient_public_key: &[u8],
    encapsulated_key: &[u8],
) -> Result<SecretSlice<u8>, EncryptionError> {
    // DeserializePublicKey(enc): only the uncompressed form is valid
    if encapsulated_key.len() != N_ENC {
        return Err(EncryptionError::Crypto(format!(
            "HPKE: invalid encapsulated key length: expected {N_ENC}, got {}",
            encapsulated_key.len()
        )));
    }
    let ephemeral_jwk = p256_public_jwk(encapsulated_key)?;

    // SerializePublicKey(pkR)
    let recipient_public_key = ECDSASigner::parse_public_key(recipient_public_key, false)
        .map_err(|e| EncryptionError::Crypto(format!("HPKE: invalid recipient key: {e}")))?;

    // dh = DH(skR, pkE)
    let dh = private_key.shared_secret(&ephemeral_jwk).await?;
    if dh.expose_secret().len() != N_DH {
        return Err(EncryptionError::Crypto(format!(
            "HPKE: invalid DH output length: expected {N_DH}, got {}",
            dh.expose_secret().len()
        )));
    }

    let kem_context = [encapsulated_key, recipient_public_key.as_slice()].concat();
    extract_and_expand(&dh, &kem_context)
}

/// DHKEM `ExtractAndExpand(dh, kem_context)` (RFC 9180 §4.1)
fn extract_and_expand(
    dh: &SecretSlice<u8>,
    kem_context: &[u8],
) -> Result<SecretSlice<u8>, EncryptionError> {
    let (_, eae_prk) = labeled_extract(&[], KEM_SUITE_ID, b"eae_prk", dh.expose_secret());

    let mut shared_secret = SecretSlice::from(vec![0u8; N_SECRET]);
    labeled_expand(
        &eae_prk,
        KEM_SUITE_ID,
        b"shared_secret",
        kem_context,
        shared_secret.expose_secret_mut(),
    )?;
    Ok(shared_secret)
}

/// `KeySchedule` (RFC 9180 §5.1) for Base mode (`psk = psk_id = ""`),
/// returns the AEAD `key` and `base_nonce`
fn key_schedule_base(
    shared_secret: &SecretSlice<u8>,
    info: &[u8],
) -> Result<(SecretSlice<u8>, [u8; N_N]), EncryptionError> {
    let (psk_id_hash, _) = labeled_extract(&[], HPKE_SUITE_ID, b"psk_id_hash", &[]);
    let (info_hash, _) = labeled_extract(&[], HPKE_SUITE_ID, b"info_hash", info);
    let key_schedule_context =
        [&[MODE_BASE], psk_id_hash.as_slice(), info_hash.as_slice()].concat();

    let (_, secret) = labeled_extract(shared_secret.expose_secret(), HPKE_SUITE_ID, b"secret", &[]);

    let mut key = SecretSlice::from(vec![0u8; N_K]);
    labeled_expand(
        &secret,
        HPKE_SUITE_ID,
        b"key",
        &key_schedule_context,
        key.expose_secret_mut(),
    )?;

    let mut base_nonce = [0u8; N_N];
    labeled_expand(
        &secret,
        HPKE_SUITE_ID,
        b"base_nonce",
        &key_schedule_context,
        &mut base_nonce,
    )?;

    Ok((key, base_nonce))
}

/// `LabeledExtract(salt, label, ikm) = Extract(salt, "HPKE-v1" || suite_id || label || ikm)`
fn labeled_extract(
    salt: &[u8],
    suite_id: &[u8],
    label: &[u8],
    ikm: &[u8],
) -> (hkdf::hmac::digest::Output<Sha256>, Hkdf<Sha256>) {
    let mut extract = HkdfExtract::<Sha256>::new(Some(salt));
    extract.input_ikm(VERSION_LABEL);
    extract.input_ikm(suite_id);
    extract.input_ikm(label);
    extract.input_ikm(ikm);
    extract.finalize()
}

/// `LabeledExpand(prk, label, info, L) = Expand(prk, I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info, L)`
fn labeled_expand(
    prk: &Hkdf<Sha256>,
    suite_id: &[u8],
    label: &[u8],
    info: &[u8],
    out: &mut [u8],
) -> Result<(), EncryptionError> {
    let length = u16::try_from(out.len())
        .map_err(|_| EncryptionError::Crypto("HPKE: expand length too large".to_string()))?
        .to_be_bytes();
    prk.expand_multi_info(&[&length, VERSION_LABEL, suite_id, label, info], out)
        .map_err(|e| EncryptionError::Crypto(format!("HPKE: failed to expand: {e}")))
}

fn p256_public_jwk(sec1: &[u8]) -> Result<PublicJwk, EncryptionError> {
    let (x, y) = ECDSASigner::get_public_key_coordinates(sec1)
        .map_err(|e| EncryptionError::Crypto(format!("HPKE: invalid encapsulated key: {e}")))?;
    let encode = |coordinate: Vec<u8>| {
        Base64UrlSafeNoPadding::encode_to_string(coordinate)
            .map_err(|e| EncryptionError::Crypto(format!("HPKE: failed to encode key: {e}")))
    };
    Ok(PublicJwk::Ec(PublicJwkEc {
        alg: None,
        r#use: None,
        kid: None,
        crv: "P-256".to_string(),
        x: encode(x)?,
        y: Some(encode(y)?),
    }))
}

#[cfg(test)]
mod test {
    use similar_asserts::assert_eq;

    use super::*;

    /// RFC 9180, A.3.1. DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, Base Setup
    mod vector {
        use hex_literal::hex;

        pub const SK_RM: [u8; 32] =
            hex!("f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2");
        pub const PK_RM: [u8; 65] = hex!(
            "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a82"
            "6a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0"
        );
        pub const ENC: [u8; 65] = hex!(
            "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac9"
            "8536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4"
        );
        pub const INFO: [u8; 20] = hex!("4f6465206f6e2061204772656369616e2055726e");
        pub const SHARED_SECRET: [u8; 32] =
            hex!("c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8");
        pub const KEY: [u8; 16] = hex!("868c066ef58aae6dc589b6cfdd18f97e");
        pub const BASE_NONCE: [u8; 12] = hex!("4e0bc5018beba4bf004cca59");
        // encryption with sequence number 0
        pub const AAD: [u8; 7] = hex!("436f756e742d30");
        pub const CT: [u8; 45] = hex!(
            "5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f"
            "9076ac232e3ab2523f39513434"
        );
        pub const PT: [u8; 29] = hex!("4265617574792069732074727574682c20747275746820626561757479");
    }

    struct P256Handle(SecretSlice<u8>);

    #[async_trait::async_trait]
    impl PrivateKeyAgreementHandle for P256Handle {
        async fn shared_secret(
            &self,
            remote_jwk: &PublicJwk,
        ) -> Result<SecretSlice<u8>, EncryptionError> {
            ECDSASigner::shared_secret_p256(&self.0, remote_jwk)
        }
    }

    fn recipient() -> P256Handle {
        P256Handle(vector::SK_RM.to_vec().into())
    }

    #[tokio::test]
    async fn test_decap_rfc9180_vector() {
        let shared_secret = decap(&recipient(), &vector::PK_RM, &vector::ENC)
            .await
            .unwrap();
        assert_eq!(shared_secret.expose_secret(), vector::SHARED_SECRET);
    }

    #[test]
    fn test_key_schedule_rfc9180_vector() {
        let (key, base_nonce) =
            key_schedule_base(&vector::SHARED_SECRET.to_vec().into(), &vector::INFO).unwrap();
        assert_eq!(key.expose_secret(), vector::KEY);
        assert_eq!(base_nonce, vector::BASE_NONCE);
    }

    #[tokio::test]
    async fn test_open_rfc9180_vector() {
        let plaintext = open_p256_sha256_aes128gcm(
            &recipient(),
            &vector::PK_RM,
            &vector::ENC,
            &vector::INFO,
            &vector::AAD,
            &vector::CT,
        )
        .await
        .unwrap();
        assert_eq!(plaintext, vector::PT);
    }

    #[tokio::test]
    async fn test_open_compressed_recipient_key() {
        let compressed = ECDSASigner::parse_public_key(&vector::PK_RM, true).unwrap();
        assert_eq!(compressed.len(), 33);

        let plaintext = open_p256_sha256_aes128gcm(
            &recipient(),
            &compressed,
            &vector::ENC,
            &vector::INFO,
            &vector::AAD,
            &vector::CT,
        )
        .await
        .unwrap();
        assert_eq!(plaintext, vector::PT);
    }

    #[tokio::test]
    async fn test_open_fails_on_wrong_info() {
        let result = open_p256_sha256_aes128gcm(
            &recipient(),
            &vector::PK_RM,
            &vector::ENC,
            b"other info",
            &vector::AAD,
            &vector::CT,
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_open_fails_on_wrong_aad() {
        let result = open_p256_sha256_aes128gcm(
            &recipient(),
            &vector::PK_RM,
            &vector::ENC,
            &vector::INFO,
            b"Count-1",
            &vector::CT,
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_open_fails_on_tampered_ciphertext() {
        let mut ciphertext = vector::CT;
        ciphertext[0] ^= 0x01;

        let result = open_p256_sha256_aes128gcm(
            &recipient(),
            &vector::PK_RM,
            &vector::ENC,
            &vector::INFO,
            &vector::AAD,
            &ciphertext,
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_open_fails_on_wrong_recipient_key() {
        // recipient key not matching the private key changes kem_context
        let result = open_p256_sha256_aes128gcm(
            &recipient(),
            &vector::ENC,
            &vector::ENC,
            &vector::INFO,
            &vector::AAD,
            &vector::CT,
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_open_rejects_compressed_encapsulated_key() {
        let compressed = ECDSASigner::parse_public_key(&vector::ENC, true).unwrap();

        let result = open_p256_sha256_aes128gcm(
            &recipient(),
            &vector::PK_RM,
            &compressed,
            &vector::INFO,
            &vector::AAD,
            &vector::CT,
        )
        .await;
        assert!(
            matches!(result, Err(EncryptionError::Crypto(msg)) if msg.contains("invalid encapsulated key length"))
        );
    }

    #[tokio::test]
    async fn test_open_rejects_invalid_encapsulated_key() {
        // x-coordinate of ENC, but y-coordinate of PK_RM - not on the curve
        let mut invalid = vector::ENC;
        invalid[33..].copy_from_slice(&vector::PK_RM[33..]);

        let result = open_p256_sha256_aes128gcm(
            &recipient(),
            &vector::PK_RM,
            &invalid,
            &vector::INFO,
            &vector::AAD,
            &vector::CT,
        )
        .await;
        assert!(
            matches!(result, Err(EncryptionError::Crypto(msg)) if msg.contains("invalid encapsulated key"))
        );
    }
}
