// todo: remove this once the key agreement things are being used somewhere
#![allow(dead_code)]

use std::collections::HashMap;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit};
use anyhow::{anyhow, bail, Context};
use coset::iana::{self, EnumI64};
use coset::{AsCborValue, CoseKey, CoseKeyBuilder, KeyType, Label};
use hkdf::Hkdf;
use one_providers::exchange_protocol::openid4vc::ExchangeProtocolError;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize, Serializer};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroize;

use super::device_engagement::DeviceEngagement;
use super::session::SessionTranscript;
use crate::provider::credential_formatter::mdoc_formatter::mdoc::EmbeddedCbor;

#[derive(Debug, Clone)]
pub struct ServerInfo {
    pub task_id: Uuid,
    pub mac: Option<String>,
    pub service_id: Uuid,
}

#[derive(Debug, Clone)]
pub enum Chunk {
    Next(Vec<u8>),
    Last(Vec<u8>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRequest {
    pub version: String,
    pub doc_request: Vec<DocRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DocRequest {
    items_request: EmbeddedCbor<ItemsRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemsRequest {
    doc_type: String,
    name_spaces: HashMap<NameSpace, DataElements>,
}

pub type NameSpace = String;
pub type DataElements = HashMap<DataElementIdentifier, IntentToRetain>;
pub type DataElementIdentifier = String;
pub type IntentToRetain = bool;

impl TryFrom<Vec<u8>> for Chunk {
    type Error = anyhow::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        match value.as_slice() {
            [0, ..] => Ok(Self::Last(value[1..].to_vec())),
            [1, ..] => Ok(Self::Next(value[1..].to_vec())),
            _ => Err(anyhow!("invalid data format")),
        }
    }
}

// EDeviceKey = COSE_Key
#[derive(Clone, Debug, PartialEq)]
pub struct EDeviceKey(pub x25519_dalek::PublicKey);

impl EDeviceKey {
    pub(crate) fn new(pk: x25519_dalek::PublicKey) -> Self {
        Self(pk)
    }

    fn to_cose_key(&self) -> CoseKey {
        x25519_to_cose_key(self.0.to_bytes().to_vec())
    }

    fn from_cose_key(key: CoseKey) -> anyhow::Result<Self> {
        x25519_from_cose_key(key).map(Self)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

impl Serialize for EDeviceKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_cose_key()
            .to_cbor_value()
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for EDeviceKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = ciborium::Value::deserialize(deserializer)?;
        let key = CoseKey::from_cbor_value(value).map_err(serde::de::Error::custom)?;

        Self::from_cose_key(key).map_err(serde::de::Error::custom)
    }
}

// EReaderKey = COSE_Key
#[derive(Debug, PartialEq, Clone)]
pub struct EReaderKey(x25519_dalek::PublicKey);

impl EReaderKey {
    pub(super) fn new(pk: x25519_dalek::PublicKey) -> Self {
        Self(pk)
    }

    fn to_cose_key(&self) -> CoseKey {
        x25519_to_cose_key(self.0.to_bytes().to_vec())
    }

    fn from_cose_key(key: CoseKey) -> anyhow::Result<Self> {
        x25519_from_cose_key(key).map(Self)
    }
}

impl Serialize for EReaderKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let device_key = self
            .to_cose_key()
            .to_cbor_value()
            .map_err(serde::ser::Error::custom)?;

        device_key.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for EReaderKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = ciborium::Value::deserialize(deserializer)?;
        let key = coset::CoseKey::from_cbor_value(value).map_err(serde::de::Error::custom)?;

        Self::from_cose_key(key).map_err(serde::de::Error::custom)
    }
}

pub struct KeyAgreement<PK> {
    pk: PK,
    sk: EphemeralSecret,
}

impl KeyAgreement<EDeviceKey> {
    pub fn new() -> Self {
        let sk = EphemeralSecret::random_from_rng(OsRng);
        let pk = EDeviceKey::new(PublicKey::from(&sk));

        KeyAgreement { pk, sk }
    }

    pub fn device_key(&self) -> &EDeviceKey {
        &self.pk
    }

    pub fn derive_session_keys(
        self,
        pk: EReaderKey,
        session_transcript_bytes: &[u8],
    ) -> anyhow::Result<(SkDevice, SkReader)> {
        derive_session_keys(self.sk, pk.0, session_transcript_bytes)
    }
}

impl KeyAgreement<EReaderKey> {
    pub(super) fn new() -> Self {
        let sk = EphemeralSecret::random_from_rng(OsRng);
        let pk = EReaderKey::new(PublicKey::from(&sk));

        KeyAgreement { pk, sk }
    }

    pub fn reader_key(&self) -> &EReaderKey {
        &self.pk
    }

    fn derive_session_keys(
        self,
        pk: EDeviceKey,
        session_transcript_bytes: &[u8],
    ) -> anyhow::Result<(SkDevice, SkReader)> {
        derive_session_keys(self.sk, pk.0, session_transcript_bytes)
    }
}

#[derive(Debug, Clone, Zeroize, Serialize, Deserialize)]
pub struct SkDevice {
    secret_key: [u8; 32],
}

impl SkDevice {
    pub fn new(secret_key: [u8; 32]) -> Self {
        Self { secret_key }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        encrypt(self.secret_key, plaintext, Self::iv()).context("SkDevice encryption failed")
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        decrypt(self.secret_key, ciphertext, Self::iv()).context("SkDevice decryption failed")
    }

    // we're not using a counter(it's always 1) since we're going to encrypt/decrypt the message only once
    const fn iv() -> [u8; 12] {
        [0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1]
    }
}

#[derive(Debug, Clone, Zeroize, Serialize, Deserialize)]
pub struct SkReader {
    secret_key: [u8; 32],
}

impl SkReader {
    pub fn new(secret_key: [u8; 32]) -> Self {
        Self { secret_key }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        encrypt(self.secret_key, plaintext, Self::iv()).context("SkReader encryption failed")
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        decrypt(self.secret_key, ciphertext, Self::iv()).context("SkReader decryption failed")
    }

    const fn iv() -> [u8; 12] {
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
    }
}

fn derive_session_keys(
    private_key: x25519_dalek::EphemeralSecret,
    public_key: x25519_dalek::PublicKey,
    session_transcript_bytes: &[u8],
) -> anyhow::Result<(SkDevice, SkReader)> {
    let z_ab = private_key.diffie_hellman(&public_key);
    let salt = Sha256::digest(session_transcript_bytes);
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), z_ab.as_bytes());

    let mut sk_device = [0u8; 32];
    hkdf.expand(b"SKDevice", &mut sk_device)
        .context("Failed to expand session key for SKDevice")?;

    let mut sk_reader = [0u8; 32];
    hkdf.expand(b"SKReader", &mut sk_reader)
        .context("Failed to expand session key for SKReader")?;

    Ok((SkDevice::new(sk_device), SkReader::new(sk_reader)))
}

fn encrypt(secret_key: [u8; 32], plaintext: &[u8], nonce: [u8; 12]) -> anyhow::Result<Vec<u8>> {
    let key = secret_key.into();
    let nonce = nonce.into();

    let ciphertext = Aes256Gcm::new(&key)
        .encrypt(&nonce, plaintext)
        .context("Encryption failed")?;

    Ok(ciphertext)
}

fn decrypt(secret_key: [u8; 32], ciphertext: &[u8], nonce: [u8; 12]) -> anyhow::Result<Vec<u8>> {
    let key = secret_key.into();
    let nonce = nonce.into();

    let plaintext = Aes256Gcm::new(&key)
        .decrypt(&nonce, ciphertext)
        .context("Decryption failed")?;

    Ok(plaintext)
}

fn x25519_to_cose_key(pk: Vec<u8>) -> CoseKey {
    CoseKeyBuilder::new_okp_key()
        .param(
            iana::Ec2KeyParameter::Crv.to_i64(),
            ciborium::Value::from(iana::EllipticCurve::X25519.to_i64()),
        )
        .param(
            iana::Ec2KeyParameter::X.to_i64(),
            ciborium::Value::Bytes(pk),
        )
        .build()
}

fn x25519_from_cose_key(key: CoseKey) -> anyhow::Result<x25519_dalek::PublicKey> {
    if key.kty != KeyType::Assigned(iana::KeyType::OKP) {
        anyhow::bail!(
            "Unsupported key type, expected OKP(x25519) found {:?}",
            key.kty
        );
    }

    if !key.params.iter().any(|(label, value)| {
        label == &Label::Int(iana::Ec2KeyParameter::Crv.to_i64())
            && value
                .as_integer()
                .filter(|v| v == &iana::EllipticCurve::X25519.to_i64().into())
                .is_some()
    }) {
        bail!("Cannot find X25519 parameter in COSE_Key")
    }

    match key.params.into_iter().find_map(|(label, value)| {
        if label != Label::Int(iana::Ec2KeyParameter::X.to_i64()) {
            return None;
        }

        value.into_bytes().ok()
    }) {
        None => bail!("Cannot find X25519 x-coordinate parameter in COSE_Key"),
        Some(public_key) => {
            let public_key: [u8; 32] = public_key.try_into().map_err(|v: Vec<u8>| {
                anyhow!(
                    "Invalid key length for public key, expected 32 got {}",
                    v.len()
                )
            })?;

            Ok(x25519_dalek::PublicKey::from(public_key))
        }
    }
}

pub fn create_session_transcript_bytes(
    device_engagement: &DeviceEngagement,
    e_reader_key: &EReaderKey,
) -> Result<Vec<u8>, ExchangeProtocolError> {
    let session_transcript = SessionTranscript {
        device_engagement_bytes: EmbeddedCbor(device_engagement)
            .to_vec()
            .context("device_engagement serialization error")
            .map_err(ExchangeProtocolError::Other)?,
        e_reader_key_bytes: EmbeddedCbor(e_reader_key)
            .to_vec()
            .context("device_engagement serialization error")
            .map_err(ExchangeProtocolError::Other)?,
    };

    to_cbor(&session_transcript)
}

fn to_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>, ExchangeProtocolError> {
    let mut buff = vec![];
    ciborium::into_writer(value, &mut buff)
        .context("serialization error")
        .map_err(ExchangeProtocolError::Other)?;
    Ok(buff)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_derive_session_key() {
        let ka_device = KeyAgreement::<EDeviceKey>::new();
        let ka_reader = KeyAgreement::<EReaderKey>::new();

        let device_pk = ka_device.device_key().clone();

        let (sk_device1, sk_reader1) = ka_device
            .derive_session_keys(ka_reader.reader_key().clone(), b"session_transcript_bytes")
            .unwrap();

        let (sk_device2, sk_reader2) = ka_reader
            .derive_session_keys(device_pk, b"session_transcript_bytes")
            .unwrap();

        assert_eq!(sk_device1.secret_key, sk_device2.secret_key);
        assert_eq!(sk_reader1.secret_key, sk_reader2.secret_key);
    }

    #[test]
    fn test_encryption_decryption_with_session_keys() {
        let ka_device = KeyAgreement::<EDeviceKey>::new();
        let ka_reader = KeyAgreement::<EReaderKey>::new();

        let device_pk = ka_device.device_key().clone();

        let (sk_device1, sk_reader1) = ka_device
            .derive_session_keys(ka_reader.reader_key().clone(), b"session_transcript_bytes")
            .unwrap();

        let (sk_device2, sk_reader2) = ka_reader
            .derive_session_keys(device_pk, b"session_transcript_bytes")
            .unwrap();

        let payload = b"test1";
        let ciphertext = sk_device1.encrypt(payload).unwrap();
        assert_eq!(payload, sk_device2.decrypt(&ciphertext).unwrap().as_slice());

        let payload = b"test2";
        let ciphertext = sk_reader1.encrypt(payload).unwrap();
        assert_eq!(payload, sk_reader2.decrypt(&ciphertext).unwrap().as_slice())
    }

    #[test]
    fn test_device_key_serialization() {
        let ka = KeyAgreement::<EDeviceKey>::new();

        let device_key = ka.device_key().clone();

        let mut writer = vec![];
        ciborium::into_writer(&device_key, &mut writer).unwrap();

        let key: EDeviceKey = ciborium::from_reader(&writer[..]).unwrap();

        assert_eq!(device_key, key);
    }

    #[test]
    fn test_reader_key_serialization() {
        let ka = KeyAgreement::<EReaderKey>::new();

        let device_key = ka.reader_key().clone();

        let mut writer = vec![];
        ciborium::into_writer(&device_key, &mut writer).unwrap();

        let key: EReaderKey = ciborium::from_reader(&writer[..]).unwrap();

        assert_eq!(device_key, key);
    }
}
