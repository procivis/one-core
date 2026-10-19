use std::collections::HashMap;
use std::sync::Arc;

use aes_gcm::aead::Aead;
use aes_gcm::aead::consts::U32;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{Aes256Gcm, KeyInit};
use coset::{AsCborValue, CoseKey};
use hkdf::Hkdf;
use one_crypto::jwe::PrivateKeyAgreementHandle;
use secrecy::{ExposeSecret, ExposeSecretMut, SecretSlice};
use serde::{Deserialize, Serialize, Serializer};
use serde_with::skip_serializing_none;
use sha2::{Digest, Sha256};
use shared_types::ProofId;

use super::device_engagement::DeviceEngagement;
use crate::error::ContextWithErrorCode;
use crate::mapper::secret_slice;
use crate::model::history::HistoryErrorMetadata;
use crate::model::proof::{ProofStateEnum, UpdateProofRequest};
use crate::proto::cose::CoseSign1;
use crate::provider::credential_formatter::mdoc_formatter::util::{EmbeddedCbor, MDLVersion};
use crate::provider::key_algorithm::KeyAlgorithm;
use crate::provider::key_algorithm::error::KeyAlgorithmError;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::presentation_formatter::mso_mdoc::session_transcript::{
    Handover, SessionTranscript,
};
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::repository::proof_repository::ProofRepository;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DeviceRequest {
    pub version: MDLVersion<1, 0>,
    pub doc_requests: Vec<DocRequest>,
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DocRequest {
    pub items_request: EmbeddedCbor<ItemsRequest>,
    pub reader_auth: Option<CoseSign1>,
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ItemsRequest {
    pub doc_type: String,
    pub name_spaces: HashMap<NameSpace, DataElements>,
    pub request_info: Option<HashMap<String, ciborium::Value>>,
}

pub(crate) type NameSpace = String;
pub(crate) type DataElements = HashMap<DataElementIdentifier, IntentToRetain>;
pub(crate) type DataElementIdentifier = String;
pub(crate) type IntentToRetain = bool;

/// EDeviceKey, EReaderKey = COSE_Key
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct EphemeralSessionKey(CoseKey);

impl EphemeralSessionKey {
    pub(crate) fn get_algorithm(
        &self,
        key_algorithm_provider: &dyn KeyAlgorithmProvider,
    ) -> Result<Arc<dyn KeyAlgorithm>, VerificationProtocolError> {
        let parsed_key = key_algorithm_provider
            .parse_cose(&self.0)
            .error_while("parsing COSE key")?;
        Ok(key_algorithm_provider.key_algorithm_from_type(parsed_key.algorithm_type)?)
    }

    /// used in DC-API flow
    pub(crate) fn to_p256_sec1(&self) -> Result<Vec<u8>, VerificationProtocolError> {
        if self.0.kty != coset::KeyType::Assigned(coset::iana::KeyType::EC2) {
            return Err(VerificationProtocolError::EncryptionError(format!(
                "Invalid key type: {:?}",
                self.0.kty
            )));
        }

        let param = |p: coset::iana::Ec2KeyParameter| {
            self.0
                .params
                .iter()
                .find(|(label, _)| *label == coset::Label::Int(p as i64))
                .map(|(_, v)| v)
        };

        match param(coset::iana::Ec2KeyParameter::Crv) {
            Some(ciborium::Value::Integer(i))
                if i128::from(*i) == coset::iana::EllipticCurve::P_256 as i128 => {}
            other => {
                return Err(VerificationProtocolError::EncryptionError(format!(
                    "Invalid crv: {other:?}"
                )));
            }
        }

        let x = match param(coset::iana::Ec2KeyParameter::X) {
            Some(ciborium::Value::Bytes(b)) if b.len() == 32 => b,
            other => {
                return Err(VerificationProtocolError::EncryptionError(format!(
                    "Invalid X: {other:?}"
                )));
            }
        };

        let y = match param(coset::iana::Ec2KeyParameter::Y) {
            Some(ciborium::Value::Bytes(b)) if b.len() == 32 => b,
            other => {
                return Err(VerificationProtocolError::EncryptionError(format!(
                    "Invalid Y: {other:?}"
                )));
            }
        };

        let mut sec1 = Vec::with_capacity(65);
        sec1.push(0x04);
        sec1.extend_from_slice(x);
        sec1.extend_from_slice(y);

        Ok(sec1)
    }
}

impl Serialize for EphemeralSessionKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0
            .to_owned()
            .to_cbor_value()
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for EphemeralSessionKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = ciborium::Value::deserialize(deserializer)?;
        let key = CoseKey::from_cbor_value(value).map_err(serde::de::Error::custom)?;

        Ok(Self(key))
    }
}

/// represents private key holding EDeviceKey or EReaderKey
pub(crate) struct KeyAgreementKey {
    public_key: EphemeralSessionKey,
    private_key: Arc<dyn PrivateKeyAgreementHandle>,
}

impl KeyAgreementKey {
    pub(crate) fn generate(algorithm: &dyn KeyAlgorithm) -> Result<Self, KeyAlgorithmError> {
        let key_pair = algorithm.generate_key()?;
        let key_agreement = key_pair.key.key_agreement().ok_or_else(move || {
            KeyAlgorithmError::NotSupported(format!(
                "Key agreement: {}",
                algorithm.algorithm_type()
            ))
        })?;
        let private = key_agreement
            .private()
            .ok_or(KeyAlgorithmError::InvalidKeyType)?;

        let cose_key = key_agreement
            .public()
            .as_cose()
            .error_while("creating COSE key")?;

        Ok(Self {
            public_key: EphemeralSessionKey(cose_key),
            private_key: private.to_owned(),
        })
    }

    /// expose the public key part
    pub(crate) fn ephemeral_key(&self) -> &EphemeralSessionKey {
        &self.public_key
    }

    pub(super) async fn derive_session_keys(
        &self,
        remote_key: &EphemeralSessionKey,
        session_transcript_bytes: &[u8],
        key_algorithm_provider: &dyn KeyAlgorithmProvider,
    ) -> Result<(SkDevice, SkReader), VerificationProtocolError> {
        let remote_key = key_algorithm_provider
            .parse_cose(&remote_key.0)
            .error_while("parsing COSE key")?;
        let remote_key = remote_key
            .key
            .key_agreement()
            .ok_or(KeyAlgorithmError::InvalidKeyType)
            .error_while("deriving session keys")?;

        let remote_jwk = remote_key
            .public()
            .as_jwk()
            .error_while("converting to JWK")?;
        let z_ab = self
            .private_key
            .shared_secret(&remote_jwk)
            .await
            .error_while("calculating shared secret")?;

        let salt = Sha256::digest(session_transcript_bytes);
        let hkdf = Hkdf::<Sha256>::new(Some(&salt), z_ab.expose_secret());

        let mut sk_device = SecretSlice::from(vec![0u8; 32]);
        hkdf.expand(b"SKDevice", sk_device.expose_secret_mut())
            .map_err(|e| {
                VerificationProtocolError::Failed(format!(
                    "Failed to expand session key for SKDevice: {e}"
                ))
            })?;

        let mut sk_reader = SecretSlice::from(vec![0u8; 32]);
        hkdf.expand(b"SKReader", sk_reader.expose_secret_mut())
            .map_err(|e| {
                VerificationProtocolError::Failed(format!(
                    "Failed to expand session key for SKReader: {e}"
                ))
            })?;

        Ok((SkDevice::new(sk_device), SkReader::new(sk_reader)))
    }
}

/// ISO 18013-5, 9.1.1.5
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SkDevice {
    #[serde(with = "secret_slice")]
    secret_key: SecretSlice<u8>,
}

impl SkDevice {
    pub(super) fn new(secret_key: SecretSlice<u8>) -> Self {
        Self { secret_key }
    }

    pub(super) fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, VerificationProtocolError> {
        encrypt(&self.secret_key, plaintext, Self::iv())
    }

    pub(super) fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, VerificationProtocolError> {
        decrypt(&self.secret_key, ciphertext, Self::iv())
    }

    // we're not using a counter(it's always 1) since we're going to encrypt/decrypt the message only once
    const fn iv() -> [u8; 12] {
        [0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1]
    }
}

/// ISO 18013-5, 9.1.1.5
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SkReader {
    #[serde(with = "secret_slice")]
    secret_key: SecretSlice<u8>,
}

impl SkReader {
    pub(super) fn new(secret_key: SecretSlice<u8>) -> Self {
        Self { secret_key }
    }

    pub(super) fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, VerificationProtocolError> {
        encrypt(&self.secret_key, plaintext, Self::iv())
    }

    pub(super) fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, VerificationProtocolError> {
        decrypt(&self.secret_key, ciphertext, Self::iv())
    }

    const fn iv() -> [u8; 12] {
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
    }
}

fn encrypt(
    secret_key: &SecretSlice<u8>,
    plaintext: &[u8],
    nonce: [u8; 12],
) -> Result<Vec<u8>, VerificationProtocolError> {
    let key = GenericArray::<u8, U32>::from_slice(secret_key.expose_secret());
    let nonce = nonce.into();

    let ciphertext = Aes256Gcm::new(key)
        .encrypt(&nonce, plaintext)
        .map_err(|e| {
            VerificationProtocolError::EncryptionError(format!("Encryption failed: {e}"))
        })?;

    Ok(ciphertext)
}

fn decrypt(
    secret_key: &SecretSlice<u8>,
    ciphertext: &[u8],
    nonce: [u8; 12],
) -> Result<Vec<u8>, VerificationProtocolError> {
    let key = GenericArray::<u8, U32>::from_slice(secret_key.expose_secret());
    let nonce = nonce.into();

    let plaintext = Aes256Gcm::new(key)
        .decrypt(&nonce, ciphertext)
        .map_err(|e| {
            VerificationProtocolError::EncryptionError(format!("Decryption failed: {e}"))
        })?;

    Ok(plaintext)
}

pub(super) fn create_session_transcript_bytes(
    device_engagement_bytes: EmbeddedCbor<DeviceEngagement>,
    e_reader_key_bytes: EmbeddedCbor<EphemeralSessionKey>,
    handover: Handover,
) -> Result<EmbeddedCbor<SessionTranscript>, VerificationProtocolError> {
    let session_transcript = SessionTranscript {
        device_engagement_bytes: Some(device_engagement_bytes),
        e_reader_key_bytes: Some(e_reader_key_bytes),
        handover,
    };

    Ok(EmbeddedCbor::new(session_transcript)?)
}

pub(crate) fn to_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>, VerificationProtocolError> {
    let mut buff = vec![];
    ciborium::into_writer(value, &mut buff)?;
    Ok(buff)
}

pub(super) async fn set_proof_to_error(
    proof_repository: &dyn ProofRepository,
    proof_id: &ProofId,
    error_metadata: HistoryErrorMetadata,
) {
    tracing::debug!("set_proof_error: {proof_id}, metadata: {error_metadata:?}");
    if let Err(err) = proof_repository
        .update_proof(
            proof_id,
            UpdateProofRequest {
                state: Some(ProofStateEnum::Error),
                ..Default::default()
            },
            Some(error_metadata),
        )
        .await
    {
        tracing::warn!("failed to set proof to error: {err}");
    }
}

#[cfg(test)]
mod test {
    use similar_asserts::assert_eq;

    use super::*;
    use crate::config::core_config::KeyAlgorithmType;
    use crate::provider::key_algorithm::ecdsa::Ecdsa;
    use crate::provider::key_algorithm::provider::{MockKeyAlgorithmProvider, ParsedKey};

    fn get_key_algorithm_provider() -> Arc<dyn KeyAlgorithmProvider> {
        let mut provider = MockKeyAlgorithmProvider::new();
        provider.expect_parse_cose().returning(|cose_key| {
            Ok(ParsedKey {
                key: Ecdsa.parse_cose(cose_key).unwrap(),
                algorithm_type: KeyAlgorithmType::Ecdsa,
            })
        });
        Arc::new(provider)
    }

    #[tokio::test]
    async fn test_derive_session_key() {
        let ka_device = KeyAgreementKey::generate(&Ecdsa).unwrap();
        let ka_reader = KeyAgreementKey::generate(&Ecdsa).unwrap();
        let session_transcript_bytes = b"session_transcript_bytes";

        let (sk_device1, sk_reader1) = ka_device
            .derive_session_keys(
                ka_reader.ephemeral_key(),
                session_transcript_bytes,
                get_key_algorithm_provider().as_ref(),
            )
            .await
            .unwrap();

        let (sk_device2, sk_reader2) = ka_reader
            .derive_session_keys(
                ka_device.ephemeral_key(),
                session_transcript_bytes,
                get_key_algorithm_provider().as_ref(),
            )
            .await
            .unwrap();

        assert_eq!(
            sk_device1.secret_key.expose_secret(),
            sk_device2.secret_key.expose_secret()
        );
        assert_eq!(
            sk_reader1.secret_key.expose_secret(),
            sk_reader2.secret_key.expose_secret()
        );
    }

    #[tokio::test]
    async fn test_encryption_decryption_with_session_keys() {
        let ka_device = KeyAgreementKey::generate(&Ecdsa).unwrap();
        let ka_reader = KeyAgreementKey::generate(&Ecdsa).unwrap();
        let session_transcript_bytes = b"session_transcript_bytes";

        let (sk_device1, sk_reader1) = ka_device
            .derive_session_keys(
                ka_reader.ephemeral_key(),
                session_transcript_bytes,
                get_key_algorithm_provider().as_ref(),
            )
            .await
            .unwrap();

        let (sk_device2, sk_reader2) = ka_reader
            .derive_session_keys(
                ka_device.ephemeral_key(),
                session_transcript_bytes,
                get_key_algorithm_provider().as_ref(),
            )
            .await
            .unwrap();

        let payload = b"test1";
        let ciphertext = sk_device1.encrypt(payload).unwrap();
        assert_eq!(payload, sk_device2.decrypt(&ciphertext).unwrap().as_slice());

        let payload = b"test2";
        let ciphertext = sk_reader1.encrypt(payload).unwrap();
        assert_eq!(payload, sk_reader2.decrypt(&ciphertext).unwrap().as_slice())
    }

    #[test]
    fn test_ephemeral_key_serialization() {
        let ka = KeyAgreementKey::generate(&Ecdsa).unwrap();

        let device_key = ka.ephemeral_key().clone();

        let mut writer = vec![];
        ciborium::into_writer(&device_key, &mut writer).unwrap();

        let key: EphemeralSessionKey = ciborium::from_reader(&writer[..]).unwrap();

        assert_eq!(device_key, key);
    }
}
