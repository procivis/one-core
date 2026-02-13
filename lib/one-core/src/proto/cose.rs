use coset::{AsCborValue, CoseSign1 as CosetCoseSign1, Header, ProtectedHeader, SignatureContext};
use one_crypto::SignerError;
use serde::{Deserialize, Serialize, Serializer, de, ser};

use crate::provider::credential_formatter::model::SignatureProvider;
use crate::provider::key_algorithm::error::KeyAlgorithmError;

/// Adaptation of the [`coset::CoseSign1Builder`] to allow signing with async signer
#[derive(Debug, Default)]
pub struct CoseSign1Builder(CosetCoseSign1);

impl CoseSign1Builder {
    #[must_use]
    pub fn new() -> Self {
        Self(CosetCoseSign1::default())
    }

    #[must_use]
    pub fn build(self) -> CosetCoseSign1 {
        self.0
    }

    #[must_use]
    pub fn protected(mut self, protected: ProtectedHeader) -> Self {
        self.0.protected = protected;

        self
    }

    #[must_use]
    pub fn unprotected(mut self, unprotected: Header) -> Self {
        self.0.unprotected = unprotected;

        self
    }

    #[must_use]
    pub fn payload(mut self, payload: Vec<u8>) -> Self {
        self.0.payload = Some(payload);

        self
    }

    #[must_use]
    pub fn signature(mut self, signature: Vec<u8>) -> Self {
        self.0.signature = signature;

        self
    }

    /// Any protected header values should be set before using this method.
    pub(crate) async fn try_create_signature_with_provider(
        self,
        external_aad: &[u8],
        signer: &dyn SignatureProvider,
    ) -> Result<Self, KeyAlgorithmError> {
        let sig_data = coset::sig_structure_data(
            SignatureContext::CoseSign1,
            self.0.protected.clone(),
            None,
            external_aad,
            self.0.payload.as_ref().unwrap_or(&vec![]),
        );
        let sig_data = signer.sign(&sig_data).await?;

        Ok(self.signature(sig_data))
    }

    pub(crate) async fn try_create_detached_signature_with_provider(
        self,
        payload: &[u8],
        external_aad: &[u8],
        signer: &dyn SignatureProvider,
    ) -> Result<Self, KeyAlgorithmError> {
        if self.0.payload.is_some() {
            return Err(SignerError::CouldNotSign(
                "For detached mode payload should not be set".to_string(),
            )
            .into());
        }

        let sig_data = coset::sig_structure_data(
            SignatureContext::CoseSign1,
            self.0.protected.clone(),
            None,
            external_aad,
            payload,
        );
        let sig_data = signer.sign(&sig_data).await?;

        Ok(self.signature(sig_data))
    }
}

#[derive(Debug, PartialEq)]
pub struct CoseSign1(pub coset::CoseSign1);

impl From<coset::CoseSign1> for CoseSign1 {
    fn from(cose_sign1: coset::CoseSign1) -> Self {
        Self(cose_sign1)
    }
}

impl Serialize for CoseSign1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0
            .clone()
            .to_cbor_value()
            .map_err(ser::Error::custom)?
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CoseSign1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let value = ciborium::Value::deserialize(deserializer)?;

        coset::CoseSign1::from_cbor_value(value)
            .map(CoseSign1)
            .map_err(de::Error::custom)
    }
}
