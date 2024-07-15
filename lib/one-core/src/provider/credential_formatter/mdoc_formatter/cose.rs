use coset::{CoseSign1, Header, ProtectedHeader, SignatureContext};
use one_providers::{crypto::SignerError, key_storage::provider::SignatureProvider};

/// Adaptation of the [`coset::CoseSign1Builder`] to allow signing with async signer
#[derive(Debug, Default)]
pub struct CoseSign1Builder(CoseSign1);

impl CoseSign1Builder {
    #[must_use]
    pub fn new() -> Self {
        Self(CoseSign1::default())
    }

    #[must_use]
    pub fn build(self) -> CoseSign1 {
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
    pub async fn try_create_signature_with_provider(
        self,
        external_aad: &[u8],
        signer: &dyn SignatureProvider,
    ) -> Result<Self, SignerError> {
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

    pub async fn try_create_detached_signature_with_provider(
        self,
        payload: &[u8],
        external_aad: &[u8],
        signer: &dyn SignatureProvider,
    ) -> Result<Self, SignerError> {
        if self.0.payload.is_some() {
            return Err(SignerError::CouldNotSign(
                "For detached mode payload should not be set".to_string(),
            ));
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
