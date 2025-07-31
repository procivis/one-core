use std::sync::Arc;

use one_crypto::SignerError;
use one_crypto::encryption::EncryptionError;
use one_crypto::jwe::PrivateKeyAgreementHandle;
use one_crypto::signer::bbs::parse_bbs_input;
use secrecy::SecretString;
use thiserror::Error;

use crate::model::key::PublicKeyJwk;

#[derive(Clone)]
pub enum KeyHandle {
    SignatureOnly(SignatureKeyHandle),
    SignatureAndKeyAgreement {
        signature: SignatureKeyHandle,
        key_agreement: KeyAgreementHandle,
    },
    KeyAgreementOnly(KeyAgreementHandle),
    MultiMessageSignature(MultiMessageSignatureKeyHandle),
}

#[derive(Debug, Error)]
pub enum KeyHandleError {
    #[error("Missing private key")]
    MissingPrivateKey,

    #[error("Encoding JWK: `{0}`")]
    EncodingJwk(String),

    #[error("Encoding multibase: `{0}`")]
    EncodingMultibase(String),

    #[error("Encoding private JWK: `{0}`")]
    EncodingPrivateJwk(String),

    #[error("Encryption error: `{0}`")]
    Encryption(EncryptionError),

    #[error("Signer error: `{0}`")]
    Signer(SignerError),
}

impl KeyHandle {
    /// ECDSA, EDDSA, dillithium
    pub fn signature(&self) -> Option<&SignatureKeyHandle> {
        match &self {
            Self::SignatureOnly(signature) | Self::SignatureAndKeyAgreement { signature, .. } => {
                Some(signature)
            }
            Self::KeyAgreementOnly(_) | Self::MultiMessageSignature(_) => None,
        }
    }

    /// ECDH
    pub fn key_agreement(&self) -> Option<&KeyAgreementHandle> {
        match &self {
            Self::SignatureOnly(_) | Self::MultiMessageSignature(_) => None,
            Self::SignatureAndKeyAgreement { key_agreement, .. }
            | Self::KeyAgreementOnly(key_agreement) => Some(key_agreement),
        }
    }

    /// BBS+
    pub fn multi_message_signature(&self) -> Option<&MultiMessageSignatureKeyHandle> {
        match &self {
            Self::SignatureOnly(_)
            | Self::SignatureAndKeyAgreement { .. }
            | Self::KeyAgreementOnly(_) => None,
            Self::MultiMessageSignature(multi_message_signature) => Some(multi_message_signature),
        }
    }

    /// helper functions
    pub fn public_key_as_jwk(&self) -> Result<PublicKeyJwk, KeyHandleError> {
        match &self {
            Self::SignatureOnly(value) => value.public().as_jwk(),
            Self::SignatureAndKeyAgreement { signature, .. } => signature.public().as_jwk(),
            Self::KeyAgreementOnly(key_agreement) => key_agreement.public().as_jwk(),
            Self::MultiMessageSignature(multi_message_signature) => {
                multi_message_signature.public().as_jwk()
            }
        }
    }

    pub fn public_key_as_multibase(&self) -> Result<String, KeyHandleError> {
        match &self {
            Self::SignatureOnly(value) => value.public().as_multibase(),
            Self::SignatureAndKeyAgreement { signature, .. } => signature.public().as_multibase(),
            Self::KeyAgreementOnly(key_agreement) => key_agreement.public().as_multibase(),
            Self::MultiMessageSignature(multi_message_signature) => {
                multi_message_signature.public().as_multibase()
            }
        }
    }

    pub fn verify(&self, message: &[u8], signature_bytes: &[u8]) -> Result<(), SignerError> {
        match &self {
            Self::SignatureOnly(value) => value.public().verify(message, signature_bytes),
            Self::SignatureAndKeyAgreement { signature, .. } => {
                signature.public().verify(message, signature_bytes)
            }
            Self::MultiMessageSignature(value) => {
                let input = parse_bbs_input(message);
                value
                    .public()
                    .verify_signature(input.header, input.messages, signature_bytes)
            }
            Self::KeyAgreementOnly(_) => {
                Err(SignerError::CouldNotVerify("Not supported".to_string()))
            }
        }
    }

    pub async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignerError> {
        match &self {
            Self::SignatureOnly(value) => {
                value
                    .private()
                    .ok_or(SignerError::MissingKey)?
                    .sign(message)
                    .await
            }
            Self::SignatureAndKeyAgreement { signature, .. } => {
                signature
                    .private()
                    .ok_or(SignerError::MissingKey)?
                    .sign(message)
                    .await
            }
            Self::MultiMessageSignature(value) => {
                let input = parse_bbs_input(message);
                value
                    .private()
                    .ok_or(SignerError::MissingKey)?
                    .sign(input.header, input.messages)
            }
            Self::KeyAgreementOnly(_) => {
                Err(SignerError::CouldNotSign("Not supported".to_string()))
            }
        }
    }

    pub fn public_key_as_raw(&self) -> Vec<u8> {
        match &self {
            Self::SignatureOnly(value) => value.public().as_raw(),
            Self::SignatureAndKeyAgreement { signature, .. } => signature.public().as_raw(),
            Self::KeyAgreementOnly(key_agreement) => key_agreement.public().as_raw(),
            Self::MultiMessageSignature(value) => value.public().as_raw(),
        }
    }
}

#[derive(Clone)]
pub enum SignatureKeyHandle {
    WithPrivateKey {
        private: Arc<dyn SignaturePrivateKeyHandle>,
        public: Arc<dyn SignaturePublicKeyHandle>,
    },
    PublicKeyOnly(Arc<dyn SignaturePublicKeyHandle>),
}

impl SignatureKeyHandle {
    /// private key operations
    pub fn private(&self) -> Option<&Arc<dyn SignaturePrivateKeyHandle>> {
        match &self {
            Self::WithPrivateKey { private, .. } => Some(private),
            Self::PublicKeyOnly(_) => None,
        }
    }

    /// public key operations
    pub fn public(&self) -> &Arc<dyn SignaturePublicKeyHandle> {
        match &self {
            Self::WithPrivateKey { public, .. } => public,
            Self::PublicKeyOnly(public) => public,
        }
    }
}

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub trait SignaturePublicKeyHandle: Send + Sync {
    fn as_jwk(&self) -> Result<PublicKeyJwk, KeyHandleError>;
    fn as_multibase(&self) -> Result<String, KeyHandleError>;
    fn as_raw(&self) -> Vec<u8>;

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), SignerError>;
}

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait SignaturePrivateKeyHandle: Send + Sync {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignerError>;
}

#[derive(Clone)]
pub enum KeyAgreementHandle {
    WithPrivateKey {
        private: Arc<dyn PrivateKeyAgreementHandle>,
        public: Arc<dyn PublicKeyAgreementHandle>,
    },
    PublicKeyOnly(Arc<dyn PublicKeyAgreementHandle>),
}

impl KeyAgreementHandle {
    /// private key operations
    pub fn private(&self) -> Option<&Arc<dyn PrivateKeyAgreementHandle>> {
        match &self {
            Self::WithPrivateKey { private, .. } => Some(private),
            Self::PublicKeyOnly(_) => None,
        }
    }

    /// public key operations
    pub fn public(&self) -> &Arc<dyn PublicKeyAgreementHandle> {
        match &self {
            Self::WithPrivateKey { public, .. } => public,
            Self::PublicKeyOnly(public) => public,
        }
    }
}

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub trait PublicKeyAgreementHandle: Send + Sync {
    fn as_jwk(&self) -> Result<PublicKeyJwk, KeyHandleError>;
    fn as_multibase(&self) -> Result<String, KeyHandleError>;
    fn as_raw(&self) -> Vec<u8>;
}

#[derive(Clone)]
pub enum MultiMessageSignatureKeyHandle {
    WithPrivateKey {
        private: Arc<dyn MultiMessageSignaturePrivateKeyHandle>,
        public: Arc<dyn MultiMessageSignaturePublicKeyHandle>,
    },
    PublicKeyOnly(Arc<dyn MultiMessageSignaturePublicKeyHandle>),
}

impl MultiMessageSignatureKeyHandle {
    /// private key operations
    pub fn private(&self) -> Option<&Arc<dyn MultiMessageSignaturePrivateKeyHandle>> {
        match &self {
            Self::WithPrivateKey { private, .. } => Some(private),
            Self::PublicKeyOnly(_) => None,
        }
    }

    /// public key operations
    pub fn public(&self) -> &Arc<dyn MultiMessageSignaturePublicKeyHandle> {
        match &self {
            Self::WithPrivateKey { public, .. } => public,
            Self::PublicKeyOnly(public) => public,
        }
    }
}

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub trait MultiMessageSignaturePublicKeyHandle: Send + Sync {
    fn as_jwk(&self) -> Result<PublicKeyJwk, KeyHandleError>;
    fn as_multibase(&self) -> Result<String, KeyHandleError>;
    fn as_raw(&self) -> Vec<u8>;

    fn verify_signature(
        &self,
        header: Vec<u8>,
        messages: Vec<Vec<u8>>,
        signature: &[u8],
    ) -> Result<(), SignerError>;

    fn derive_proof(
        &self,
        header: Vec<u8>,
        messages: Vec<(Vec<u8>, bool)>,
        signature: Vec<u8>,
    ) -> Result<Vec<u8>, SignerError>;

    fn verify_proof(
        &self,
        header: Vec<u8>,
        messages: Vec<(usize, Vec<u8>)>,
        presentation_header: Option<Vec<u8>>,
        proof: &[u8],
    ) -> Result<(), SignerError>;
}

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub trait MultiMessageSignaturePrivateKeyHandle: Send + Sync {
    fn sign(&self, header: Vec<u8>, messages: Vec<Vec<u8>>) -> Result<Vec<u8>, SignerError>;
    fn as_jwk(&self) -> Result<SecretString, KeyHandleError>;
}
