use one_crypto::signer::rsa::RsaSigner;
use one_crypto::{Signer, SignerError};
use secrecy::SecretSlice;

use crate::config::core_config::KeyAlgorithmType;
use crate::error::ErrorCodeMixinExt;
use crate::model::key::KeyModelError;
use crate::provider::credential_formatter::model::SignatureProvider;
use crate::provider::key_algorithm::error::KeyAlgorithmError;

/// [`SignatureProvider`] implementing JOSE `RS256` ([RFC 7518 §3.3](https://www.rfc-editor.org/rfc/rfc7518#section-3.3))
pub(crate) struct RS256Signer {
    private_key: SecretSlice<u8>,
    public_key: Vec<u8>,
}

impl RS256Signer {
    pub(crate) fn from_pem(private_key: &str) -> Result<Self, SignerError> {
        let pem = pem::parse(private_key)
            .map_err(|err| SignerError::CouldNotExtractPrivateKey(err.to_string()))?;
        if pem.tag() != "PRIVATE KEY" {
            return Err(SignerError::CouldNotExtractPrivateKey(format!(
                "expected a PKCS#8 private key, found `{}`",
                pem.tag()
            )));
        }
        let private_key: SecretSlice<u8> = pem.into_contents().into();
        Ok(Self {
            public_key: RsaSigner::public_key(&private_key)?,
            private_key,
        })
    }
}

#[async_trait::async_trait]
impl SignatureProvider for RS256Signer {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeyAlgorithmError> {
        Ok(RsaSigner.sign(message, &self.public_key, &self.private_key)?)
    }

    fn get_key_id(&self) -> Option<String> {
        None
    }

    fn get_key_algorithm(&self) -> Result<KeyAlgorithmType, KeyAlgorithmError> {
        Err(
            KeyModelError::UnsupportedKeyAlgorithmType("RS256".to_string())
                .error_while("getting key algorithm type")
                .into(),
        )
    }

    fn jose_alg(&self) -> Result<String, KeyAlgorithmError> {
        Ok("RS256".to_string())
    }

    fn get_public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }
}
