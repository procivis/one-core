//! Implementation of ISO mDL (ISO/IEC 18013-5:2021).
//! https://www.iso.org/standard/69084.html

use std::sync::Arc;

use anyhow::Context;
use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use ouroboros::self_referencing;
use shared_types::{DidId, DidValue};
pub use validator::{DidMdlValidationError, DidMdlValidator};
use x509_parser::certificate::X509Certificate;
use x509_parser::pem::Pem;

use super::common::expect_one_key;
use super::{DidCreateKeys, DidCreated};
use crate::config::core_config::KeyAlgorithmType;
use crate::provider::did_method::DidMethod;
use crate::provider::did_method::common::jwk_context;
use crate::provider::did_method::error::DidMethodError;
use crate::provider::did_method::key_helpers::{DidKeyType, decode_did, generate_document};
use crate::provider::did_method::keys::Keys;
use crate::provider::did_method::model::{
    AmountOfKeys, DidCapabilities, DidDocument, DidVerificationMethod, Operation,
};
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::util::x509::extract_jwk_from_der;

#[cfg(test)]
mod test;
pub(crate) mod validator;

pub struct DidMdl {
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    params: InnerParams,
}

#[derive(Debug, Clone, Default)]
pub struct Params {
    pub keys: Keys,
    pub iaca_certificate: Vec<u8>,
}

#[self_referencing]
struct InnerParams {
    keys: Keys,
    iaca_certificate_der: Vec<u8>,
    #[borrows(iaca_certificate_der)]
    #[not_covariant]
    iaca_certificate: X509Certificate<'this>,
}

impl DidMdl {
    pub fn new(
        params: Params,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    ) -> anyhow::Result<Self> {
        let params = InnerParamsTryBuilder {
            keys: params.keys,
            iaca_certificate_der: params.iaca_certificate,
            iaca_certificate_builder: |iaca_certificate_der| {
                parse_x509_from_der(iaca_certificate_der).context("Invalid IACA Certificate")
            },
        }
        .try_build()?;

        Ok(Self {
            params,
            key_algorithm_provider,
        })
    }
}

#[async_trait::async_trait]
impl DidMethod for DidMdl {
    async fn create(
        &self,
        _id: Option<DidId>,
        params: &Option<serde_json::Value>,
        keys: Option<DidCreateKeys>,
    ) -> Result<DidCreated, DidMethodError> {
        let Some(params) = params.as_ref() else {
            return Err(DidMethodError::CouldNotCreate(
                "Missing params for MDL".to_owned(),
            ));
        };

        let certificate = extract_x509_certificate(params)?;

        let keys = keys.ok_or(DidMethodError::ResolutionError("Missing keys".to_string()))?;
        let selected_key = expect_one_key(&keys)?;

        let pem = parse_pem(certificate)?;
        let certificate = parse_x509_from_pem(&pem)?;

        self.validate_subject_public_key(&certificate, selected_key)
            .map_err(|err| DidMethodError::CouldNotCreate(err.to_string()))?;

        self.validate_certificate(&certificate)
            .map_err(|err| DidMethodError::CouldNotCreate(err.to_string()))?;

        let did_mdl = Base64UrlSafeNoPadding::encode_to_string(pem.contents)
            .map(|cert| format!("did:mdl:certificate:{cert}"))
            .map_err(|err| {
                DidMethodError::CouldNotCreate(format!("Base64 encoding failed: {err}"))
            })?;

        did_mdl
            .parse()
            .map(|did| DidCreated { did, log: None })
            .context("did parsing error")
            .map_err(|e| DidMethodError::ResolutionError(e.to_string()))
    }

    async fn resolve(&self, did: &DidValue) -> Result<DidDocument, DidMethodError> {
        if let Some(certificate) = did.as_str().strip_prefix("did:mdl:certificate:") {
            let id = format!("{did}#key-0");

            let verification_method = DidVerificationMethod {
                id: id.clone(),
                r#type: "JsonWebKey2020".into(),
                controller: did.to_string(),
                public_key_jwk: extract_jwk_from_der(
                    certificate,
                    self.key_algorithm_provider.clone(),
                )
                .map_err(|e| DidMethodError::ResolutionError(e.to_string()))?,
            };

            Ok(DidDocument {
                context: jwk_context(),
                id: did.to_owned(),
                verification_method: vec![verification_method],
                authentication: Some(vec![id.clone()]),
                assertion_method: Some(vec![id.clone()]),
                key_agreement: Some(vec![id.clone()]),
                capability_invocation: Some(vec![id.clone()]),
                capability_delegation: Some(vec![id]),
                also_known_as: None,
                service: None,
            })
        } else if let Some(mdl_public_key) = did.as_str().strip_prefix("did:mdl:public_key:") {
            let did_key = format!("did:key:{mdl_public_key}")
                .parse()
                .context("did parsing error")
                .map_err(|e| DidMethodError::ResolutionError(e.to_string()))?;

            let decoded_did_key = decode_did(&did_key)?;
            let algorithm = if decoded_did_key.type_ == DidKeyType::Ecdsa {
                "ECDSA"
            } else if decoded_did_key.type_ == DidKeyType::Eddsa {
                "EDDSA"
            } else {
                return Err(DidMethodError::ResolutionError(format!(
                    "Unsupported algorithm for mdl public key: {:?}",
                    decoded_did_key.type_
                )));
            };

            let key_algorithm = self
                .key_algorithm_provider
                .key_algorithm_from_name(algorithm)
                .ok_or(DidMethodError::ResolutionError(format!(
                    "Missing algorithm for mdl public key: {algorithm}",
                )))?;
            let public_key_jwk = key_algorithm
                .reconstruct_key(&decoded_did_key.decoded_multibase, None, None)
                .map_err(|err| DidMethodError::ResolutionError(err.to_string()))?
                .public_key_as_jwk()
                .map_err(|err| DidMethodError::ResolutionError(err.to_string()))?;

            generate_document(decoded_did_key, &did_key, public_key_jwk)
        } else {
            Err(DidMethodError::ResolutionError(format!(
                "`{}` cannot be resolved as did:mdl",
                did.as_str()
            )))
        }
    }

    fn update(&self) -> Result<(), DidMethodError> {
        Err(DidMethodError::NotSupported)
    }

    fn can_be_deactivated(&self) -> bool {
        false
    }

    fn get_capabilities(&self) -> DidCapabilities {
        DidCapabilities {
            operations: vec![Operation::CREATE, Operation::RESOLVE],
            key_algorithms: vec![KeyAlgorithmType::Ecdsa, KeyAlgorithmType::Eddsa],
            method_names: vec!["mdl".to_string()],
            features: vec![],
            supported_update_key_types: vec![],
        }
    }

    fn validate_keys(&self, keys: AmountOfKeys) -> bool {
        self.params.borrow_keys().validate_keys(keys)
    }

    fn get_keys(&self) -> Option<Keys> {
        Some(self.params.borrow_keys().to_owned())
    }
}

fn extract_x509_certificate(params: &serde_json::Value) -> Result<&str, DidMethodError> {
    const CERTIFICATE_PARAM: &str = "certificate";

    let certificate = params
        .get(CERTIFICATE_PARAM)
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            DidMethodError::CouldNotCreate(format!("Missing `{CERTIFICATE_PARAM}` in MDL params"))
        })?;

    Ok(certificate)
}

pub(crate) fn parse_pem(certificate: &str) -> Result<Pem, DidMethodError> {
    let (_leftover, pem) =
        x509_parser::pem::parse_x509_pem(certificate.as_bytes()).map_err(|err| {
            DidMethodError::CouldNotCreate(format!(
                "Error parsing certificate into PEM format: {err}"
            ))
        })?;

    Ok(pem)
}

pub(crate) fn parse_x509_from_pem(pem: &Pem) -> Result<X509Certificate, DidMethodError> {
    pem.parse_x509().map_err(|err| {
        DidMethodError::CouldNotCreate(format!(
            "Error parsing x509 certificate from PEM format: {err}"
        ))
    })
}

pub(crate) fn parse_x509_from_der(certificate: &[u8]) -> Result<X509Certificate, DidMethodError> {
    let (_leftover, certificate) =
        x509_parser::parse_x509_certificate(certificate).map_err(|err| {
            DidMethodError::CouldNotCreate(format!(
                "Error parsing x509 certificate from DER format: {err}"
            ))
        })?;

    Ok(certificate)
}
