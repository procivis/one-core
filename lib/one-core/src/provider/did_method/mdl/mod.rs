use std::sync::Arc;

use anyhow::Context;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use ouroboros::self_referencing;
use serde::{Deserialize, Deserializer};
use serde_json::json;
use shared_types::{DidId, DidValue};
use x509_parser::{
    certificate::X509Certificate,
    oid_registry::{OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY, OID_SIG_ED25519},
    pem::Pem,
};

use crate::{
    config::core_config::{self, DidType, Fields},
    model::key::Key,
    provider::key_algorithm::provider::KeyAlgorithmProvider,
};

use super::{
    common::jwk_context,
    dto::{AmountOfKeys, DidDocumentDTO, DidVerificationMethodDTO, Keys},
    DidCapabilities, DidMethod, DidMethodError, Operation,
};

pub use validator::{DidMdlValidationError, DidMdlValidator};

#[cfg(test)]
mod test;
mod validator;

pub struct DidMdl {
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    params: InnerParams,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    #[serde(default)]
    keys: Keys,
    #[serde(deserialize_with = "deserialize_base64")]
    iaca_certificate: Vec<u8>,
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
        _id: &DidId,
        params: &Option<serde_json::Value>,
        keys: &[Key],
    ) -> Result<DidValue, DidMethodError> {
        let Some(params) = params.as_ref() else {
            return Err(DidMethodError::CouldNotCreate(
                "Missing params for MDL".to_owned(),
            ));
        };

        let certificate = extract_x509_certificate(params)?;

        let selected_key = select_key(keys)?;

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

        Ok(DidValue::from(did_mdl))
    }

    async fn resolve(&self, did: &DidValue) -> Result<DidDocumentDTO, DidMethodError> {
        match did.as_str() {
            certificate if certificate.starts_with("did:mdl:certificate:") => {
                let certificate = certificate.strip_prefix("did:mdl:certificate:").unwrap();
                let certificate = Base64UrlSafeNoPadding::decode_to_vec(certificate, None)
                    .map_err(|err| DidMethodError::ResolutionError(err.to_string()))?;
                let x509 = parse_x509_from_der(&certificate)
                    .map_err(|err| DidMethodError::ResolutionError(err.to_string()))?;

                let key_algorithm = match &x509.subject_pki.algorithm.algorithm {
                    alg if alg == &OID_SIG_ED25519 => self
                        .key_algorithm_provider
                        .get_key_algorithm("EDDSA")
                        .ok_or_else(|| DidMethodError::KeyAlgorithmNotFound)?,
                    alg if alg == &OID_KEY_TYPE_EC_PUBLIC_KEY => {
                        let curve_oid = x509
                            .subject_pki
                            .algorithm
                            .parameters
                            .as_ref()
                            .and_then(|p| p.as_oid().ok())
                            .ok_or_else(|| {
                                DidMethodError::ResolutionError(
                                    "Invalid did:mdl:certificate: EC algorithm missing curve information".to_owned()
                                )
                            })?;
                        if curve_oid != OID_EC_P256 {
                            return Err(DidMethodError::ResolutionError(format!(
                                "did:mdl:certificate EC algorithm with unsupported curve. oid: {curve_oid}"
                            )));
                        }

                        self.key_algorithm_provider
                            .get_key_algorithm("ES256")
                            .ok_or_else(|| DidMethodError::KeyAlgorithmNotFound)?
                    }
                    other => {
                        return Err(DidMethodError::ResolutionError(format!(
                            "did:mdl:certificate with unsupported algorithm. oid: {other}"
                        )))
                    }
                };

                let id = format!("{did}#key-0");

                let public_key_jwk = key_algorithm
                    .public_key_from_der(x509.subject_pki.raw)
                    .and_then(|key| key_algorithm.bytes_to_jwk(&key, None))
                    .map_err(|err| DidMethodError::ResolutionError(err.to_string()))?;

                let verification_method = DidVerificationMethodDTO {
                    id: id.clone(),
                    r#type: "JsonWebKey2020".into(),
                    controller: did.to_string(),
                    public_key_jwk,
                };

                Ok(DidDocumentDTO {
                    context: jwk_context(),
                    id: did.to_owned(),
                    verification_method: vec![verification_method],
                    authentication: Some(vec![id.clone()]),
                    assertion_method: Some(vec![id.clone()]),
                    key_agreement: Some(vec![id.clone()]),
                    capability_invocation: Some(vec![id.clone()]),
                    capability_delegation: Some(vec![id]),
                    rest: Default::default(),
                })
            }
            mdl_public_key if mdl_public_key.starts_with("did:mdl:public_key:") => {
                let did_key: DidValue = match mdl_public_key
                    .replace("did:mdl:public_key", "did:key")
                    .parse()
                {
                    Ok(did_key) => did_key,
                    Err(err) => match err {},
                };

                let decoded_did_key = super::key::decode_did(&did_key)?;
                let algorithm = if decoded_did_key.type_.is_ecdsa() {
                    "ES256"
                } else if decoded_did_key.type_.is_eddsa() {
                    "EDDSA"
                } else {
                    return Err(DidMethodError::ResolutionError(format!(
                        "Unsupported algorithm for mdl public key: {:?}",
                        decoded_did_key.type_
                    )));
                };

                let Some(key_algorithm) = self.key_algorithm_provider.get_key_algorithm(algorithm)
                else {
                    return Err(DidMethodError::ResolutionError(format!(
                        "Missing algorithm for mdl public key: {algorithm}",
                    )));
                };
                let public_key_jwk = key_algorithm
                    .bytes_to_jwk(&decoded_did_key.decoded_multibase, None)
                    .map_err(|err| DidMethodError::ResolutionError(err.to_string()))?;

                super::key::generate_document(decoded_did_key, &did_key, public_key_jwk)
            }
            other => Err(DidMethodError::ResolutionError(format!(
                "`{other}` cannot be resolved as did:mdl"
            ))),
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
            key_algorithms: ["ES256", "EDDSA"].map(str::to_string).to_vec(),
        }
    }

    fn validate_keys(&self, keys: AmountOfKeys) -> bool {
        self.params.borrow_keys().validate_keys(keys)
    }

    fn visit_config_fields(&self, fields: &Fields<DidType>) -> Fields<DidType> {
        Fields {
            capabilities: Some(json!(self.get_capabilities())),
            params: Some(core_config::Params {
                public: Some(json!({
                    "keys": self.params.borrow_keys(),
                })),
                private: None,
            }),
            ..fields.clone()
        }
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

fn parse_pem(certificate: &str) -> Result<Pem, DidMethodError> {
    let (_leftover, pem) =
        x509_parser::pem::parse_x509_pem(certificate.as_bytes()).map_err(|err| {
            DidMethodError::CouldNotCreate(format!(
                "Error parsing certificate into PEM format: {err}"
            ))
        })?;

    Ok(pem)
}

fn parse_x509_from_pem(pem: &Pem) -> Result<X509Certificate, DidMethodError> {
    pem.parse_x509().map_err(|err| {
        DidMethodError::CouldNotCreate(format!(
            "Error parsing x509 certificate from PEM format: {err}"
        ))
    })
}

fn parse_x509_from_der(certificate: &[u8]) -> Result<X509Certificate, DidMethodError> {
    let (_leftover, certificate) =
        x509_parser::parse_x509_certificate(certificate).map_err(|err| {
            DidMethodError::CouldNotCreate(format!(
                "Error parsing x509 certificate from DER format: {err}"
            ))
        })?;

    Ok(certificate)
}

fn select_key(keys: &[Key]) -> Result<&Key, DidMethodError> {
    let [key] = keys else {
        return Err(DidMethodError::CouldNotCreate(format!(
            "Expected 1 provided {} keys for DID MDL creation",
            keys.len()
        )));
    };

    Ok(key)
}

fn deserialize_base64<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;

    Base64UrlSafeNoPadding::decode_to_vec(s, None).map_err(serde::de::Error::custom)
}
