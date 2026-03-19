use std::collections::HashMap;
use std::slice::from_ref;

use ct_codecs::{Base64, Encoder};
use one_dto_mapper::try_convert_inner;
use standardized_types::etsi_119_602::LoTEPayload;
use x509_parser::error::X509Error;

use crate::error::{ContextWithErrorCode, ErrorCode, ErrorCodeMixin, NestedError};
use crate::mapper::x509::x5c_into_pem_chain;
use crate::proto::certificate_validator::parse::parse_chain_to_x509_attributes;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::trust_list_subscriber::etsi_lote::model::PreprocessedLote;

#[derive(Debug, thiserror::Error)]
pub enum LotePreprocessingError {
    #[error("Invalid trust list content: {0}")]
    InvalidContent(Box<dyn std::error::Error + Send + Sync>),
    #[error("Encoding error: `{0}`")]
    Encoding(#[from] ct_codecs::Error),
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for LotePreprocessingError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::InvalidContent(_) => ErrorCode::BR_0393,
            Self::Encoding(_) => ErrorCode::BR_0397,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}

impl From<serde_json::Error> for LotePreprocessingError {
    fn from(err: serde_json::Error) -> Self {
        LotePreprocessingError::InvalidContent(Box::new(err))
    }
}

impl From<X509Error> for LotePreprocessingError {
    fn from(err: X509Error) -> Self {
        LotePreprocessingError::InvalidContent(Box::new(err))
    }
}

impl From<asn1_rs::Err<X509Error>> for LotePreprocessingError {
    fn from(err: asn1_rs::Err<X509Error>) -> Self {
        LotePreprocessingError::InvalidContent(Box::new(err))
    }
}

pub(super) fn preprocess_lote(
    lote: &LoTEPayload,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
) -> Result<PreprocessedLote, LotePreprocessingError> {
    let lote_type = try_convert_inner(lote.list_and_scheme_information.lote_type.clone())
        .unwrap_or_else(|err| {
            tracing::warn!("Discarding unsupported LoTE type: `{err}`");
            None
        });
    let mut preprocessed_lote = PreprocessedLote {
        role: lote_type,
        trusted_entities: Vec::new(),
        certificate_fingerprints: HashMap::new(),
        subject_key_identifiers: HashMap::new(),
        subject_names: HashMap::new(),
        public_keys: HashMap::new(),
    };
    let Some(trusted_entities) = &lote.trusted_entities_list else {
        return Ok(preprocessed_lote);
    };
    for (idx, trusted_entity) in trusted_entities.iter().enumerate() {
        preprocessed_lote
            .trusted_entities
            .push(trusted_entity.trusted_entity_information.clone());
        for service in &trusted_entity.trusted_entity_services {
            let Some(identity) = &service.service_information.service_digital_identity else {
                continue;
            };

            // certificate fingerprints
            if let Some(lote_certs) = &identity.x509_certificates {
                for cert in lote_certs {
                    let pem_chain = x5c_into_pem_chain(from_ref(&cert.val))
                        .error_while("encoding certificate to PEM")?;
                    let parsed_attributes = parse_chain_to_x509_attributes(pem_chain.as_bytes())
                        .error_while("parsing certificate")?;
                    preprocessed_lote
                        .certificate_fingerprints
                        .insert(parsed_attributes.fingerprint, idx);
                }
            }
            // subject key identifiers
            if let Some(skis) = &identity.x509_skis {
                for ski in skis {
                    preprocessed_lote
                        .subject_key_identifiers
                        .insert(ski.to_string(), idx);
                }
            }

            // subject names
            if let Some(subject_names) = &identity.x509_subject_names {
                for subject_name in subject_names {
                    preprocessed_lote
                        .subject_names
                        .insert(subject_name.to_string(), idx);
                }
            }

            // public keys
            if let Some(jwks) = &identity.public_key_values {
                for jwk in jwks {
                    let public_key = serde_json::from_value(jwk.clone())?;
                    let parsed_key = key_algorithm_provider
                        .parse_jwk(&public_key)
                        .error_while("parsing public JWK")?;
                    let raw_b64 = Base64::encode_to_string(parsed_key.key.public_key_as_raw())?;
                    preprocessed_lote.public_keys.insert(raw_b64, idx);
                }
            }
        }
    }
    Ok(preprocessed_lote)
}
