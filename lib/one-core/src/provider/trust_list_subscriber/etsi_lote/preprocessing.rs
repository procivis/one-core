use std::collections::HashSet;
use std::slice::from_ref;

use ct_codecs::{Base64, Encoder};
use one_dto_mapper::try_convert_inner;
use standardized_types::etsi_119_602::{
    LoTEPayload, MultiLangString, ServiceDigitalIdentity, ServiceStatus, TrustedEntity,
    TrustedEntityInformation,
};
use standardized_types::jwk::PublicJwk;
use standardized_types::x509::KeyIdentifier;
use x509_parser::error::X509Error;
use x509_parser::oid_registry::OID_X509_EXT_SUBJECT_KEY_IDENTIFIER;

use super::model::{LoteEntity, PreprocessedLote};
use crate::error::{ContextWithErrorCode, ErrorCode, ErrorCodeMixin, NestedError};
use crate::mapper::x509::{pem_to_subject_key_identifier, x5c_into_pem_chain};
use crate::model::trust_list_role::TrustListRoleEnum;
use crate::proto::certificate_validator::parse::extract_leaf_pem_from_chain;
use crate::proto::certificate_validator::{
    CertificateValidationOptions, CertificateValidator, ParsedCertificate,
};
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;

#[derive(Debug, thiserror::Error)]
pub enum LotePreprocessingError {
    #[error("Invalid trust list content: {0}")]
    InvalidContent(Box<dyn std::error::Error + Send + Sync>),
    #[error("Missing identifiers on entity `{entity:?}` in service `{service:?}`")]
    MissingIdentifiers {
        entity: Vec<MultiLangString>,
        service: Vec<MultiLangString>,
    },
    #[error(
        "Attribute `{attribute}` on entity `{entity:?}` in service `{service:?}` is not present in any certificate"
    )]
    InconsistentDigitalIdentityInformation {
        attribute: String,
        entity: Vec<MultiLangString>,
        service: Vec<MultiLangString>,
    },
    #[error("Encoding error: `{0}`")]
    Encoding(#[from] ct_codecs::Error),
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for LotePreprocessingError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::InvalidContent(_)
            | Self::MissingIdentifiers { .. }
            | Self::InconsistentDigitalIdentityInformation { .. } => ErrorCode::BR_0393,
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

pub(super) async fn preprocess_lote(
    lote: LoTEPayload,
    certificate_validator: &dyn CertificateValidator,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
) -> Result<PreprocessedLote, LotePreprocessingError> {
    let lote_type = try_convert_inner(lote.list_and_scheme_information.lote_type.clone())
        .unwrap_or_else(|err| {
            tracing::warn!("Discarding unsupported LoTE type: `{err}`");
            None
        });
    let mut preprocessed_lote = PreprocessedLote {
        role: lote_type,
        ..Default::default()
    };

    let Some(trusted_entities) = lote.trusted_entities_list else {
        return Ok(preprocessed_lote);
    };

    for trusted_entity in trusted_entities {
        let PreprocessingResult {
            entity,
            certificates,
            public_keys,
        } = match preprocess_trusted_entity(
            trusted_entity,
            certificate_validator,
            key_algorithm_provider,
        )
        .await
        {
            Ok(res) => res,
            Err(err) => {
                tracing::warn!(%err, "Failed to preprocess trusted entity, skipping");
                continue;
            }
        };

        let derived_role = preprocessed_lote.role;
        preprocessed_lote.trusted_entities.push(LoteEntity {
            info: entity,
            derived_role,
        });
        let idx = preprocessed_lote.trusted_entities.len() - 1;

        for certificate in certificates {
            preprocessed_lote.cert_index.insert(
                certificate.fingerprint,
                certificate.subject_key_identifier,
                certificate.pem,
                idx,
            );
        }

        for public_key in public_keys {
            preprocessed_lote
                .public_keys
                .entry(public_key)
                .or_default()
                .push(idx);
        }
    }
    Ok(preprocessed_lote)
}

/// Merge a pointed-to LoTE into `target`, offsetting its entity indices and
/// recomputing the aggregate role.
pub(super) fn merge_lote(target: &mut PreprocessedLote, source: PreprocessedLote) {
    let offset = target.trusted_entities.len();
    target.trusted_entities.extend(source.trusted_entities);
    target.cert_index.extend_offset(source.cert_index, offset);
    for (key, indices) in source.public_keys {
        target
            .public_keys
            .entry(key)
            .or_default()
            .extend(indices.into_iter().map(|idx| idx + offset));
    }
    target.role = aggregate_role(&target.trusted_entities);
}

/// The role shared by every entity, or `None` if they differ or there are none.
fn aggregate_role(entities: &[LoteEntity]) -> Option<TrustListRoleEnum> {
    let first = entities.iter().find_map(|e| e.derived_role)?;
    entities
        .iter()
        .all(|e| e.derived_role == Some(first))
        .then_some(first)
}

struct PreprocessingResult {
    entity: TrustedEntityInformation,
    certificates: Vec<PreprocessedCertificate>,
    public_keys: Vec<String>,
}

struct PreprocessedCertificate {
    subject_key_identifier: Option<KeyIdentifier>,
    fingerprint: String,
    pem: String,
}

/// According to the profile defined in 119 602 v1.1.1 annex H, entries in the Pub-EAA providers list SHALL include the status.
/// For all other profiles / list types, when an entity is suspended it's simply removed from the list, and the status field is not allowed.
fn is_active(service_status: Option<&ServiceStatus>) -> bool {
    !matches!(service_status, Some(ServiceStatus::PubEaaWithdrawn))
}

async fn preprocess_trusted_entity(
    trusted_entity: TrustedEntity,
    certificate_validator: &dyn CertificateValidator,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
) -> Result<PreprocessingResult, LotePreprocessingError> {
    let mut certificates = vec![];
    let mut public_keys = HashSet::new();

    for service in trusted_entity.trusted_entity_services {
        if !is_active(service.service_information.service_status.as_ref()) {
            tracing::debug!(
                status = service
                    .service_information
                    .service_status
                    .as_ref()
                    .map(ToString::to_string),
                "skipping LoTE service that is not active"
            );
            continue;
        }
        let Some(identity) = service.service_information.service_digital_identity else {
            continue;
        };

        let entity_name = &trusted_entity.trusted_entity_information.te_name;
        let service_name = &service.service_information.service_name;

        if identity.x509_certificates.is_some() {
            certificates.extend(
                preprocess_certificate_identity(
                    &identity,
                    entity_name,
                    service_name,
                    certificate_validator,
                    key_algorithm_provider,
                )
                .await?,
            );
        } else if identity.public_key_values.is_some() {
            public_keys.extend(preprocess_public_key_identity(
                &identity,
                entity_name,
                service_name,
                key_algorithm_provider,
            )?);
        } else {
            return Err(LotePreprocessingError::MissingIdentifiers {
                entity: entity_name.clone(),
                service: service_name.clone(),
            });
        }
    }

    if certificates.is_empty() && public_keys.is_empty() {
        return Err(LotePreprocessingError::InvalidContent(
            format!(
                "No digital identity information for entity `{:?}`",
                trusted_entity.trusted_entity_information.te_name
            )
            .into(),
        ));
    }

    Ok(PreprocessingResult {
        entity: trusted_entity.trusted_entity_information,
        certificates,
        public_keys: public_keys.into_iter().collect(),
    })
}

async fn preprocess_certificate_identity(
    identity: &ServiceDigitalIdentity,
    entity_name: &[MultiLangString],
    service_name: &[MultiLangString],
    certificate_validator: &dyn CertificateValidator,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
) -> Result<Vec<PreprocessedCertificate>, LotePreprocessingError> {
    let mut result = vec![];

    let mut subject_key_identifiers = HashSet::new();
    let mut subject_names = HashSet::new();
    let mut public_keys = HashSet::new();

    let Some(lote_certs) = &identity.x509_certificates else {
        return Err(LotePreprocessingError::MissingIdentifiers {
            entity: entity_name.to_owned(),
            service: service_name.to_owned(),
        });
    };
    if lote_certs.is_empty() {
        return Err(LotePreprocessingError::MissingIdentifiers {
            entity: entity_name.to_owned(),
            service: service_name.to_owned(),
        });
    }

    for lote_cert in lote_certs {
        let pem_chain = x5c_into_pem_chain(from_ref(&lote_cert.val))
            .error_while("encoding certificate to PEM")?;

        let subject_key_identifier =
            pem_to_subject_key_identifier(&pem_chain).error_while("parsing PEM chain SKI")?;

        let fingerprint = match certificate_validator
            .parse_pem_chain(
                &pem_chain,
                CertificateValidationOptions::signature_and_revocation(None),
            )
            .await
        {
            Ok(ParsedCertificate { attributes, .. }) => attributes.fingerprint,
            Err(err) => {
                tracing::warn!(%err, "Failed to validate certificate on trust-list, skipping");
                continue;
            }
        };

        let pem = extract_leaf_pem_from_chain(pem_chain.as_bytes())
            .error_while("parsing certificate value")?;
        let cert = pem.parse_x509()?;
        let der_b64 = Base64::encode_to_string(cert.public_key().raw)?;
        public_keys.insert(der_b64);
        if let Some(ski_ext) = cert.get_extension_unique(&OID_X509_EXT_SUBJECT_KEY_IDENTIFIER)? {
            let subject_key_identifier = Base64::encode_to_string(ski_ext.value)?;
            subject_key_identifiers.insert(subject_key_identifier);
        }
        subject_names.insert(cert.subject.to_string());

        result.push(PreprocessedCertificate {
            subject_key_identifier,
            fingerprint,
            pem: pem_chain,
        });
    }

    // validate consistency
    if let Some(skis) = &identity.x509_skis {
        for ski in skis {
            if !subject_key_identifiers.contains(ski) {
                return Err(
                    LotePreprocessingError::InconsistentDigitalIdentityInformation {
                        attribute: format!("Subject key identifier `{ski}`"),
                        entity: entity_name.to_owned(),
                        service: service_name.to_owned(),
                    },
                );
            }
        }
    }
    if let Some(names) = &identity.x509_subject_names {
        for name in names {
            if !subject_names.contains(name) {
                return Err(
                    LotePreprocessingError::InconsistentDigitalIdentityInformation {
                        attribute: format!("Subject name `{name}`"),
                        entity: entity_name.to_owned(),
                        service: service_name.to_owned(),
                    },
                );
            }
        }
    }
    if let Some(jwks) = &identity.public_key_values {
        for jwk in jwks {
            let public_key: PublicJwk = serde_json::from_value(jwk.clone())?;
            let der_b64 = jwk_to_der_b64(&public_key, key_algorithm_provider)?;
            if !public_keys.contains(&der_b64) {
                return Err(
                    LotePreprocessingError::InconsistentDigitalIdentityInformation {
                        attribute: format!("Public key `{jwk}`"),
                        entity: entity_name.to_owned(),
                        service: service_name.to_owned(),
                    },
                );
            }
        }
    }

    Ok(result)
}

fn preprocess_public_key_identity(
    identity: &ServiceDigitalIdentity,
    entity_name: &[MultiLangString],
    service_name: &[MultiLangString],
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
) -> Result<HashSet<String>, LotePreprocessingError> {
    let mut public_keys = HashSet::new();

    let Some(jwks) = &identity.public_key_values else {
        return Err(LotePreprocessingError::MissingIdentifiers {
            entity: entity_name.to_owned(),
            service: service_name.to_owned(),
        });
    };
    if jwks.is_empty() {
        return Err(LotePreprocessingError::MissingIdentifiers {
            entity: entity_name.to_owned(),
            service: service_name.to_owned(),
        });
    }

    for jwk in jwks {
        let public_key: PublicJwk = serde_json::from_value(jwk.clone())?;
        public_keys.insert(jwk_to_der_b64(&public_key, key_algorithm_provider)?);
    }

    Ok(public_keys)
}

pub(super) fn jwk_to_der_b64(
    jwk: &PublicJwk,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
) -> Result<String, LotePreprocessingError> {
    let parsed_key = key_algorithm_provider
        .parse_jwk(jwk)
        .error_while("parsing public JWK")?;
    let der_b64 = Base64::encode_to_string(
        parsed_key
            .key
            .public_key_as_der()
            .error_while("encoding public key to DER")?,
    )?;
    Ok(der_b64)
}

#[cfg(test)]
mod test {
    use similar_asserts::assert_eq;

    use super::*;

    fn entity(role: Option<TrustListRoleEnum>) -> LoteEntity {
        LoteEntity {
            info: Default::default(),
            derived_role: role,
        }
    }

    #[test]
    fn aggregate_role_is_the_shared_role_when_homogeneous() {
        let entities = vec![
            entity(Some(TrustListRoleEnum::PidProvider)),
            entity(Some(TrustListRoleEnum::PidProvider)),
        ];
        assert_eq!(
            aggregate_role(&entities),
            Some(TrustListRoleEnum::PidProvider)
        );
    }

    #[test]
    fn aggregate_role_is_none_when_roles_differ() {
        let entities = vec![
            entity(Some(TrustListRoleEnum::PidProvider)),
            entity(Some(TrustListRoleEnum::WalletProvider)),
        ];
        assert_eq!(aggregate_role(&entities), None);
    }

    #[test]
    fn withdrawn_services_are_not_active() {
        assert!(is_active(None));
        assert!(is_active(Some(&ServiceStatus::PubEaaNotified)));
        assert!(is_active(Some(&ServiceStatus::Other(
            "http://uri.etsi.org/19602/ServiceStatus/granted".to_string()
        ))));
        assert!(!is_active(Some(&ServiceStatus::PubEaaWithdrawn)));
    }

    #[test]
    fn aggregate_role_is_none_when_no_entity_has_a_role() {
        assert_eq!(aggregate_role(&[entity(None), entity(None)]), None);
    }

    #[test]
    fn merge_offsets_indices_and_recomputes_a_roleless_aggregate() {
        let mut target = PreprocessedLote {
            role: Some(TrustListRoleEnum::PidProvider),
            trusted_entities: vec![entity(Some(TrustListRoleEnum::PidProvider))],
            ..Default::default()
        };
        target
            .cert_index
            .insert("fp-root".to_string(), None, String::new(), 0);
        let mut source = PreprocessedLote {
            role: Some(TrustListRoleEnum::WalletProvider),
            trusted_entities: vec![entity(Some(TrustListRoleEnum::WalletProvider))],
            ..Default::default()
        };
        source
            .cert_index
            .insert("fp-child".to_string(), None, String::new(), 0);
        source.public_keys.insert("pk-child".to_string(), vec![0]);

        merge_lote(&mut target, source);

        assert_eq!(target.trusted_entities.len(), 2);
        // the child's entity index 0 is offset past the root's entry
        assert_eq!(
            target.cert_index.fingerprint_to_entries.get("fp-child"),
            Some(&vec![1])
        );
        assert_eq!(target.public_keys.get("pk-child"), Some(&vec![1]));
        // each entity keeps the role of its source list
        assert_eq!(
            target.trusted_entities[1].derived_role,
            Some(TrustListRoleEnum::WalletProvider)
        );
        // a mixed aggregate is roleless (gated per entity at resolve time)
        assert_eq!(target.role, None);
    }
}
