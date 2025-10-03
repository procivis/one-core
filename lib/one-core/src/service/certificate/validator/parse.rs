use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use time::Duration;
use x509_parser::oid_registry::{OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY, OID_SIG_ED25519};
use x509_parser::pem::Pem;
use x509_parser::prelude::{ASN1Time, X509Certificate};

use super::x509_extension::{
    validate_ca_key_usage, validate_critical_extensions, validate_required_cert_key_usage,
};
use super::{
    CertSelection, CertificateValidationOptions, CertificateValidator, CertificateValidatorImpl,
    ParsedCertificate, x509_extension,
};
use crate::config::core_config::KeyAlgorithmType;
use crate::provider::key_algorithm::error::KeyAlgorithmProviderError;
use crate::provider::key_algorithm::key::KeyHandle;
use crate::service::certificate::dto::CertificateX509AttributesDTO;
use crate::service::error::{MissingProviderError, ServiceError, ValidationError};
use crate::util::x509::{authority_key_identifier, subject_key_identifier};

const LEEWAY: Duration = Duration::seconds(60);

#[async_trait::async_trait]
impl CertificateValidator for CertificateValidatorImpl {
    async fn parse_pem_chain(
        &self,
        pem_chain: &str,
        validation: CertificateValidationOptions,
    ) -> Result<ParsedCertificate, ServiceError> {
        let items = Pem::iter_from_buffer(pem_chain.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| ValidationError::CertificateParsingFailed(err.to_string()))?;

        let certs = items
            .iter()
            .map(|pem| pem.parse_x509())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| ValidationError::CertificateParsingFailed(err.to_string()))?;

        let leaf_certificate = self.parse_chain(&certs, validation).await?;
        self.to_parsed_certificate(leaf_certificate)
    }

    async fn validate_chain_against_ca_chain(
        &self,
        pem_chain: &str,
        ca_pem_chain: &str,
        validation: CertificateValidationOptions,
        cert_selection: CertSelection,
    ) -> Result<ParsedCertificate, ServiceError> {
        let pems = Pem::iter_from_buffer(pem_chain.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| ValidationError::CertificateParsingFailed(err.to_string()))?;
        let ca_pems = Pem::iter_from_buffer(ca_pem_chain.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| ValidationError::CertificateParsingFailed(err.to_string()))?;

        let certs = pems
            .iter()
            .map(|pem| pem.parse_x509())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| ValidationError::CertificateParsingFailed(err.to_string()))?;

        let ca_certs = ca_pems
            .iter()
            .map(|pem| pem.parse_x509())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| ValidationError::CertificateParsingFailed(err.to_string()))?;

        let connected = connect_chains(&certs, &ca_certs)?;
        let parsed = self.parse_chain(&connected, validation).await?;

        let selected_cert = match cert_selection {
            CertSelection::LowestCaChain => {
                ca_certs
                    .first()
                    .ok_or(ValidationError::CertificateParsingFailed(
                        "empty chain".to_string(),
                    ))?
            }
            CertSelection::Leaf => parsed,
        };
        self.to_parsed_certificate(selected_cert)
    }
}

impl CertificateValidatorImpl {
    async fn parse_chain<'a>(
        &self,
        chain: &'a [X509Certificate<'a>],
        validation: CertificateValidationOptions,
    ) -> Result<&'a X509Certificate<'a>, ServiceError> {
        if validation.require_root_termination {
            self.validate_root_ca_termination(chain)?;
        }

        if validation.integrity_check {
            self.validate_path_length(chain)?;
        }

        let mut result: Option<&X509Certificate<'a>> = None;
        let mut chain = chain.iter().peekable();
        while let Some(current) = chain.next() {
            if result.is_none() {
                if !validation.required_leaf_cert_key_usage.is_empty() {
                    validate_required_cert_key_usage(
                        current,
                        &validation.required_leaf_cert_key_usage,
                    )?;
                }

                if validation.validity_check.is_none()
                    && !validation.integrity_check
                    && validation.leaf_only_extensions.is_empty()
                {
                    return Ok(current);
                }

                result = Some(current);
            }

            let next = chain.peek();
            if validation.integrity_check {
                if let Some(parent) = next {
                    if !parent.is_ca() {
                        return Err(ValidationError::InvalidCaCertificateChain(
                            "Certificate chain containing non-CA parents".to_string(),
                        )
                        .into());
                    };

                    current
                        .verify_signature(Some(parent.public_key()))
                        .map_err(|_| ValidationError::CertificateSignatureInvalid)?;
                }

                validate_ca_key_usage(current)?;
                validate_critical_extensions(current)?;
            }

            if let Some(crl_mode) = validation.validity_check {
                self.check_validity_with_leeway(current, LEEWAY)?;

                let revoked = self
                    .check_revocation(current, next.copied(), crl_mode)
                    .await?;
                if revoked {
                    return Err(ValidationError::CertificateRevoked.into());
                }
            }

            if !validation.leaf_only_extensions.is_empty()
                && current.is_ca()
                && current.extensions().iter().any(|ext| {
                    validation
                        .leaf_only_extensions
                        .contains(&ext.oid.to_id_string())
                })
            {
                return Err(ValidationError::InvalidCaCertificateChain(
                    "Found leaf only extension in CA cert".to_string(),
                )
                .into());
            }
        }

        result.ok_or(
            ValidationError::CertificateParsingFailed("No certificates specified".to_string())
                .into(),
        )
    }

    fn to_parsed_certificate(
        &self,
        certificate: &X509Certificate,
    ) -> Result<ParsedCertificate, ServiceError> {
        let subject_common_name = certificate
            .subject
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .map(ToString::to_string);

        Ok(ParsedCertificate {
            attributes: parse_x509_attributes(certificate)?,
            subject_common_name,
            subject_key_identifier: subject_key_identifier(certificate)?,
            public_key: self.extract_public_key(certificate)?,
        })
    }

    fn extract_public_key(&self, certificate: &X509Certificate) -> Result<KeyHandle, ServiceError> {
        let alg_type = match &certificate.subject_pki.algorithm.algorithm {
            alg if alg == &OID_SIG_ED25519 => KeyAlgorithmType::Eddsa,

            alg if alg == &OID_KEY_TYPE_EC_PUBLIC_KEY => {
                let curve_oid = certificate
                    .subject_pki
                    .algorithm
                    .parameters
                    .as_ref()
                    .and_then(|p| p.as_oid().ok())
                    .ok_or(ValidationError::CertificateParsingFailed(
                        "EC algorithm missing curve information".to_string(),
                    ))?;

                if curve_oid != OID_EC_P256 {
                    return Err(ValidationError::CertificateParsingFailed(format!(
                        "EC algorithm with unsupported curve. oid: {curve_oid}"
                    ))
                    .into());
                }

                KeyAlgorithmType::Ecdsa
            }
            other => {
                return Err(ValidationError::CertificateParsingFailed(format!(
                    "certificate with unsupported algorithm. oid: {other}"
                ))
                .into());
            }
        };

        let key_algorithm = self
            .key_algorithm_provider
            .key_algorithm_from_type(alg_type)
            .ok_or_else(|| {
                MissingProviderError::KeyAlgorithmProvider(
                    KeyAlgorithmProviderError::MissingAlgorithmImplementation(alg_type.to_string()),
                )
            })?;

        let key_handle = key_algorithm.parse_raw(certificate.subject_pki.raw)?;

        Ok(key_handle)
    }

    /// Validates the path length constraints for each certificate in the chain.
    /// For each certificate with a BasicConstraints extension and a pathLenConstraint,
    /// ensures that the number of remaining intermediate CA certificates in the chain does not exceed the constraint.
    fn validate_path_length(
        &self,
        certificate_chain: &[X509Certificate],
    ) -> Result<(), ServiceError> {
        use x509_parser::extensions::ParsedExtension;

        // Filter only CA certificates from the chain (leaf -> root order)
        let ca_certs: Vec<&X509Certificate> = certificate_chain
            .iter()
            .filter(|cert| cert.is_ca())
            .collect();

        for (chain_idx, certificate) in ca_certs.iter().enumerate() {
            for ext in certificate.extensions() {
                if let ParsedExtension::BasicConstraints(bc) = &ext.parsed_extension() {
                    if let Some(path_len_constraint) = bc.path_len_constraint {
                        // chain_idx is the number of intermediate CAs that "follow" this certificate
                        let intermediate_cas_following = chain_idx;
                        if (path_len_constraint as usize) < intermediate_cas_following {
                            return Err(ValidationError::BasicConstraintsViolation(
                                format!(
                                    "Path length constraint={path_len_constraint}, intermediate CAs count={intermediate_cas_following}"
                                ),
                            ).into());
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn validate_root_ca_termination(
        &self,
        certificate_chain: &[X509Certificate],
    ) -> Result<(), ServiceError> {
        let Some(terminating_certificate) = certificate_chain.last() else {
            return Err(ValidationError::InvalidCaCertificateChain(
                "Certificate chain is empty".to_string(),
            )
            .into());
        };

        if !terminating_certificate.is_ca() {
            return Err(ValidationError::InvalidCaCertificateChain(
                "Certificate chain does not terminate to a CA".to_string(),
            )
            .into());
        };

        if terminating_certificate.issuer() != terminating_certificate.subject() {
            return Err(ValidationError::InvalidCaCertificateChain(
                "Certificate chain does not terminate to a root CA".to_string(),
            )
            .into());
        }

        // Verify the self-signed signature to ensure it's a legitimate root CA
        terminating_certificate
            .verify_signature(Some(terminating_certificate.public_key()))
            .map_err(|_| ValidationError::CertificateSignatureInvalid)?;

        Ok(())
    }

    fn check_validity_with_leeway(
        &self,
        cert: &X509Certificate,
        leeway: Duration,
    ) -> Result<(), ValidationError> {
        let now = self.clock.now_utc();
        if ASN1Time::from(now + leeway) < cert.validity.not_before {
            return Err(ValidationError::CertificateNotYetValid);
        }

        if ASN1Time::from(now - leeway) > cert.validity.not_after {
            return Err(ValidationError::CertificateExpired);
        }

        Ok(())
    }
}

pub fn parse_chain_to_x509_attributes(
    pem_chain: &[u8],
) -> Result<CertificateX509AttributesDTO, ValidationError> {
    let Some(pem) = Pem::iter_from_buffer(pem_chain).next() else {
        return Err(ValidationError::CertificateParsingFailed(
            "No certificates specified".to_string(),
        ));
    };

    let pem = pem.map_err(|e| ValidationError::CertificateParsingFailed(e.to_string()))?;

    let x509_cert = pem
        .parse_x509()
        .map_err(|e| ValidationError::CertificateParsingFailed(e.to_string()))?;
    parse_x509_attributes(&x509_cert)
}

fn parse_x509_attributes(
    certificate: &X509Certificate,
) -> Result<CertificateX509AttributesDTO, ValidationError> {
    let validity = certificate.validity();

    let fingerprint = SHA256
        .hash(certificate.as_ref())
        .map_err(|err| ValidationError::CertificateParsingFailed(err.to_string()))?;

    let extensions = certificate
        .extensions()
        .iter()
        .map(x509_extension::parse)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(CertificateX509AttributesDTO {
        serial_number: certificate.raw_serial_as_string(),
        not_before: validity.not_before.to_datetime(),
        not_after: validity.not_after.to_datetime(),
        issuer: certificate.issuer.to_string(),
        subject: certificate.subject.to_string(),
        fingerprint: hex::encode(fingerprint),
        extensions,
    })
}

/// Tries to connect two certificate chains into a single chain
/// * `leaf_certs` - The chain beginning with a leaf/child certificate
/// * `ca_certs` - The chain beginning with an intermediate CA certificate, potentially ending with a root CA certificate
///
/// The two chains can overlap (e.g. if `leaf_certs` specifies the whole chain already)
///
/// If no match between the two chains are found, it will result in an error
fn connect_chains<'a>(
    leaf_certs: &'a [X509Certificate<'a>],
    ca_certs: &'a [X509Certificate<'a>],
) -> Result<Vec<X509Certificate<'a>>, ValidationError> {
    let Some(first_ca_cert) = ca_certs.first() else {
        return Err(ValidationError::InvalidCaCertificateChain(
            "CA certificate chain is empty".to_string(),
        ));
    };

    let first_ca_subject_key_identifier = subject_key_identifier(first_ca_cert)?.ok_or(
        ValidationError::InvalidCaCertificateChain(format!(
            "CA certificate (subject: {}) is missing subject key identifier",
            first_ca_cert.subject
        )),
    )?;

    let mut result = vec![];
    for current in leaf_certs {
        result.push(current.to_owned());

        let matching_with_first_ca = match authority_key_identifier(current)? {
            Some(authority_key_identifier) => {
                authority_key_identifier == first_ca_subject_key_identifier
            }
            None => {
                // no authority key identifier was provided, we have to check by attempting to verify the signature
                current
                    .verify_signature(Some(first_ca_cert.public_key()))
                    .is_ok()
            }
        };

        if matching_with_first_ca {
            // we have found the match with the first CA cert, now append the rest of the ca_chain to complete the whole chain
            result.extend(ca_certs.to_owned());
            return Ok(result);
        }
    }

    Err(ValidationError::InvalidCaCertificateChain(
        "Certificate chain incomplete".to_string(),
    ))
}
