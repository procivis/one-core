use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use time::Duration;
use x509_parser::oid_registry::{OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY, OID_SIG_ED25519};
use x509_parser::pem::Pem;
use x509_parser::prelude::{ASN1Time, X509Certificate};

use super::x509_extension::{
    validate_ca_signature, validate_critical_extensions, validate_required_cert_key_usage,
};
use super::{
    CertSelection, CertificateValidationOptions, CertificateValidator, CertificateValidatorImpl,
    Error, ParsedCertificate, x509_extension,
};
use crate::config::core_config::KeyAlgorithmType;
use crate::error::ContextWithErrorCode;
use crate::mapper::x509::{authority_key_identifier, subject_key_identifier};
use crate::provider::key_algorithm::error::KeyAlgorithmProviderError;
use crate::provider::key_algorithm::key::KeyHandle;
use crate::service::certificate::dto::CertificateX509AttributesDTO;

#[async_trait::async_trait]
impl CertificateValidator for CertificateValidatorImpl {
    async fn parse_pem_chain(
        &self,
        pem_chain: &str,
        validation: CertificateValidationOptions,
    ) -> Result<ParsedCertificate, Error> {
        let items = Pem::iter_from_buffer(pem_chain.as_bytes()).collect::<Result<Vec<_>, _>>()?;

        let leaf_pem = items.first().ok_or(Error::EmptyChain)?;

        let certs = items
            .iter()
            .map(|pem| pem.parse_x509())
            .collect::<Result<Vec<_>, _>>()?;

        let leaf_certificate = self.parse_chain(&certs, validation).await?;
        self.to_parsed_certificate(leaf_certificate, &leaf_pem.contents)
    }

    async fn validate_chain_against_ca_chain(
        &self,
        pem_chain: &str,
        ca_pem_chain: &str,
        validation: CertificateValidationOptions,
        cert_selection: CertSelection,
    ) -> Result<ParsedCertificate, Error> {
        let pems = Pem::iter_from_buffer(pem_chain.as_bytes()).collect::<Result<Vec<_>, _>>()?;
        let ca_pems =
            Pem::iter_from_buffer(ca_pem_chain.as_bytes()).collect::<Result<Vec<_>, _>>()?;

        let certs = pems
            .iter()
            .map(|pem| pem.parse_x509())
            .collect::<Result<Vec<_>, _>>()?;

        let ca_certs = ca_pems
            .iter()
            .map(|pem| pem.parse_x509())
            .collect::<Result<Vec<_>, _>>()?;

        let connected = connect_chains(&certs, &ca_certs)?;
        let parsed = self.parse_chain(&connected, validation).await?;

        let (selected_cert, pem) = match cert_selection {
            CertSelection::LowestCaChain => (
                ca_certs.first().ok_or(Error::EmptyChain)?,
                ca_pems.first().ok_or(Error::EmptyChain)?,
            ),
            CertSelection::Leaf => (parsed, pems.first().ok_or(Error::EmptyChain)?),
        };
        self.to_parsed_certificate(selected_cert, &pem.contents)
    }
}

impl CertificateValidatorImpl {
    async fn parse_chain<'a>(
        &self,
        chain: &'a [X509Certificate<'a>],
        validation: CertificateValidationOptions,
    ) -> Result<&'a X509Certificate<'a>, Error> {
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
                    && validation.leaf_validations.is_empty()
                {
                    // no more checks needed, return the parsed certificate
                    return Ok(current);
                }

                result = Some(current);
            }

            if validation.integrity_check {
                if let Some(parent) = chain.peek() {
                    validate_ca_signature(current, parent)?;
                }

                validate_critical_extensions(current)?;
            }

            if let Some(crl_mode) = validation.validity_check {
                self.check_validity_with_leeway(current, self.clock_leeway)?;

                self.check_revocation(current, chain.peek().copied(), crl_mode)
                    .await?;
            }

            if !validation.leaf_only_extensions.is_empty()
                && current.is_ca()
                && current.extensions().iter().any(|ext| {
                    validation
                        .leaf_only_extensions
                        .contains(&ext.oid.to_id_string())
                })
            {
                return Err(Error::InvalidCaCertificateChain(
                    "Found leaf only extension in CA cert".to_string(),
                ));
            }

            if !validation.leaf_validations.is_empty() {
                validation
                    .leaf_validations
                    .iter()
                    .try_for_each(|v| v(current))
                    .error_while("validating leaf certificate")?;
            }
        }

        result.ok_or(Error::EmptyChain)
    }

    fn to_parsed_certificate(
        &self,
        certificate: &X509Certificate,
        der_representation: &[u8],
    ) -> Result<ParsedCertificate, Error> {
        let subject_common_name = certificate
            .subject
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .map(ToString::to_string);

        Ok(ParsedCertificate {
            attributes: parse_x509_attributes(certificate, der_representation)?,
            subject_common_name,
            subject_key_identifier: subject_key_identifier(certificate)
                .error_while("parsing subject_key_identifier")?,
            public_key: self.extract_public_key(certificate)?,
        })
    }

    fn extract_public_key(&self, certificate: &X509Certificate) -> Result<KeyHandle, Error> {
        let alg_type = get_public_key_type(certificate)?;

        let key_algorithm = self
            .key_algorithm_provider
            .key_algorithm_from_type(alg_type)
            .ok_or_else(|| {
                KeyAlgorithmProviderError::MissingAlgorithmImplementation(alg_type.to_string())
            })
            .error_while("getting key algorithm")?;

        let key_handle = key_algorithm
            .parse_raw(certificate.subject_pki.raw)
            .error_while("parsing certificate public key")?;

        Ok(key_handle)
    }

    /// Validates the path length constraints for each certificate_validator in the chain.
    /// For each certificate_validator with a BasicConstraints extension and a pathLenConstraint,
    /// ensures that the number of remaining intermediate CA certificates in the chain does not exceed the constraint.
    fn validate_path_length(&self, certificate_chain: &[X509Certificate]) -> Result<(), Error> {
        use x509_parser::extensions::ParsedExtension;

        // Filter only CA certificates from the chain (leaf -> root order)
        let ca_certs: Vec<&X509Certificate> = certificate_chain
            .iter()
            .filter(|cert| cert.is_ca())
            .collect();

        for (chain_idx, certificate) in ca_certs.iter().enumerate() {
            for ext in certificate.extensions() {
                if let ParsedExtension::BasicConstraints(bc) = &ext.parsed_extension()
                    && let Some(path_len_constraint) = bc.path_len_constraint
                {
                    // chain_idx is the number of intermediate CAs that "follow" this certificate_validator
                    let intermediate_cas_following = chain_idx;
                    if (path_len_constraint as usize) < intermediate_cas_following {
                        return Err(Error::BasicConstraintsViolation(format!(
                            "Path length constraint={path_len_constraint}, intermediate CAs count={intermediate_cas_following}"
                        )));
                    }
                }
            }
        }
        Ok(())
    }

    fn validate_root_ca_termination(
        &self,
        certificate_chain: &[X509Certificate],
    ) -> Result<(), Error> {
        let Some(terminating_certificate) = certificate_chain.last() else {
            return Err(Error::InvalidCaCertificateChain(
                "Certificate chain is empty".to_string(),
            ));
        };

        if !terminating_certificate.is_ca() {
            return Err(Error::InvalidCaCertificateChain(
                "Certificate chain does not terminate to a CA".to_string(),
            ));
        };

        if terminating_certificate.issuer() != terminating_certificate.subject() {
            return Err(Error::InvalidCaCertificateChain(
                "Certificate chain does not terminate to a root CA".to_string(),
            ));
        }

        // Verify the self-signed signature to ensure it's a legitimate root CA
        terminating_certificate
            .verify_signature(Some(terminating_certificate.public_key()))
            .map_err(|_| Error::CertificateSignatureInvalid)?;

        Ok(())
    }

    fn check_validity_with_leeway(
        &self,
        cert: &X509Certificate,
        leeway: Duration,
    ) -> Result<(), Error> {
        let now = self.clock.now_utc();
        if ASN1Time::from(now + leeway) < cert.validity.not_before {
            return Err(Error::CertificateNotYetValid);
        }

        if ASN1Time::from(now - leeway) > cert.validity.not_after {
            return Err(Error::CertificateExpired);
        }

        Ok(())
    }
}

pub(crate) fn extract_leaf_pem_from_chain(pem_chain: &[u8]) -> Result<Pem, Error> {
    let Some(pem) = Pem::iter_from_buffer(pem_chain).next() else {
        return Err(Error::EmptyChain);
    };

    Ok(pem?)
}

pub(crate) fn parse_chain_to_x509_attributes(
    pem_chain: &[u8],
) -> Result<CertificateX509AttributesDTO, Error> {
    let pem = extract_leaf_pem_from_chain(pem_chain)?;

    let x509_cert = pem.parse_x509()?;
    parse_x509_attributes(&x509_cert, &pem.contents)
}

fn get_public_key_type(certificate: &X509Certificate) -> Result<KeyAlgorithmType, Error> {
    Ok(match &certificate.subject_pki.algorithm.algorithm {
        alg if alg == &OID_SIG_ED25519 => KeyAlgorithmType::Eddsa,

        alg if alg == &OID_KEY_TYPE_EC_PUBLIC_KEY => {
            let curve_oid = certificate
                .subject_pki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.as_oid().ok())
                .ok_or(Error::UnsupportedAlgorithm(
                    "EC algorithm missing curve information".to_string(),
                ))?;

            if curve_oid != OID_EC_P256 {
                return Err(Error::UnsupportedAlgorithm(format!(
                    "EC algorithm with unsupported curve. oid: {curve_oid}"
                )));
            }

            KeyAlgorithmType::Ecdsa
        }
        other => {
            return Err(Error::UnsupportedAlgorithm(format!(
                "certificate with unsupported algorithm. oid: {other}"
            )));
        }
    })
}

fn parse_x509_attributes(
    certificate: &X509Certificate,
    der_representation: &[u8],
) -> Result<CertificateX509AttributesDTO, Error> {
    let validity = certificate.validity();

    let fingerprint = SHA256.hash(der_representation)?;

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

/// Tries to connect two certificate_validator chains into a single chain
/// * `leaf_certs` - The chain beginning with a leaf/child certificate_validator
/// * `ca_certs` - The chain beginning with an intermediate CA certificate_validator, potentially ending with a root CA certificate_validator
///
/// The two chains can overlap (e.g. if `leaf_certs` specifies the whole chain already)
///
/// If no match between the two chains are found, it will result in an error
fn connect_chains<'a>(
    leaf_certs: &'a [X509Certificate<'a>],
    ca_certs: &'a [X509Certificate<'a>],
) -> Result<Vec<X509Certificate<'a>>, Error> {
    let Some(first_ca_cert) = ca_certs.first() else {
        return Err(Error::InvalidCaCertificateChain(
            "CA certificate_validator chain is empty".to_string(),
        ));
    };

    let first_ca_subject_key_identifier = subject_key_identifier(first_ca_cert)
        .error_while("parsing subject key identifier")?
        .ok_or(Error::InvalidCaCertificateChain(format!(
            "CA certificate_validator (subject: {}) is missing subject key identifier",
            first_ca_cert.subject
        )))?;

    let mut result = vec![];
    for current in leaf_certs {
        result.push(current.to_owned());

        let matching_with_first_ca = match authority_key_identifier(current)
            .error_while("parsing authority key identifier")?
        {
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

    Err(Error::InvalidCaCertificateChain(
        "Certificate chain incomplete".to_string(),
    ))
}
