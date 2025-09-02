use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use x509_parser::oid_registry::{OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY, OID_SIG_ED25519};
use x509_parser::pem::Pem;
use x509_parser::prelude::{ASN1Time, X509Certificate};

use super::{CertificateValidator, CertificateValidatorImpl, ParsedCertificate, x509_extension};
use crate::config::core_config::KeyAlgorithmType;
use crate::model::certificate::CertificateState;
use crate::provider::key_algorithm::error::KeyAlgorithmProviderError;
use crate::provider::key_algorithm::key::KeyHandle;
use crate::service::certificate::dto::CertificateX509AttributesDTO;
use crate::service::certificate::validator::CertificateValidationOptions;
use crate::service::certificate::validator::x509_extension::validate_key_usage;
use crate::service::error::{MissingProviderError, ServiceError, ValidationError};
use crate::util::x509::{authority_key_identifier, subject_key_identifier};

#[async_trait::async_trait]
impl CertificateValidator for CertificateValidatorImpl {
    async fn parse_pem_chain(
        &self,
        pem_chain: &[u8],
        validation_context: CertificateValidationOptions,
    ) -> Result<ParsedCertificate, ServiceError> {
        let mut result: Option<ParsedCertificate> = None;

        let items = Pem::iter_from_buffer(pem_chain)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| ValidationError::CertificateParsingFailed(err.to_string()))?;

        let certs = items
            .iter()
            .map(|pem| pem.parse_x509())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| ValidationError::CertificateParsingFailed(err.to_string()))?;

        for (current, next) in certs
            .iter()
            .zip(certs.iter().skip(1).map(Some).chain(std::iter::once(None)))
        {
            validate_key_usage(current)?;
            if result.is_none() {
                let subject_common_name = current
                    .subject
                    .iter_common_name()
                    .next()
                    .and_then(|cn| cn.as_str().ok())
                    .map(ToString::to_string);

                let res = ParsedCertificate {
                    attributes: parse_x509_attributes(current)?,
                    subject_common_name,
                    subject_key_identifier: subject_key_identifier(current)?,
                    public_key: self.extract_public_key(current)?,
                };
                if validation_context.validity_check {
                    result = Some(res);
                } else {
                    return Ok(res);
                }
            }

            if validation_context.require_root_termination {
                self.validate_root_ca_termination(&certs)?;
            }

            if validation_context.validate_path_length {
                self.validate_path_length(&certs)?;
            }

            if !current
                .validity()
                .is_valid_at(ASN1Time::from(self.clock.now_utc()))
            {
                return Err(ValidationError::CertificateNotValid.into());
            }

            if let Some(next) = next {
                // parent entry in the chain, validate signature
                current
                    .verify_signature(Some(next.public_key()))
                    .map_err(|_| ValidationError::CertificateSignatureInvalid)?;
            }

            let revoked = self.check_revocation(current, next).await?;
            if revoked {
                return Err(ValidationError::CertificateRevoked.into());
            }
        }

        result.ok_or(
            ValidationError::CertificateParsingFailed("No certificates specified".to_string())
                .into(),
        )
    }

    async fn parse_pem_chain_with_status(
        &self,
        pem_chain: &[u8],
    ) -> Result<(CertificateState, ParsedCertificate), ServiceError> {
        let mut result: Option<ParsedCertificate> = None;

        let items = Pem::iter_from_buffer(pem_chain)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| ValidationError::CertificateParsingFailed(err.to_string()))?;

        let certs = items
            .iter()
            .map(|pem| pem.parse_x509())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| ValidationError::CertificateParsingFailed(err.to_string()))?;

        for (current, next) in certs
            .iter()
            .zip(certs.iter().skip(1).map(Some).chain(std::iter::once(None)))
        {
            if result.is_none() {
                let subject_common_name = current
                    .subject
                    .iter_common_name()
                    .next()
                    .and_then(|cn| cn.as_str().ok())
                    .map(ToString::to_string);

                let res = ParsedCertificate {
                    attributes: parse_x509_attributes(current)?,
                    subject_common_name,
                    subject_key_identifier: subject_key_identifier(current)?,
                    public_key: self.extract_public_key(current)?,
                };
                result = Some(res);
            }

            let now = ASN1Time::from(self.clock.now_utc());
            if !current.validity().is_valid_at(now) {
                let result = result.ok_or(ValidationError::CertificateParsingFailed(
                    "No certificates specified".to_string(),
                ))?;

                return if now < current.validity.not_before {
                    Ok((CertificateState::NotYetActive, result))
                } else {
                    Ok((CertificateState::Expired, result))
                };
            }

            if let Some(next) = next {
                // parent entry in the chain, validate signature
                current
                    .verify_signature(Some(next.public_key()))
                    .map_err(|_| ValidationError::CertificateSignatureInvalid)?;
            }

            let revoked = self.check_revocation(current, next).await?;
            if revoked {
                let result = result.ok_or(ValidationError::CertificateParsingFailed(
                    "No certificates specified".to_string(),
                ))?;
                return Ok((CertificateState::Revoked, result));
            }
        }

        let result = result.ok_or(ValidationError::CertificateParsingFailed(
            "No certificates specified".to_string(),
        ))?;
        Ok((CertificateState::Active, result))
    }

    async fn validate_chain_against_ca_chain(
        &self,
        pem_chain: &[u8],
        ca_pem_chain: &[u8],
    ) -> Result<ParsedCertificate, ServiceError> {
        let pems = Pem::iter_from_buffer(pem_chain)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| ValidationError::CertificateParsingFailed(err.to_string()))?;
        let ca_pems = Pem::iter_from_buffer(ca_pem_chain)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| ValidationError::CertificateParsingFailed(err.to_string()))?;
        let ca_cert = self
            .validate_chain_against_ca_chain_inner(&ca_pems, &pems)
            .await?;
        let subject_common_name = ca_cert
            .subject
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .map(ToString::to_string);
        Ok(ParsedCertificate {
            attributes: parse_x509_attributes(&ca_cert)?,
            subject_common_name,
            subject_key_identifier: subject_key_identifier(&ca_cert)?,
            public_key: self.extract_public_key(&ca_cert)?,
        })
    }

    async fn validate_der_chain_against_ca(
        &self,
        der_chain: Vec<Vec<u8>>,
        ca_pem: &str,
    ) -> Result<ParsedCertificate, ServiceError> {
        let pems = der_chain
            .into_iter()
            .map(|contents| Pem {
                label: "CERTIFICATE".to_string(),
                contents,
            })
            .collect::<Vec<_>>();
        let Some(leaf_pem) = pems.first() else {
            return Err(ValidationError::CertificateParsingFailed(
                "der_chain is empty".to_string(),
            )
            .into());
        };
        let ca_pems = Pem::iter_from_buffer(ca_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| ValidationError::CertificateParsingFailed(err.to_string()))?;
        self.validate_chain_against_ca_chain_inner(&ca_pems, &pems)
            .await?;
        let parsed_cert = leaf_pem
            .parse_x509()
            .map_err(|err| ValidationError::CertificateParsingFailed(err.to_string()))?;

        let subject_common_name = parsed_cert
            .subject
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .map(ToString::to_string);

        Ok(ParsedCertificate {
            attributes: parse_x509_attributes(&parsed_cert)?,
            subject_common_name,
            subject_key_identifier: subject_key_identifier(&parsed_cert)?,
            public_key: self.extract_public_key(&parsed_cert)?,
        })
    }
}

impl CertificateValidatorImpl {
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

    async fn validate_chain_against_ca_chain_inner<'a>(
        &self,
        ca_pems: &'a [Pem],
        pems: &[Pem],
    ) -> Result<X509Certificate<'a>, ServiceError> {
        let certs = pems
            .iter()
            .map(|pem| pem.parse_x509())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| ValidationError::CertificateParsingFailed(err.to_string()))?;

        let mut ca_certs = ca_pems
            .iter()
            .map(|pem| pem.parse_x509())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| ValidationError::CertificateParsingFailed(err.to_string()))?;

        self.validate_path_length(&ca_certs)?;
        self.validate_root_ca_termination(&ca_certs)?;

        let Some(first_ca_cert) = ca_certs.first() else {
            return Err(ValidationError::InvalidCaCertificateChain(
                "CA certificate chain is empty".to_string(),
            )
            .into());
        };

        let first_ca_subject_key_identifier = subject_key_identifier(first_ca_cert)?.ok_or(
            ValidationError::InvalidCaCertificateChain(format!(
                "CA certificate (subject: {}) is missing subject key identifier",
                first_ca_cert.subject
            )),
        )?;

        // whether we have already switched to iterating over the certs in the CA chain
        let mut is_ca_chain = false;
        let mut chain = certs.iter().peekable();
        while let Some(current_cert) = chain.next() {
            validate_key_usage(current_cert)?;
            if !current_cert
                .validity()
                .is_valid_at(ASN1Time::from(self.clock.now_utc()))
            {
                return Err(ValidationError::CertificateNotValid.into());
            }

            // This is the root CA
            // signature is already validated in validate_root_ca_termination
            if is_ca_chain && current_cert.is_ca() && chain.peek().is_none() {
                self.check_revocation(current_cert, Some(current_cert))
                    .await?;

                return Ok(ca_certs.swap_remove(0));
            };

            let mut sig_validated = false;
            // Non-CA certificates might provide an authority key identifier to more easily find
            // matching CA cert.
            if let Some(authority_key_identifier) = authority_key_identifier(current_cert)?
                && authority_key_identifier == first_ca_subject_key_identifier
            {
                // parent of the current cert is first CA cert -> switch chain to CA cert chain
                chain = ca_certs.iter().peekable();
                is_ca_chain = true;
            }
            // no authority key identifier was provided, we have to check by attempting to verify the signature
            else if current_cert
                .verify_signature(Some(first_ca_cert.public_key()))
                .is_ok()
            {
                // parent of the current cert is first CA cert -> switch chain to CA cert chain
                chain = ca_certs.iter().peekable();
                is_ca_chain = true;
                sig_validated = true;
            };

            let parent_cert = chain
                .peek()
                .ok_or(ValidationError::InvalidCaCertificateChain(
                    "Certificate chain incomplete".to_string(),
                ))?;
            // If we matched the parent by checking the signature, then there is no point in checking again.
            if !sig_validated {
                current_cert
                    .verify_signature(Some(parent_cert.public_key()))
                    .map_err(|_| ValidationError::CertificateSignatureInvalid)?;
            }
            let revoked = self
                .check_revocation(current_cert, Some(parent_cert))
                .await?;
            if revoked {
                return Err(ValidationError::CertificateRevoked.into());
            }
        }
        Err(
            ValidationError::InvalidCaCertificateChain("Certificate chain is empty".to_string())
                .into(),
        )
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
