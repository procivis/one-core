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
use crate::service::error::{MissingProviderError, ServiceError, ValidationError};

#[async_trait::async_trait]
impl CertificateValidator for CertificateValidatorImpl {
    async fn parse_pem_chain(
        &self,
        pem_chain: &[u8],
        validate: bool,
    ) -> Result<ParsedCertificate, ServiceError> {
        let mut result: Option<ParsedCertificate> = None;

        let items = Pem::iter_from_buffer(pem_chain)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| ValidationError::CertificateParsingFailed(err.to_string()))?;

        let certs = items
            .iter()
            .map(|pem| match pem.parse_x509() {
                Ok(parsed) => Ok((parsed, pem)),
                Err(err) => Err(err),
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| ValidationError::CertificateParsingFailed(err.to_string()))?;

        for ((current, current_pem), (next, _)) in certs.iter().zip(
            certs
                .iter()
                .skip(1)
                .map(|(cert, pem)| (Some(cert), Some(pem)))
                .chain(std::iter::once((None, None))),
        ) {
            if result.is_none() {
                let subject_common_name = current
                    .subject
                    .iter_common_name()
                    .next()
                    .and_then(|cn| cn.as_str().ok())
                    .map(ToString::to_string);

                let res = ParsedCertificate {
                    attributes: parse_x509_attributes(current, &current_pem.contents)?,
                    subject_common_name,
                    public_key: self.extract_public_key(current)?,
                };
                if validate {
                    result = Some(res);
                } else {
                    return Ok(res);
                }
            }

            if !current.validity().is_valid() {
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
            .map(|pem| match pem.parse_x509() {
                Ok(parsed) => Ok((parsed, pem)),
                Err(err) => Err(err),
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| ValidationError::CertificateParsingFailed(err.to_string()))?;

        for ((current, current_pem), (next, _)) in certs.iter().zip(
            certs
                .iter()
                .skip(1)
                .map(|(cert, pem)| (Some(cert), Some(pem)))
                .chain(std::iter::once((None, None))),
        ) {
            if result.is_none() {
                let subject_common_name = current
                    .subject
                    .iter_common_name()
                    .next()
                    .and_then(|cn| cn.as_str().ok())
                    .map(ToString::to_string);

                let res = ParsedCertificate {
                    attributes: parse_x509_attributes(current, &current_pem.contents)?,
                    subject_common_name,
                    public_key: self.extract_public_key(current)?,
                };
                result = Some(res);
            }

            let now = ASN1Time::now();
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
    parse_x509_attributes(&x509_cert, &pem.contents)
}

fn parse_x509_attributes(
    certificate: &X509Certificate,
    der: &[u8],
) -> Result<CertificateX509AttributesDTO, ValidationError> {
    let validity = certificate.validity();

    let fingerprint = SHA256
        .hash(der)
        .map_err(|err| ValidationError::CertificateParsingFailed(err.to_string()))?;

    let extensions = certificate
        .extensions()
        .iter()
        .map(x509_extension::parse)
        .collect();

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
