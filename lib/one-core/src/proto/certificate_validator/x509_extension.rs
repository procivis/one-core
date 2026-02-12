use x509_parser::der_parser::Oid;
use x509_parser::prelude::{
    AccessDescription, AuthorityKeyIdentifier, CRLDistributionPoint, DistributionPointName,
    ExtendedKeyUsage, FromDer, GeneralName, KeyIdentifier, KeyUsage, ParsedExtension, ReasonFlags,
    X509Certificate, X509Extension, oid_registry,
};
use x509_parser::x509::X509Name;

use super::Error;
use crate::proto::certificate_validator::EnforceKeyUsage;
use crate::service::certificate::dto::CertificateX509ExtensionDTO;

pub(crate) fn parse(extension: &X509Extension) -> Result<CertificateX509ExtensionDTO, Error> {
    let values = match extension.parsed_extension() {
        ParsedExtension::UnsupportedExtension { .. } if extension.critical => {
            return Err(Error::UnknownCriticalExtension(
                extension.oid.to_id_string(),
            ));
        }
        ParsedExtension::AuthorityKeyIdentifier(key_identifier) => {
            parse_authority_key_identifier(key_identifier)
        }
        ParsedExtension::SubjectKeyIdentifier(key_identifier) => {
            vec![parse_key_identifier(key_identifier)]
        }
        ParsedExtension::KeyUsage(key_usage) => parse_key_usage(key_usage),
        ParsedExtension::SubjectAlternativeName(san) => parse_general_names(&san.general_names),
        ParsedExtension::IssuerAlternativeName(ian) => parse_general_names(&ian.general_names),
        ParsedExtension::BasicConstraints(constraints) => {
            vec![format!("Certificate Authority: {}", constraints.ca)]
        }
        ParsedExtension::ExtendedKeyUsage(key_usage) => {
            parse_extended_key_usage(key_usage, extension.value)
        }
        ParsedExtension::CRLDistributionPoints(crl) => crl
            .points
            .iter()
            .flat_map(parse_crl_distribution_point)
            .collect(),
        ParsedExtension::AuthorityInfoAccess(info_access) => info_access
            .accessdescs
            .iter()
            .flat_map(parse_access_description)
            .collect(),
        ParsedExtension::CRLNumber(crl) => vec![format!("{crl:x}")],
        _ => vec![hex::encode(extension.value)],
    };

    Ok(CertificateX509ExtensionDTO {
        oid: extension.oid.to_id_string(),
        value: values.join("\n"),
        critical: extension.critical,
    })
}

/// Fail if found an unknown critical extension
/// <https://www.rfc-editor.org/rfc/rfc5280.html#appendix-B>
pub(crate) fn validate_critical_extensions(certificate: &X509Certificate) -> Result<(), Error> {
    for extension in certificate.extensions() {
        if extension.critical
            && matches!(
                extension.parsed_extension(),
                ParsedExtension::UnsupportedExtension { .. }
            )
        {
            return Err(Error::UnknownCriticalExtension(
                extension.oid.to_id_string(),
            ));
        }
    }

    Ok(())
}

/// Validates certificate is signed properly by the parent CA certificate in the chain.
/// Also performs other consistency checks (parent must be a CA, parent CA cert has to contain correct keyUsage)
pub(crate) fn validate_ca_signature(
    certificate: &X509Certificate,
    parent_ca_certificate: &X509Certificate,
) -> Result<(), Error> {
    validate_ca(parent_ca_certificate)?;
    certificate
        .verify_signature(Some(parent_ca_certificate.public_key()))
        .map_err(|_| Error::CertificateSignatureInvalid)
}

/// Validates certificate has BasicConstraints extension with `ca` set to true and KeyUsage extension with `keyCertSign` set.
pub(crate) fn validate_ca(ca_certificate: &X509Certificate) -> Result<(), Error> {
    if !ca_certificate.is_ca() {
        return Err(Error::InvalidCaCertificateChain(
            "Certificate chain containing non-CA parents".to_string(),
        ));
    };

    validate_ca_key_cert_sign_key_usage(ca_certificate)
}

pub(crate) fn validate_required_cert_key_usage(
    certificate: &X509Certificate,
    required_key_usages: &[EnforceKeyUsage],
) -> Result<(), Error> {
    let key_usage = certificate
        .key_usage()
        .map_err(|e| Error::KeyUsageViolation(e.to_string()))?
        .ok_or(Error::KeyUsageViolation(
            "Leaf certificate_validator missing required Key Usage extension".to_string(),
        ))?;

    for required_key_usage in required_key_usages {
        match required_key_usage {
            EnforceKeyUsage::DigitalSignature => {
                if !key_usage.value.digital_signature() {
                    return Err(Error::KeyUsageViolation(
                        "End-entity certificate_validator missing DigitalSignature usage"
                            .to_string(),
                    ));
                }
            }
            EnforceKeyUsage::KeyCertSign => {
                if !key_usage.value.key_cert_sign() {
                    return Err(Error::KeyUsageViolation(
                        "End-entity certificate_validator missing KeyCertSign usage".to_string(),
                    ));
                }
            }
            EnforceKeyUsage::CRLSign => {
                if !key_usage.value.crl_sign() {
                    return Err(Error::KeyUsageViolation(
                        "End-entity certificate_validator missing CRLSign usage".to_string(),
                    ));
                }
            }
        }
    }

    Ok(())
}

/// Validates key usage constraint `keyCertSign` according to [RFC 5280 section 4.2.1.3](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3)
///
/// CA certificates must declare `keyCertSign` usage if the key is used to sign other certificates (always enforced)
fn validate_ca_key_cert_sign_key_usage(ca_certificate: &X509Certificate) -> Result<(), Error> {
    let key_usage = ca_certificate
        .key_usage()
        .map_err(|e| Error::KeyUsageViolation(e.to_string()))?
        .ok_or(Error::KeyUsageViolation(
            "CA certificate_validator missing Key Usage extension".to_string(),
        ))?;

    // The keyCertSign bit is asserted when the subject public key is used for verifying signatures on public key certificates
    if !key_usage.value.key_cert_sign() {
        return Err(Error::KeyUsageViolation(
            "CA certificate_validator missing keyCertSign usage".to_string(),
        ));
    }

    Ok(())
}

fn parse_authority_key_identifier(key_identifier: &AuthorityKeyIdentifier) -> Vec<String> {
    let mut result = vec![];
    if let Some(authority_cert_issuer) = &key_identifier.authority_cert_issuer {
        result.extend(parse_general_names(authority_cert_issuer));
    }
    if let Some(authority_cert_serial) = &key_identifier.authority_cert_serial {
        result.push(format!("Serial: {}", hex::encode(authority_cert_serial)));
    }
    if let Some(key_identifier) = &key_identifier.key_identifier {
        result.push(parse_key_identifier(key_identifier));
    }
    result
}

fn parse_general_names(names: &[GeneralName]) -> Vec<String> {
    names.iter().map(|name| format!("{name}")).collect()
}

fn parse_key_identifier(key_identifier: &KeyIdentifier) -> String {
    format!("Key ID: {key_identifier:x}")
}

fn parse_key_usage(key_usage: &KeyUsage) -> Vec<String> {
    let mut result = vec![];
    if key_usage.digital_signature() {
        result.push("digitalSignature".to_string());
    }
    if key_usage.non_repudiation() {
        result.push("nonRepudiation".to_string());
    }
    if key_usage.key_encipherment() {
        result.push("keyEncipherment".to_string());
    }
    if key_usage.data_encipherment() {
        result.push("dataEncipherment".to_string());
    }
    if key_usage.key_agreement() {
        result.push("keyAgreement".to_string());
    }
    if key_usage.key_cert_sign() {
        result.push("keyCertSign".to_string());
    }
    if key_usage.crl_sign() {
        result.push("crlSign".to_string());
    }
    if key_usage.encipher_only() {
        result.push("encipherOnly".to_string());
    }
    if key_usage.decipher_only() {
        result.push("decipherOnly".to_string());
    }
    result
}

fn parse_extended_key_usage(_key_usage: &ExtendedKeyUsage, der: &[u8]) -> Vec<String> {
    if let Ok((_, seq)) = <Vec<Oid>>::from_der(der) {
        seq.iter().map(|oid| oid.to_id_string()).collect()
    } else {
        vec![]
    }
}

fn parse_crl_distribution_point(point: &CRLDistributionPoint) -> Vec<String> {
    let mut result = vec![];
    if let Some(crl_issuer) = &point.crl_issuer {
        result.extend(parse_general_names(crl_issuer));
    }
    if let Some(distribution_point) = &point.distribution_point {
        match distribution_point {
            DistributionPointName::FullName(general_names) => {
                result.extend(parse_general_names(general_names));
            }
            DistributionPointName::NameRelativeToCRLIssuer(relative_distinguished_name) => {
                let dummy = vec![];
                let name = X509Name::new(vec![relative_distinguished_name.to_owned()], &dummy);
                if let Ok(name) = name.to_string_with_registry(oid_registry()) {
                    result.push(format!("RelativeToCRLIssuer: {name}"));
                }
            }
        }
    }
    if let Some(reasons) = &point.reasons {
        result.push(format!(
            "Reasons: {}",
            parse_crl_reasons(reasons).join(", ")
        ));
    }
    result
}

fn parse_crl_reasons(reasons: &ReasonFlags) -> Vec<String> {
    let mut result = vec![];
    if reasons.key_compromise() {
        result.push("keyCompromise".to_string());
    }
    if reasons.ca_compromise() {
        result.push("caCompromise".to_string());
    }
    if reasons.affilation_changed() {
        result.push("affilationChanged".to_string());
    }
    if reasons.superseded() {
        result.push("superseded".to_string());
    }
    if reasons.cessation_of_operation() {
        result.push("cessationOfOperation".to_string());
    }
    if reasons.certificate_hold() {
        result.push("certificateHold".to_string());
    }
    if reasons.privelege_withdrawn() {
        result.push("privelegeWithdrawn".to_string());
    }
    if reasons.aa_compromise() {
        result.push("aaCompromise".to_string());
    }
    result
}

fn parse_access_description(description: &AccessDescription) -> Vec<String> {
    vec![
        description.access_method.to_id_string(),
        format!("{}", description.access_location),
    ]
}
