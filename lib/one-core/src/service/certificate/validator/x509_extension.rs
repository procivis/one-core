use x509_parser::der_parser::Oid;
use x509_parser::prelude::{
    AccessDescription, AuthorityKeyIdentifier, CRLDistributionPoint, DistributionPointName,
    ExtendedKeyUsage, FromDer, GeneralName, KeyIdentifier, KeyUsage, ParsedExtension, ReasonFlags,
    X509Certificate, X509Extension, oid_registry,
};
use x509_parser::x509::X509Name;

use crate::service::certificate::dto::CertificateX509ExtensionDTO;
use crate::service::certificate::validator::EnforceKeyUsage;
use crate::service::error::ValidationError;

pub(super) fn parse(
    extension: &X509Extension,
) -> Result<CertificateX509ExtensionDTO, ValidationError> {
    let values = match extension.parsed_extension() {
        ParsedExtension::UnsupportedExtension { .. } if extension.critical => {
            return Err(ValidationError::UnknownCriticalExtension(
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

/// Validates key usage constraints according to RFC 5280 section 4.2.1.3
/// CA certificates must have keyCertSign usage (always enforced)
/// End-entity certificates:
/// If required_end_entity_key_usages is Some, the key usage extension must be present and contain the specified usages
/// If required_end_entity_key_usages is None, the key usage extension is optional
pub(super) fn validate_key_usage(
    certificate: &X509Certificate,
    required_end_entity_key_usages: &Option<Vec<EnforceKeyUsage>>,
) -> Result<(), ValidationError> {
    let key_usage = certificate
        .key_usage()
        .map_err(|e| ValidationError::KeyUsageViolation(e.to_string()))?;

    // Always validate CA certificates regardless of the enforcement flag
    if certificate.is_ca() {
        let key_usage = key_usage.ok_or(ValidationError::KeyUsageViolation(
            "CA certificate missing Key Usage extension".to_string(),
        ))?;

        if !key_usage.value.key_cert_sign() {
            return Err(ValidationError::KeyUsageViolation(
                "CA certificate missing keyCertSign usage".to_string(),
            ));
        }
    } else {
        match (required_end_entity_key_usages, key_usage) {
            // If required_end_entity_key_usages is Some, the key usage extension must be present and contain the specified usages
            (Some(required_key_usages), Some(key_usage)) => {
                for required_key_usage in required_key_usages {
                    match required_key_usage {
                        EnforceKeyUsage::DigitalSignature => {
                            if !key_usage.value.digital_signature() {
                                return Err(ValidationError::KeyUsageViolation(
                                    "End-entity certificate missing DigitalSignature usage"
                                        .to_string(),
                                ));
                            }
                        }
                    }
                }
            }
            (Some(_), None) => {
                return Err(ValidationError::KeyUsageViolation(
                    "End-entity certificate missing Key Usage extension".to_string(),
                ));
            }
            // If required_end_entity_key_usages is None, the key usage extension is optional
            (None, _) => {}
        }
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
