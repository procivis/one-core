use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::ParsedExtension;
use x509_parser::oid_registry::{
    OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER, OID_X509_EXT_SUBJECT_KEY_IDENTIFIER,
};

use crate::service::error::ValidationError;

pub(crate) fn subject_key_identifier(
    cert: &X509Certificate,
) -> Result<Option<String>, ValidationError> {
    Ok(cert
        .get_extension_unique(&OID_X509_EXT_SUBJECT_KEY_IDENTIFIER)
        .map_err(|err| {
            ValidationError::CertificateParsingFailed(format!(
                "failed to get subject key identifier: {err}"
            ))
        })?
        .map(|ext| ext.parsed_extension())
        .map(|ext| match ext {
            ParsedExtension::SubjectKeyIdentifier(key_identifier) => Ok(key_identifier),
            _ => Err(ValidationError::CertificateParsingFailed(
                "Encountered unexpected extension while looking for subject key identifier"
                    .to_string(),
            )),
        })
        .transpose()?
        .map(|key_id| format!("{key_id:x}")))
}

pub(crate) fn authority_key_identifier(
    cert: &X509Certificate,
) -> Result<Option<String>, ValidationError> {
    Ok(cert
        .get_extension_unique(&OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER)
        .map_err(|err| {
            ValidationError::CertificateParsingFailed(format!(
                "failed to get subject key identifier: {err}"
            ))
        })?
        .map(|ext| ext.parsed_extension())
        .map(|ext| match ext {
            ParsedExtension::AuthorityKeyIdentifier(key_identifier) => Ok(key_identifier),
            _ => Err(ValidationError::CertificateParsingFailed(
                "Encountered unexpected extension while looking for subject key identifier"
                    .to_string(),
            )),
        })
        .transpose()?
        .map(|key_identifier| {
            key_identifier
                .key_identifier
                .as_ref()
                .ok_or(ValidationError::CertificateParsingFailed(
                    "Mising authority key identifier".to_string(),
                ))
        })
        .transpose()?
        .map(|key_id| format!("{key_id:x}")))
}

pub(crate) fn is_dns_name_matching(dns_def: &str, target_domain: &str) -> bool {
    // https://datatracker.ietf.org/doc/html/rfc1034#section-4.3.3
    if let Some(wildcard_domain) = dns_def.strip_prefix("*") {
        target_domain.ends_with(wildcard_domain)
    } else {
        // simple case
        dns_def == target_domain
    }
}

#[cfg(test)]
mod tests {
    use similar_asserts::assert_eq;
    use x509_parser::pem::parse_x509_pem;

    use super::*;

    #[test]
    fn test_authority_key_identifier() {
        let pem = "-----BEGIN CERTIFICATE-----
MIIBODCB66ADAgECAhQjDWW20goQ5ZYZHnUYjgEAtpYAxjAFBgMrZXAwEjEQMA4G
A1UEAwwHQ0EgY2VydDAeFw0yMzA3MjgxMzA5MDhaFw0zNTAxMjYxMzA5MDhaMBIx
EDAOBgNVBAMMB0NBIGNlcnQwKjAFBgMrZXADIQBKBEnJk+6LyU8tcMSYIw8mvo06
E2W4JVTSZRP1JavvX6NTMFEwHwYDVR0jBBgwFoAUYSDrfq7B9LW8JqFf8Goypix1
9fswHQYDVR0OBBYEFGEg636uwfS1vCahX/BqMqYsdfX7MA8GA1UdEwEB/wQFMAMB
Af8wBQYDK2VwA0EAia2OnNqDv08Y8X6r1e7iBsgYsEa6V2Df65WDMKd/8LHCuhvL
GsPNAYTwQu1egNMnoBk0k0cwNJCBJmS3zEGaDw==
-----END CERTIFICATE-----";

        let (_, pem) = parse_x509_pem(pem.as_bytes()).unwrap();
        let cert = pem.parse_x509().unwrap();
        let identifier = authority_key_identifier(&cert).unwrap().unwrap();
        assert_eq!(
            identifier,
            "61:20:eb:7e:ae:c1:f4:b5:bc:26:a1:5f:f0:6a:32:a6:2c:75:f5:fb"
        );
    }
}
