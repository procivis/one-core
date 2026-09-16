use asn1_rs::{FromDer, Tag, TaggedExplicit};
use standardized_types::etsi_119_475::access_certificate::CertificatePolicy;
use standardized_types::x509::oid;
use url::Url;
use x509_parser::extensions::GeneralName;
use x509_parser::oid_registry::{
    OID_X509_EXT_CERTIFICATE_POLICIES, OID_X509_EXT_SUBJECT_ALT_NAME, OID_X509_SERIALNUMBER,
};
use x509_parser::pem::Pem;
use x509_parser::prelude::ParsedExtension;

use crate::error::{ContextWithErrorCode, ErrorCode, ErrorCodeMixin, NestedError};
use crate::mapper::x509::parse_oid;

#[derive(Debug, thiserror::Error)]
pub(crate) enum AccessCertParsingError {
    #[error("Missing organisation identifier")]
    MissingOrganisationIdentifier,
    #[error("Missing country")]
    MissingCountry,
    #[error("Invalid phone nr: `{0}`")]
    InvalidPhoneNr(String),

    #[error("Missing subject alternative name extension")]
    MissingSubjectAlternativeName,
    #[error("No certificates specified in the chain")]
    EmptyChain,
    #[error("PEM error: `{0}`")]
    PEMError(#[from] x509_parser::error::PEMError),
    #[error("X509 nom error: `{0}`")]
    X509NomError(#[from] x509_parser::nom::Err<x509_parser::error::X509Error>),
    #[error("X509 error: `{0}`")]
    X509ParserError(#[from] x509_parser::error::X509Error),

    #[error("URL parsing error: `{0}`")]
    URLParsing(#[from] url::ParseError),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for AccessCertParsingError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::EmptyChain
            | Self::MissingOrganisationIdentifier
            | Self::PEMError(_)
            | Self::X509NomError(_)
            | Self::MissingCountry
            | Self::InvalidPhoneNr(_)
            | Self::MissingSubjectAlternativeName
            | Self::X509ParserError(_) => ErrorCode::BR_0487,
            Self::URLParsing(_) => ErrorCode::BR_0047,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EtsiParsedAccessCert {
    pub rp_id: String,
    pub support_uri: Option<Url>,
    pub country: String,
    pub common_name: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub registry_url: Option<Url>,
}

pub(crate) fn etsi_access_cert_from_pem_chain(
    pem_chain: &str,
) -> Result<EtsiParsedAccessCert, AccessCertParsingError> {
    let leaf_pem = Pem::iter_from_buffer(pem_chain.as_bytes())
        .next()
        .ok_or(AccessCertParsingError::EmptyChain)??;

    let certificate = leaf_pem.parse_x509()?;

    let policies = certificate
        .get_extension_unique(&OID_X509_EXT_CERTIFICATE_POLICIES)?
        .ok_or(AccessCertParsingError::MissingOrganisationIdentifier)?;
    let ParsedExtension::CertificatePolicies(policies) = policies.parsed_extension() else {
        return Err(AccessCertParsingError::MissingOrganisationIdentifier);
    };
    let policy = policies.iter().find_map(|policy| {
        CertificatePolicy::from_oid(&policy.policy_id.iter()?.collect::<Vec<_>>())
    });

    let subject = certificate.subject();
    let rp_id = match policy {
        // ETSI 119 475 Table 3: identifier (natural person) → serialNumber (clause 5.1.5)
        Some(CertificatePolicy::NaturalPerson) => {
            subject.iter_by_oid(&OID_X509_SERIALNUMBER).next()
        }
        // ETSI 119 475 Table 1: identifier (legal person) → organizationIdentifier (clause 5.1.3)
        Some(CertificatePolicy::LegalPerson) => subject
            .iter_by_oid(
                &parse_oid(oid::attribute::ORGANIZATION_IDENTIFIER)
                    .error_while("parsing organizationIdentifier OID")?,
            )
            .next(),
        None => {
            return Err(AccessCertParsingError::MissingOrganisationIdentifier);
        }
    }
    .ok_or(AccessCertParsingError::MissingOrganisationIdentifier)?
    .as_str()?
    .to_string();

    let country = subject
        .iter_country()
        .next()
        .ok_or(AccessCertParsingError::MissingCountry)?
        .as_str()?
        .to_string();

    let common_name = subject
        .iter_common_name()
        .next()
        .map(|cn| cn.as_str())
        .transpose()?
        .map(String::from);

    let san = certificate
        .get_extension_unique(&OID_X509_EXT_SUBJECT_ALT_NAME)?
        .ok_or(AccessCertParsingError::MissingSubjectAlternativeName)?;
    let ParsedExtension::SubjectAlternativeName(san) = san.parsed_extension() else {
        return Err(AccessCertParsingError::MissingSubjectAlternativeName);
    };
    let support_uri = san
        .general_names
        .iter()
        .find_map(|general_name| match general_name {
            GeneralName::URI(support_uri) => Some(support_uri),
            _ => None,
        })
        .map(|support_uri| Url::parse(support_uri))
        .transpose()?;
    let email = san
        .general_names
        .iter()
        .find_map(|general_name| match general_name {
            GeneralName::RFC822Name(email) => Some(email.to_string()),
            _ => None,
        });
    let phone_oid =
        parse_oid(oid::attribute::TELEPHONE_NUMBER).error_while("parsing telephoneNumber OID")?;
    let phone = san
        .general_names
        .iter()
        .find_map(|general_name| match general_name {
            GeneralName::OtherName(oid, data) if *oid == phone_oid => Some(parse_phone_nr(data)),
            _ => None,
        })
        .transpose()?;

    let content_url_oid =
        parse_oid(oid::attribute::CONTENT_URL).error_while("parsing contentUrl OID")?;
    let registry_url = if let Some(entry) = subject.iter_by_oid(&content_url_oid).next() {
        Some(Url::parse(entry.as_str()?)?)
    } else {
        None
    };

    Ok(EtsiParsedAccessCert {
        rp_id,
        registry_url,
        support_uri,
        country,
        common_name,
        email,
        phone,
    })
}

fn parse_phone_nr(data: &[u8]) -> Result<String, AccessCertParsingError> {
    let (_, other_name) = TaggedExplicit::<asn1_rs::Any, _, 0>::from_der(data).map_err(|err| {
        AccessCertParsingError::InvalidPhoneNr(format!("DER parsing failure: {err}"))
    })?;
    let other_name = other_name.into_inner();

    let other_name_value = match other_name.tag() {
        Tag::Utf8String => std::str::from_utf8(other_name.data)
            .map_err(|_| AccessCertParsingError::InvalidPhoneNr("Invalid UTF-8 string".to_owned()))?
            .to_owned(),

        tag => {
            return Err(AccessCertParsingError::InvalidPhoneNr(format!(
                "Invalid other name type: {tag}"
            )));
        }
    };
    Ok(other_name_value)
}

#[cfg(test)]
mod tests {
    use similar_asserts::assert_eq;
    use url::Url;

    use super::{EtsiParsedAccessCert, etsi_access_cert_from_pem_chain};

    const NATURAL_PERSON: &str = r#"-----BEGIN CERTIFICATE-----
MIIDAzCCAqugAwIBAgIRAfgZjZvWyEMdh9hZcC5L3vUwCgYIKoZIzj0EAwIwEjEQ
MA4GA1UEAwwHQ0EgY2VydDAeFw0yNjA0MDkwODQ1NThaFw0zMTA0MDgwODQ1NTha
MHExCzAJBgNVBAYMAkNIMR0wGwYDVQRRDBRodHRwczovL3NvbWUtdXJsLmNvbTEU
MBIGA1UEAwwLY29tbW9uIG5hbWUxDjAMBgNVBAUMBW9yZ0lkMQwwCgYDVQQqDANN
YXgxDzANBgNVBAQMBk11c3RlcjAqMAUGAytlcAMhAEoEScmT7ovJTy1wxJgjDya+
jToTZbglVNJlE/Ulq+9fo4IBsDCCAawwHwYDVR0jBBgwFoAUNyjNsnb8v1K0L0Bt
EPf0uTxrQuAwRgYDVR0RBD8wPYYUaHR0cHM6Ly9zb21lLXVyaS5jb22gFAYDVQQU
oA0MCys0MTIzNDU2Nzg5gQ90ZXN0ZXJAdGVzdC5jb20wDgYDVR0PAQH/BAQDAgOI
MCUGA1UdJQQeMBwGCCsGAQUFBwMCBgcogYxdBQEGBgcogbU0BAEGMGIGA1UdHwRb
MFkwV6BVoFOGUWh0dHA6Ly8xMjcuMC4wLjE6NjEzNTgvc3NpL3Jldm9jYXRpb24v
djEvY3JsLzg2ZjY4NTdjLTRlNGQtNDNiZC04NzliLWZiYTUyMjA2N2VlZjAdBgNV
HQ4EFgQUYSDrfq7B9LW8JqFf8Goypix19fswDwYDVR0TAQH/BAUwAwEBADAUBgNV
HSAEDTALMAkGBwQAi+xAAQAwYAYIKwYBBQUHAQEEVDBSMFAGCCsGAQUFBzACpkQW
Qmh0dHA6Ly8xMjcuMC4wLjE6NjEzNTgvc3NpL2NhLzMwMzc0M2UxLTYzYzctNDAz
My05OTUwLWRkZGU2ZTQxN2UyOTAKBggqhkjOPQQDAgNGADBDAiAOXUDvoNYh6os0
MET+cTAhlpnzMZzZciWyRY7poIhybgIfNaBOINmvSSI6tZZZzdp+cQswXKlhYnC4
15XEHVrAsA==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBiTCCAS+gAwIBAgIUEiXvMbJt3TJwCJ56URr8IqLUqeowCgYIKoZIzj0EAwIw
EjEQMA4GA1UEAwwHQ0EgY2VydDAeFw0yNDA1MDkwODQ1NThaFw0zNTExMDgwODQ1
NThaMBIxEDAOBgNVBAMMB0NBIGNlcnQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AARx38tO0JCdq3ZecMSW6a+BAAzllydQxVOQ+KDjnwLXJ4mkJj1IIq/NCNlwhap9
vyj6nVh9D8TMwgj/Ft7j8ZVAo2MwYTAfBgNVHSMEGDAWgBQ3KM2ydvy/UrQvQG0Q
9/S5PGtC4DAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFDcozbJ2/L9StC9AbRD3
9Lk8a0LgMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIgBbQUKzrX
fQ0/dtdRF6pNnX+uPATW5lz0SKX5VmzrJA0CIQCHG/0OYHHvkyfsKay0BnIpEBEc
4goBKclrxu4HRPWr/Q==
-----END CERTIFICATE-----"#;

    const LEGAL_PERSON: &str = r#"-----BEGIN CERTIFICATE-----
MIIC+jCCAp+gAwIBAgIRAQrC1dwJkUxlszrpRjXZv+QwCgYIKoZIzj0EAwIwEjEQ
MA4GA1UEAwwHQ0EgY2VydDAeFw0yNjA0MDkwODQzMDhaFw0zMTA0MDgwODQzMDha
MGUxCzAJBgNVBAYMAkNIMR0wGwYDVQRRDBRodHRwczovL3NvbWUtdXJsLmNvbTEU
MBIGA1UEAwwLY29tbW9uIG5hbWUxDjAMBgNVBGEMBW9yZ0lkMREwDwYDVQQKDAhP
cmcgbmFtZTAqMAUGAytlcAMhAEoEScmT7ovJTy1wxJgjDya+jToTZbglVNJlE/Ul
q+9fo4IBsDCCAawwHwYDVR0jBBgwFoAUNyjNsnb8v1K0L0BtEPf0uTxrQuAwRgYD
VR0RBD8wPYYUaHR0cHM6Ly9zb21lLXVyaS5jb22gFAYDVQQUoA0MCys0MTIzNDU2
Nzg5gQ90ZXN0ZXJAdGVzdC5jb20wDgYDVR0PAQH/BAQDAgOIMCUGA1UdJQQeMBwG
CCsGAQUFBwMCBgcogYxdBQEGBgcogbU0BAEGMGIGA1UdHwRbMFkwV6BVoFOGUWh0
dHA6Ly8xMjcuMC4wLjE6NjEzNDYvc3NpL3Jldm9jYXRpb24vdjEvY3JsLzJiYzE2
MjllLWM2YWItNGNlNy1hMTlkLWYwN2Q1M2YwYzU3NzAdBgNVHQ4EFgQUYSDrfq7B
9LW8JqFf8Goypix19fswDwYDVR0TAQH/BAUwAwEBADAUBgNVHSAEDTALMAkGBwQA
i+xAAQEwYAYIKwYBBQUHAQEEVDBSMFAGCCsGAQUFBzACpkQWQmh0dHA6Ly8xMjcu
MC4wLjE6NjEzNDYvc3NpL2NhL2Q3NzgxNGI1LWIxZGMtNDIwNS1iZDlmLTA5OGE4
ZTRjNDlkZDAKBggqhkjOPQQDAgNJADBGAiEAuS3o1nlzchI4I0ag0qUxpAUD8/ot
qs3spp6Rlr/mP9wCIQDVavmou3AtikpwkUWe+ZM5HbrwAi6k6lt5nxTPk3tf0A==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBiDCCAS+gAwIBAgIUEiXvMbJt3TJwCJ56URr8IqLUqeowCgYIKoZIzj0EAwIw
EjEQMA4GA1UEAwwHQ0EgY2VydDAeFw0yNDA1MDkwODQzMDhaFw0zNTExMDgwODQz
MDhaMBIxEDAOBgNVBAMMB0NBIGNlcnQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AARx38tO0JCdq3ZecMSW6a+BAAzllydQxVOQ+KDjnwLXJ4mkJj1IIq/NCNlwhap9
vyj6nVh9D8TMwgj/Ft7j8ZVAo2MwYTAfBgNVHSMEGDAWgBQ3KM2ydvy/UrQvQG0Q
9/S5PGtC4DAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFDcozbJ2/L9StC9AbRD3
9Lk8a0LgMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgb03wMpPQ
RTR8h4so2dqOjgIvuaCwEI9OQVS6F0W5HbUCIFzPiE5kAATzkMNAbzumvMuA3bL/
KqyEej23GXbZ9gL6
-----END CERTIFICATE-----"#;

    #[test]
    fn test_natual_person_access_certificate() {
        let res = etsi_access_cert_from_pem_chain(NATURAL_PERSON).unwrap();
        assert_eq!(res, test_data());
    }

    #[test]
    fn test_legal_person_access_certificate() {
        let res = etsi_access_cert_from_pem_chain(LEGAL_PERSON).unwrap();
        assert_eq!(res, test_data());
    }

    fn test_data() -> EtsiParsedAccessCert {
        EtsiParsedAccessCert {
            rp_id: "orgId".to_string(),
            support_uri: Some(Url::parse("https://some-uri.com").unwrap()),
            country: "CH".to_string(),
            common_name: Some("common name".to_string()),
            email: Some("tester@test.com".to_string()),
            phone: Some("+4123456789".to_string()),
            registry_url: Some(Url::parse("https://some-url.com").unwrap()),
        }
    }
}
