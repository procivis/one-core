use ct_codecs::{Base64, Base64UrlSafeNoPadding, Decoder, Encoder};
use shared_types::DidValue;
use x509_parser::certificate::X509Certificate;
use x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME;
use x509_parser::prelude::{GeneralName, ParsedExtension};

use crate::provider::did_method::mdl::parse_x509_from_der;
use crate::provider::exchange_protocol::error::ExchangeProtocolError;

enum Certificate {
    Der(Vec<u8>),
}

pub(crate) fn extract_x5c_san_dns(
    x5c: &[String],
    client_id: &str,
    x509_ca_certificate: &str,
) -> Result<DidValue, ExchangeProtocolError> {
    if x5c.is_empty() {
        return Err(ExchangeProtocolError::Failed("x5c empty".to_string()));
    }

    let mut chain: Vec<Certificate> = x5c.iter().try_fold(Vec::new(), |mut aggr, item| {
        let der = Base64::decode_to_vec(item, None)
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;
        aggr.push(Certificate::Der(der));
        Ok(aggr)
    })?;

    // CA certificate as the last item in the chain
    let x509_ca_certificate = Base64UrlSafeNoPadding::decode_to_vec(x509_ca_certificate, None)
        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;
    chain.push(Certificate::Der(x509_ca_certificate));

    let mut previous: Option<&Certificate> = None;
    for certificate in chain.iter() {
        let current = parse_x509(certificate)?;
        if !current.validity().is_valid() {
            return Err(ExchangeProtocolError::Failed(
                "certificate expired".to_string(),
            ));
        }

        if let Some(previous) = previous {
            // parent entry in the chain, validate signature
            let previous = parse_x509(previous)?;
            previous
                .verify_signature(Some(current.public_key()))
                .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;
        } else {
            // first in chain, check client_id match
            let dns_names = current
                .iter_extensions()
                .filter(|extension| extension.oid == OID_X509_EXT_SUBJECT_ALT_NAME)
                .try_fold(Vec::new(), |mut aggr, entry| {
                    if let ParsedExtension::SubjectAlternativeName(san) = entry.parsed_extension() {
                        for name in &san.general_names {
                            if let GeneralName::DNSName(dns) = name {
                                aggr.push(dns.to_string());
                            }
                        }
                    }
                    Ok(aggr)
                })?;

            if !dns_names
                .iter()
                .any(|dns_name| is_dns_name_matching(dns_name, client_id))
            {
                return Err(ExchangeProtocolError::Failed(format!(
                    "dNSName mismatch client_id: '{client_id}'"
                )));
            }
        }

        previous = Some(certificate);
    }

    // construct DidValue from the first (leaf) entry
    // https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.6
    let Some(Certificate::Der(der)) = chain.first() else {
        return Err(ExchangeProtocolError::Failed(
            "invalid certificate".to_string(),
        ));
    };

    let did_mdl = Base64UrlSafeNoPadding::encode_to_string(der)
        .map(|cert| format!("did:mdl:certificate:{cert}"))
        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

    did_mdl
        .parse()
        .map_err(|e: anyhow::Error| ExchangeProtocolError::Failed(e.to_string()))
}

fn parse_x509(certificate: &Certificate) -> Result<X509Certificate, ExchangeProtocolError> {
    match certificate {
        Certificate::Der(der) => parse_x509_from_der(der),
    }
    .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))
}

fn is_dns_name_matching(dns_name: &str, client_id: &str) -> bool {
    // https://datatracker.ietf.org/doc/html/rfc1034#section-4.3.3
    if let Some(wildcard_domain) = dns_name.strip_prefix("*") {
        client_id.ends_with(wildcard_domain)
    } else {
        // simple case
        dns_name == client_id
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    const DOMAIN: &str = "core.dev.procivis-one.com";
    const X509_CERT: &str = "MIIDrzCCA1SgAwIBAgIUA9IPga3NlWs0nTiYle4Yhz2hljgwCgYIKoZIzj0EAwIwYjELMAkGA1UEBhMCQ0gxDzANBgNVBAcMBlp1cmljaDERMA8GA1UECgwIUHJvY2l2aXMxETAPBgNVBAsMCFByb2NpdmlzMRwwGgYDVQQDDBNjYS5kZXYubWRsLXBsdXMuY29tMB4XDTI1MDEyMjExMjMwMFoXDTI4MTIzMTAwMDAwMFowWDELMAkGA1UEBhMCQ0gxDzANBgNVBAcMBlp1cmljaDEUMBIGA1UECgwLUHJvY2l2aXMgQUcxIjAgBgNVBAMMGWNvcmUuZGV2LnByb2NpdmlzLW9uZS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASfzLZQ6ejktBYcBjTBXPXTkalgkum/R/84Tdm+7Jxm2UR+JTsxJP1ccrHwvySDHbt5EDnHdNovJyCtjH4b9FDgo4IB8DCCAewwDgYDVR0PAQH/BAQDAgeAMBUGA1UdJQEB/wQLMAkGByiBjF0FAQIwDAYDVR0TAQH/BAIwADAkBgNVHREEHTAbghljb3JlLmRldi5wcm9jaXZpcy1vbmUuY29tMB8GA1UdIwQYMBaAFO0asJ3iYEVQADvaWjQyGpi+LbfFMFoGA1UdHwRTMFEwT6BNoEuGSWh0dHBzOi8vY2EuZGV2Lm1kbC1wbHVzLmNvbS9jcmwvNDBDRDIyNTQ3RjM4MzRDNTI2QzVDMjJFMUEyNkM3RTIwMzMyNDY2OC8wgcoGCCsGAQUFBwEBBIG9MIG6MFsGCCsGAQUFBzAChk9odHRwczovL2NhLmRldi5tZGwtcGx1cy5jb20vaXNzdWVyLzQwQ0QyMjU0N0YzODM0QzUyNkM1QzIyRTFBMjZDN0UyMDMzMjQ2NjguZGVyMFsGCCsGAQUFBzABhk9odHRwczovL2NhLmRldi5tZGwtcGx1cy5jb20vb2NzcC80MENEMjI1NDdGMzgzNEM1MjZDNUMyMkUxQTI2QzdFMjAzMzI0NjY4L2NlcnQvMCYGA1UdEgQfMB2GG2h0dHBzOi8vY2EuZGV2Lm1kbC1wbHVzLmNvbTAdBgNVHQ4EFgQUruIPHQ4F1HmX3H8EW2knrLczQRQwCgYIKoZIzj0EAwIDSQAwRgIhALk9d8u5OOTMbU3+IFEt9IXQWCQyRQgDUXwaz4zKAJ5AAiEAlSHs1Tz6crYNJ9gJ6enYctzLSaVp7m3okkZiLU2Suhk=";
    const CERT_AS_DID: &str = "did:mdl:certificate:MIIDrzCCA1SgAwIBAgIUA9IPga3NlWs0nTiYle4Yhz2hljgwCgYIKoZIzj0EAwIwYjELMAkGA1UEBhMCQ0gxDzANBgNVBAcMBlp1cmljaDERMA8GA1UECgwIUHJvY2l2aXMxETAPBgNVBAsMCFByb2NpdmlzMRwwGgYDVQQDDBNjYS5kZXYubWRsLXBsdXMuY29tMB4XDTI1MDEyMjExMjMwMFoXDTI4MTIzMTAwMDAwMFowWDELMAkGA1UEBhMCQ0gxDzANBgNVBAcMBlp1cmljaDEUMBIGA1UECgwLUHJvY2l2aXMgQUcxIjAgBgNVBAMMGWNvcmUuZGV2LnByb2NpdmlzLW9uZS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASfzLZQ6ejktBYcBjTBXPXTkalgkum_R_84Tdm-7Jxm2UR-JTsxJP1ccrHwvySDHbt5EDnHdNovJyCtjH4b9FDgo4IB8DCCAewwDgYDVR0PAQH_BAQDAgeAMBUGA1UdJQEB_wQLMAkGByiBjF0FAQIwDAYDVR0TAQH_BAIwADAkBgNVHREEHTAbghljb3JlLmRldi5wcm9jaXZpcy1vbmUuY29tMB8GA1UdIwQYMBaAFO0asJ3iYEVQADvaWjQyGpi-LbfFMFoGA1UdHwRTMFEwT6BNoEuGSWh0dHBzOi8vY2EuZGV2Lm1kbC1wbHVzLmNvbS9jcmwvNDBDRDIyNTQ3RjM4MzRDNTI2QzVDMjJFMUEyNkM3RTIwMzMyNDY2OC8wgcoGCCsGAQUFBwEBBIG9MIG6MFsGCCsGAQUFBzAChk9odHRwczovL2NhLmRldi5tZGwtcGx1cy5jb20vaXNzdWVyLzQwQ0QyMjU0N0YzODM0QzUyNkM1QzIyRTFBMjZDN0UyMDMzMjQ2NjguZGVyMFsGCCsGAQUFBzABhk9odHRwczovL2NhLmRldi5tZGwtcGx1cy5jb20vb2NzcC80MENEMjI1NDdGMzgzNEM1MjZDNUMyMkUxQTI2QzdFMjAzMzI0NjY4L2NlcnQvMCYGA1UdEgQfMB2GG2h0dHBzOi8vY2EuZGV2Lm1kbC1wbHVzLmNvbTAdBgNVHQ4EFgQUruIPHQ4F1HmX3H8EW2knrLczQRQwCgYIKoZIzj0EAwIDSQAwRgIhALk9d8u5OOTMbU3-IFEt9IXQWCQyRQgDUXwaz4zKAJ5AAiEAlSHs1Tz6crYNJ9gJ6enYctzLSaVp7m3okkZiLU2Suhk";
    const CA_CERT: &str = "MIICLDCCAdKgAwIBAgIUQM0iVH84NMUmxcIuGibH4gMyRmgwCgYIKoZIzj0EAwQwYjELMAkGA1UEBhMCQ0gxDzANBgNVBAcMBlp1cmljaDERMA8GA1UECgwIUHJvY2l2aXMxETAPBgNVBAsMCFByb2NpdmlzMRwwGgYDVQQDDBNjYS5kZXYubWRsLXBsdXMuY29tMB4XDTIyMDExMjEyMDAwMFoXDTMyMDExMDEyMDAwMFowYjELMAkGA1UEBhMCQ0gxDzANBgNVBAcMBlp1cmljaDERMA8GA1UECgwIUHJvY2l2aXMxETAPBgNVBAsMCFByb2NpdmlzMRwwGgYDVQQDDBNjYS5kZXYubWRsLXBsdXMuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaRFtZbpYHFlPgGyZCt6bGKS0hEekPVxiBHRXImo8_NUR-czg-DI2KTE3ikRVNgq2rICatkvkV2jaM2frPEOl1qNmMGQwEgYDVR0TAQH_BAgwBgEB_wIBADAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFO0asJ3iYEVQADvaWjQyGpi-LbfFMB8GA1UdIwQYMBaAFO0asJ3iYEVQADvaWjQyGpi-LbfFMAoGCCqGSM49BAMEA0gAMEUCIQD9kfI800DOj76YsiW4lUNRZowH07j152M3UKHKEaIjUAIgZNINukb4SFKEC4A0qEKgpPEZM7_Vh5aNro-PQn3_rgA";

    #[test]
    fn test_extract_x5c_san_dns_success() {
        let did_value = extract_x5c_san_dns(&[X509_CERT.to_string()], DOMAIN, CA_CERT).unwrap();
        assert_eq!(did_value.as_str(), CERT_AS_DID);
    }

    #[test]
    fn test_extract_x5c_san_dns_mismatch_client_id() {
        let result = extract_x5c_san_dns(&[X509_CERT.to_string()], "invalid.domain", CA_CERT);
        assert!(matches!(result, Err(ExchangeProtocolError::Failed(_))));
    }

    const EXPIRED_CERT: &str = "MIIDrjCCA1SgAwIBAgIUB3ls6U2x92IFP9Nzk0ogLzpfQTAwCgYIKoZIzj0EAwIwYjELMAkGA1UEBhMCQ0gxDzANBgNVBAcMBlp1cmljaDERMA8GA1UECgwIUHJvY2l2aXMxETAPBgNVBAsMCFByb2NpdmlzMRwwGgYDVQQDDBNjYS5kZXYubWRsLXBsdXMuY29tMB4XDTI1MDEyMjExNTMwMFoXDTI1MDEyMzAwMDAwMFowWDELMAkGA1UEBhMCQ0gxDzANBgNVBAcMBlp1cmljaDEUMBIGA1UECgwLUHJvY2l2aXMgQUcxIjAgBgNVBAMMGWNvcmUuZGV2LnByb2NpdmlzLW9uZS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASfzLZQ6ejktBYcBjTBXPXTkalgkum/R/84Tdm+7Jxm2UR+JTsxJP1ccrHwvySDHbt5EDnHdNovJyCtjH4b9FDgo4IB8DCCAewwDgYDVR0PAQH/BAQDAgeAMBUGA1UdJQEB/wQLMAkGByiBjF0FAQIwDAYDVR0TAQH/BAIwADAkBgNVHREEHTAbghljb3JlLmRldi5wcm9jaXZpcy1vbmUuY29tMB8GA1UdIwQYMBaAFO0asJ3iYEVQADvaWjQyGpi+LbfFMFoGA1UdHwRTMFEwT6BNoEuGSWh0dHBzOi8vY2EuZGV2Lm1kbC1wbHVzLmNvbS9jcmwvNDBDRDIyNTQ3RjM4MzRDNTI2QzVDMjJFMUEyNkM3RTIwMzMyNDY2OC8wgcoGCCsGAQUFBwEBBIG9MIG6MFsGCCsGAQUFBzAChk9odHRwczovL2NhLmRldi5tZGwtcGx1cy5jb20vaXNzdWVyLzQwQ0QyMjU0N0YzODM0QzUyNkM1QzIyRTFBMjZDN0UyMDMzMjQ2NjguZGVyMFsGCCsGAQUFBzABhk9odHRwczovL2NhLmRldi5tZGwtcGx1cy5jb20vb2NzcC80MENEMjI1NDdGMzgzNEM1MjZDNUMyMkUxQTI2QzdFMjAzMzI0NjY4L2NlcnQvMCYGA1UdEgQfMB2GG2h0dHBzOi8vY2EuZGV2Lm1kbC1wbHVzLmNvbTAdBgNVHQ4EFgQUruIPHQ4F1HmX3H8EW2knrLczQRQwCgYIKoZIzj0EAwIDSAAwRQIgYcmNEKIyD4x7e9hKgAEdzvdAMxDX9rBZkvN/B72VGp0CIQCFF1EGaAzH+X3g0XF7hTh+aPJwcKp1xcllHPkVG7+rpg==";

    #[test]
    fn test_extract_x5c_san_dns_expired_cert() {
        let result = extract_x5c_san_dns(&[EXPIRED_CERT.to_string()], DOMAIN, CA_CERT);
        assert!(matches!(result, Err(ExchangeProtocolError::Failed(_))));
    }
}
