use std::ops::{Add, Sub};
use std::time::Duration;

use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use time::OffsetDateTime;

use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::openid4vp::error::OpenID4VCError;
use crate::service::certificate::dto::CertificateX509AttributesDTO;
use crate::validator::x509::is_dns_name_matching;

pub(super) fn validate_against_redirect_uris(
    redirect_uris: &[String],
    uri: Option<&str>,
) -> Result<(), VerificationProtocolError> {
    if redirect_uris.is_empty() {
        return Ok(());
    }

    if let Some(uri) = uri
        && !redirect_uris.iter().any(|v| v == uri)
    {
        return Err(VerificationProtocolError::Failed(
            "redirect_uri or response_uri is not allowed by verifier_attestation token".to_string(),
        ));
    }

    Ok(())
}

pub(crate) fn validate_issuance_time(
    issued_at: &Option<OffsetDateTime>,
    leeway: u64,
) -> Result<(), OpenID4VCError> {
    if issued_at.is_none() {
        return Ok(());
    }

    let now = OffsetDateTime::now_utc();
    let issued = issued_at.ok_or(OpenID4VCError::ValidationError(
        "Missing issuance date".to_owned(),
    ))?;

    if issued > now.add(Duration::from_secs(leeway)) {
        return Err(OpenID4VCError::ValidationError(
            "Issued in future".to_owned(),
        ));
    }

    Ok(())
}

pub(crate) fn validate_expiration_time(
    expires_at: &Option<OffsetDateTime>,
    leeway: u64,
) -> Result<(), OpenID4VCError> {
    if expires_at.is_none() {
        return Ok(());
    }

    let now = OffsetDateTime::now_utc();
    let expires = expires_at.ok_or(OpenID4VCError::ValidationError(
        "Missing expiration date".to_owned(),
    ))?;

    if expires < now.sub(Duration::from_secs(leeway)) {
        return Err(OpenID4VCError::ValidationError("Expired".to_owned()));
    }

    Ok(())
}

pub(crate) fn validate_san_dns_matching_client_id(
    certificate_attributes: &CertificateX509AttributesDTO,
    client_id: &str,
) -> Result<(), VerificationProtocolError> {
    let san = certificate_attributes
        .extensions
        .iter()
        .find(
            |extension| extension.oid == "2.5.29.17", // Subject Alternative Name
        )
        .ok_or(VerificationProtocolError::Failed(
            "Verifier certificate does not contain a SAN extension".to_string(),
        ))?;

    let san_dns_names: Vec<_> = san
        .value
        .split("\n")
        .filter_map(|san_entry| {
            san_entry
                .strip_prefix("DNSName(")
                .and_then(|entry| entry.strip_suffix(")"))
        })
        .collect();

    if san_dns_names.is_empty() {
        return Err(VerificationProtocolError::Failed(
            "Verifier certificate does not contain a SAN DNS entry".to_string(),
        ));
    }

    if !san_dns_names
        .iter()
        .any(|dns_name| is_dns_name_matching(dns_name, client_id))
    {
        return Err(VerificationProtocolError::Failed(format!(
            "dNSName mismatch client_id: '{client_id}'"
        )));
    }

    Ok(())
}

pub(crate) fn validate_x509_hash_matching_client_id(
    certificate_attributes: &CertificateX509AttributesDTO,
    client_id: &str,
) -> Result<(), VerificationProtocolError> {
    let hash = Base64UrlSafeNoPadding::decode_to_vec(client_id, None)
        .map_err(|e| VerificationProtocolError::InvalidRequest(e.to_string()))?;
    let fingerprint = hex::decode(&certificate_attributes.fingerprint)
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;
    if hash != fingerprint {
        tracing::debug!("Mismatch x509_hash x5c:{fingerprint:?}, client_id:{hash:?}");
        return Err(VerificationProtocolError::InvalidRequest(
            "Invalid client_id hash".to_string(),
        ));
    }

    Ok(())
}
