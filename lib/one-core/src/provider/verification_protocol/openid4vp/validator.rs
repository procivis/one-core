use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use shared_types::DidValue;

use crate::error::ContextWithErrorCode;
use crate::mapper::x509::x5c_into_pem_chain;
use crate::model::did::KeyRole;
use crate::proto::certificate_validator::{
    CertificateValidationOptions, CertificateValidator, ParsedCertificate,
};
use crate::proto::jwt::model::DecomposedJwt;
use crate::provider::credential_formatter::model::CertificateDetails;
use crate::provider::did_method::error::DidMethodError;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::verification_protocol::error::VerificationProtocolError;
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

pub(super) async fn validate_x509_san_dns_token<T>(
    request_token: &DecomposedJwt<T>,
    client_id: &str, // without prefix
    certificate_validator: &dyn CertificateValidator,
) -> Result<CertificateDetails, VerificationProtocolError> {
    let x5c = request_token
        .header
        .x5c
        .as_ref()
        .ok_or(VerificationProtocolError::Failed("x5c missing".to_string()))?;

    let pem_chain = x5c_into_pem_chain(x5c).error_while("parsing x5c")?;

    let ParsedCertificate {
        public_key,
        attributes,
        subject_common_name,
        ..
    } = certificate_validator
        .parse_pem_chain(
            &pem_chain,
            CertificateValidationOptions::signature_and_revocation(None),
        )
        .await
        .error_while("parsing PEM chain")?;

    public_key
        .signature()
        .ok_or(VerificationProtocolError::Failed(
            "Signature key missing".to_string(),
        ))?
        .public()
        .verify(
            request_token.unverified_jwt.as_bytes(),
            &request_token.signature,
        )
        .error_while("verifying signature")?;

    // x509 SAN must match client_id
    validate_san_dns_matching_client_id(&attributes, client_id)?;

    Ok(CertificateDetails {
        chain: pem_chain,
        fingerprint: attributes.fingerprint,
        expiry: attributes.not_after,
        subject_common_name,
        x5_references: Default::default(),
    })
}

fn validate_san_dns_matching_client_id(
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

pub(crate) async fn validate_x509_hash_request_token<T>(
    request_token: &DecomposedJwt<T>,
    client_id: &str,
    certificate_validator: &dyn CertificateValidator,
) -> Result<CertificateDetails, VerificationProtocolError> {
    let x5c = request_token
        .header
        .x5c
        .as_ref()
        .ok_or(VerificationProtocolError::Failed("x5c missing".to_string()))?;

    let pem_chain = x5c_into_pem_chain(x5c).error_while("parsing x5c")?;

    let ParsedCertificate {
        public_key,
        attributes,
        subject_common_name,
        ..
    } = certificate_validator
        .parse_pem_chain(
            &pem_chain,
            CertificateValidationOptions::signature_and_revocation(None),
        )
        .await
        .error_while("parsing PEM chain")?;

    public_key
        .signature()
        .ok_or(VerificationProtocolError::Failed(
            "Signature key missing".to_string(),
        ))?
        .public()
        .verify(
            request_token.unverified_jwt.as_bytes(),
            &request_token.signature,
        )
        .error_while("verifying signature")?;

    // client_id hash must match certificate fingerprint
    validate_x509_hash_matching_client_id(&attributes, client_id)?;

    Ok(CertificateDetails {
        chain: pem_chain,
        fingerprint: attributes.fingerprint,
        expiry: attributes.not_after,
        subject_common_name,
        x5_references: Default::default(),
    })
}

fn validate_x509_hash_matching_client_id(
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

pub(super) async fn validate_did_request_token<T>(
    request_token: &DecomposedJwt<T>,
    client_id: &str, // without prefix
    did_method_provider: &dyn DidMethodProvider,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
) -> Result<DidValue, VerificationProtocolError> {
    let Some(kid) = request_token.header.key_id.clone() else {
        return Err(VerificationProtocolError::Failed(
            "JOSE header missing kid".to_string(),
        ));
    };

    let verifier_did = client_id
        .parse()
        .map_err(DidMethodError::DidValueError)
        .error_while("parsing verifier DID")?;

    let did_document = did_method_provider
        .resolve(&verifier_did)
        .await
        .error_while("resolving verifier DID")?;

    let (_, alg) = key_algorithm_provider
        .key_algorithm_from_jose_alg(&request_token.header.algorithm)
        .ok_or(VerificationProtocolError::Failed(format!(
            "Missing algorithm: {}",
            request_token.header.algorithm
        )))?;

    let key = did_document
        .find_verification_method(Some(&kid), Some(KeyRole::Authentication))
        .or_else(|| {
            did_document.find_verification_method(Some(&kid), Some(KeyRole::AssertionMethod))
        })
        .ok_or(VerificationProtocolError::Failed(
            "Missing key in did".to_string(),
        ))?
        .public_key_jwk
        .clone();

    alg.parse_jwk(&key)
        .error_while("parsing JWK")?
        .signature()
        .ok_or(VerificationProtocolError::Failed(
            "signature missing".to_string(),
        ))?
        .public()
        .verify(
            request_token.unverified_jwt.as_bytes(),
            &request_token.signature,
        )
        .error_while("verifying signature")?;

    Ok(verifier_did)
}
