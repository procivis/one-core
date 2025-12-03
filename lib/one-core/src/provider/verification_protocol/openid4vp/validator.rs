use std::collections::HashMap;
use std::ops::{Add, Sub};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use dcql::TrustedAuthority;
use shared_types::DidValue;
use time::OffsetDateTime;

use crate::config::core_config::{DidType, VerificationProtocolType};
use crate::mapper::NESTED_CLAIM_MARKER;
use crate::mapper::oidc::map_from_oidc_format_to_core_detailed;
use crate::model::key::PublicKeyJwk;
use crate::model::proof::Proof;
use crate::model::proof_schema::ProofInputSchema;
use crate::proto::key_verification::KeyVerification;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::mdoc_formatter::try_extracting_mso_from_token;
use crate::provider::credential_formatter::mdoc_formatter::util::MobileSecurityObject;
use crate::provider::credential_formatter::model::{
    CredentialClaim, DetailCredential, HolderBindingCtx, IdentifierDetails, TokenVerifier,
};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::presentation_formatter::model::{
    ExtractPresentationCtx, ExtractedPresentation,
};
use crate::provider::presentation_formatter::provider::PresentationFormatterProvider;
use crate::provider::revocation::lvvc::util::is_lvvc_credential;
use crate::provider::revocation::model::{
    CredentialDataByRole, CredentialRevocationState, VerifierCredentialData,
};
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::openid4vp::error::OpenID4VCError;
use crate::provider::verification_protocol::openid4vp::model::ValidatedProofClaimDTO;
use crate::service::certificate::dto::CertificateX509AttributesDTO;
use crate::util::authority_key_identifier::get_aki_for_pem_chain;
use crate::validator::x509::is_dns_name_matching;

pub(super) async fn peek_presentation(
    presentation_string: &str,
    oidc_format: &str,
    formatter_provider: &Arc<dyn PresentationFormatterProvider>,
    protocol_type: VerificationProtocolType,
) -> Result<ExtractedPresentation, OpenID4VCError> {
    let format = map_from_oidc_format_to_core_detailed(oidc_format, Some(presentation_string))
        .map_err(|_| OpenID4VCError::VCFormatsNotSupported)?;
    let presentation_formatter = formatter_provider
        .get_presentation_formatter(&format)
        .ok_or(OpenID4VCError::VCFormatsNotSupported)?;

    let presentation = presentation_formatter
        .extract_presentation_unverified(
            presentation_string,
            ExtractPresentationCtx {
                verification_protocol_type: protocol_type,
                nonce: None,
                format_nonce: None,
                issuance_date: None,
                expiration_date: None,
                client_id: None,
                response_uri: None,
                mdoc_session_transcript: None,
                verifier_key: None,
            },
        )
        .await
        .map_err(|e| {
            if matches!(e, FormatterError::CouldNotExtractPresentation(_)) {
                OpenID4VCError::VPFormatsNotSupported
            } else {
                OpenID4VCError::Other(e.to_string())
            }
        })?;

    Ok(presentation)
}

pub(super) async fn validate_presentation(
    presentation_string: &str,
    nonce: &str,
    presentation_format: &str,
    formatter_provider: &Arc<dyn PresentationFormatterProvider>,
    key_verification: Box<dyn TokenVerifier>,
    context: ExtractPresentationCtx,
) -> Result<ExtractedPresentation, OpenID4VCError> {
    let presentation_formatter = formatter_provider
        .get_presentation_formatter(presentation_format)
        .ok_or(OpenID4VCError::VCFormatsNotSupported)?;

    let presentation = presentation_formatter
        .extract_presentation(presentation_string, key_verification, context)
        .await
        .map_err(|e| {
            if matches!(e, FormatterError::CouldNotExtractPresentation(_)) {
                OpenID4VCError::VPFormatsNotSupported
            } else {
                OpenID4VCError::Other(e.to_string())
            }
        })?;

    validate_issuance_time(&presentation.issued_at, presentation_formatter.get_leeway())?;
    validate_expiration_time(
        &presentation.expires_at,
        presentation_formatter.get_leeway(),
    )?;

    if presentation
        .nonce
        .as_ref()
        .is_none_or(|presentation_nonce| presentation_nonce != nonce)
    {
        return Err(OpenID4VCError::ValidationError(
            "Nonce not matched".to_string(),
        ));
    }

    Ok(presentation)
}

fn is_revocation_credential(credential: &DetailCredential) -> bool {
    is_lvvc_credential(credential)
        || (credential.claims.claims.contains_key("encodedList")
            && credential.claims.claims.contains_key("statusPurpose"))
}

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
#[expect(clippy::too_many_arguments)]
pub(super) async fn validate_credential(
    holder_details: &IdentifierDetails,
    credential_token: &str,
    extracted_lvvcs: &[DetailCredential],
    proof_schema_input: &ProofInputSchema,
    formatter_provider: &Arc<dyn CredentialFormatterProvider>,
    key_verification: Box<KeyVerification>,
    did_method_provider: &Arc<dyn DidMethodProvider>,
    revocation_method_provider: &Arc<dyn RevocationMethodProvider>,
    holder_binding_ctx: HolderBindingCtx,
    trusted_authorities: Option<&[TrustedAuthority]>,
) -> Result<(DetailCredential, Option<MobileSecurityObject>), OpenID4VCError> {
    let format = proof_schema_input
        .credential_schema
        .as_ref()
        .map(|schema| schema.format.as_str())
        .ok_or(OpenID4VCError::VCFormatsNotSupported)?;
    let formatter = formatter_provider
        .get_credential_formatter(format)
        .ok_or(OpenID4VCError::VCFormatsNotSupported)?;

    let credential = formatter
        .extract_credentials(
            credential_token,
            proof_schema_input.credential_schema.as_ref(),
            key_verification,
            Some(holder_binding_ctx),
        )
        .await
        .map_err(|e| {
            if matches!(e, FormatterError::CouldNotExtractCredentials(_)) {
                OpenID4VCError::VCFormatsNotSupported
            } else {
                OpenID4VCError::Other(e.to_string())
            }
        })?;

    validate_issuance_time(&credential.valid_from, formatter.get_leeway())?;
    validate_expiration_time(&credential.valid_until, formatter.get_leeway())?;

    if is_revocation_credential(&credential) {
        return Ok((credential, None));
    };

    for credential_status in credential.status.iter() {
        let (revocation_method, _) = revocation_method_provider
            .get_revocation_method_by_status_type(&credential_status.r#type)
            .ok_or(OpenID4VCError::MissingRevocationProviderForType(
                credential_status.r#type.clone(),
            ))?;

        match revocation_method
            .check_credential_revocation_status(
                credential_status,
                &credential.issuer,
                Some(CredentialDataByRole::Verifier(Box::new(
                    VerifierCredentialData {
                        credential: credential.to_owned(),
                        extracted_lvvcs: extracted_lvvcs.to_owned(),
                        proof_input: proof_schema_input.to_owned(),
                    },
                ))),
                false,
            )
            .await?
        {
            CredentialRevocationState::Valid => {}
            CredentialRevocationState::Revoked | CredentialRevocationState::Suspended { .. } => {
                return Err(OpenID4VCError::CredentialIsRevokedOrSuspended);
            }
        }
    }

    // Check if all subjects of the submitted VCs are matching the holder did.
    let Some(credential_subject) = &credential.subject else {
        return Err(OpenID4VCError::ValidationError(
            "Claim Holder DID missing".to_owned(),
        ));
    };

    check_matching_identifiers(
        credential_subject,
        holder_details,
        &**did_method_provider,
        &formatter.get_capabilities().holder_did_methods,
    )
    .await?;

    if let Some(authorities) = trusted_authorities {
        check_issuer_is_trusted_authority(&credential.issuer, authorities)?;
    }

    let mut mso = None;
    if format == "MDOC" {
        mso = Some(
            try_extracting_mso_from_token(credential_token)
                .await
                .map_err(|e| OpenID4VCError::ValidationError(e.to_string()))?,
        );
    }

    Ok((credential, mso))
}

/// it can happen that credential holder binding is a key, while proof issuer is a did
/// we have to allow that combination if the same public key is used
async fn check_matching_identifiers(
    a: &IdentifierDetails,
    b: &IdentifierDetails,
    did_method_provider: &dyn DidMethodProvider,
    allowed_did_methods: &[DidType],
) -> Result<(), OpenID4VCError> {
    if a == b {
        return Ok(());
    }

    match (a, b) {
        (IdentifierDetails::Did(a), IdentifierDetails::Did(b)) => {
            check_did_method_allowed(a, allowed_did_methods)?;
            check_did_method_allowed(b, allowed_did_methods)?;
            check_matching_dids(a, b, did_method_provider).await?
        }
        (IdentifierDetails::Did(did_value), IdentifierDetails::Key(public_key_jwk))
        | (IdentifierDetails::Key(public_key_jwk), IdentifierDetails::Did(did_value)) => {
            check_did_method_allowed(did_value, allowed_did_methods)?;
            check_matching_key_with_did(public_key_jwk, did_value, did_method_provider).await?
        }
        _ => {
            return Err(OpenID4VCError::ValidationError(
                "Mismatching holder identifiers".to_owned(),
            ));
        }
    };

    Ok(())
}

fn check_issuer_is_trusted_authority(
    issuer: &IdentifierDetails,
    authorities: &[TrustedAuthority],
) -> Result<(), OpenID4VCError> {
    let issuer_aki = match issuer {
        IdentifierDetails::Certificate(cert) => {
            match get_aki_for_pem_chain(cert.chain.as_bytes()) {
                Some(value) => value,
                None => {
                    return Err(OpenID4VCError::ValidationError(
                        "Failed to retrieve Authority Key Identifier for credential issuer"
                            .to_owned(),
                    ));
                }
            }
        }
        // Currently, we support only AuthorityKeyId trusted authorities.
        // Non-certificate issuers cannot pass an AKI check, so the code can bail out early here.
        _ => {
            return Err(OpenID4VCError::ValidationError(
                "Issuer is not in Trusted Authorities list".to_owned(),
            ));
        }
    };

    // DCQL spec says that AKI values should be provided as base64-encoded strings.
    // We need to decode those before we can match them against stored AKIs.
    let trusted_akis = {
        let mut akis: Vec<Vec<u8>> = Vec::new();
        for authority in authorities {
            if let TrustedAuthority::AuthorityKeyId { values } = &authority {
                for value in values {
                    match Base64UrlSafeNoPadding::decode_to_vec(value.as_bytes(), None) {
                        Ok(bytes) => akis.push(bytes),
                        Err(_) => { /* Discard invalid values */ }
                    }
                }
            }
        }
        akis
    };

    for trusted_aki in &trusted_akis {
        // This is very inefficient.
        // We could use something like `bstr::ByteSlice::contains_str()`,
        // or maybe `.contains_bytes()` once the following gets implemented:
        // https://github.com/rust-lang/rust/issues/134149
        for window in issuer_aki.windows(trusted_aki.len()) {
            if window.iter().eq(trusted_aki.iter()) {
                return Ok(());
            }
        }
    }

    Err(OpenID4VCError::ValidationError(
        "Issuer is not in Trusted Authorities list".to_owned(),
    ))
}

fn check_did_method_allowed(
    did: &DidValue,
    allowed_did_methods: &[DidType],
) -> Result<(), OpenID4VCError> {
    let did_method = DidType::from_str(did.method().to_uppercase().as_str()).map_err(|_| {
        OpenID4VCError::ValidationError(format!("Unsupported holder DID method: {}", did.method()))
    })?;

    if !allowed_did_methods.contains(&did_method) {
        return Err(OpenID4VCError::ValidationError(format!(
            "Unsupported holder DID method: {}",
            did.method()
        )));
    }

    Ok(())
}

async fn check_matching_key_with_did(
    key: &PublicKeyJwk,
    did: &DidValue,
    did_method_provider: &dyn DidMethodProvider,
) -> Result<(), OpenID4VCError> {
    let did_document = did_method_provider
        .resolve(did)
        .await
        .map_err(|e| OpenID4VCError::ValidationError(e.to_string()))?;

    // Find matching key in did document
    did_document
        .verification_method
        .iter()
        .find(|vm| &vm.public_key_jwk == key)
        .ok_or(OpenID4VCError::ValidationError(
            "Presentation signer DID not matching credential holder binding key".to_owned(),
        ))?;

    Ok(())
}

async fn check_matching_dids(
    a: &DidValue,
    b: &DidValue,
    did_method_provider: &dyn DidMethodProvider,
) -> Result<(), OpenID4VCError> {
    let claim_subject_did_document = did_method_provider
        .resolve(a)
        .await
        .map_err(|e| OpenID4VCError::ValidationError(e.to_string()))?;

    let holder_did_document = did_method_provider
        .resolve(b)
        .await
        .map_err(|e| OpenID4VCError::ValidationError(e.to_string()))?;

    // Simplest case, the DIDs (and resolved documents) are exactly the same
    let same_did_document = claim_subject_did_document == holder_did_document;

    if same_did_document {
        return Ok(());
    }

    // If did documents / DIDs are different, validate that holder has matching key in claim subject

    // Get the holder's verification key
    let holder_key = holder_did_document
        .find_verification_method(None, None)
        .ok_or(OpenID4VCError::ValidationError(
            "Presentation signer DID document contains no verification methods".to_owned(),
        ))?;

    // Find matching key in claim subject's verification methods
    claim_subject_did_document
        .verification_method
        .iter()
        .find(|vm| vm.public_key_jwk == holder_key.public_key_jwk)
        .ok_or(OpenID4VCError::ValidationError(
            "Presentation signer key not found in claim subject DID document".to_owned(),
        ))?;

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

pub(super) fn validate_claims(
    received_credential: DetailCredential,
    proof_input_schema: &ProofInputSchema,
    mso: Option<MobileSecurityObject>,
) -> Result<Vec<ValidatedProofClaimDTO>, OpenID4VCError> {
    let expected_credential_claims =
        proof_input_schema
            .claim_schemas
            .as_ref()
            .ok_or(OpenID4VCError::MappingError(
                "Missing claim schemas".to_string(),
            ))?;

    let credential_schema =
        proof_input_schema
            .credential_schema
            .as_ref()
            .ok_or(OpenID4VCError::MappingError(
                "Missing credential schema".to_string(),
            ))?;
    let mut proved_claims: Vec<ValidatedProofClaimDTO> = Vec::new();

    for expected_credential_claim in expected_credential_claims {
        let resolved = resolve_claim(
            &expected_credential_claim.schema.key,
            &received_credential.claims.claims,
        );
        if let Some(value) = resolved? {
            // Expected claim present in the presentation
            proved_claims.push(ValidatedProofClaimDTO {
                proof_input_claim: expected_credential_claim.to_owned(),
                credential: received_credential.to_owned(),
                value: value.to_owned(),
                credential_schema: credential_schema.to_owned(),
                mdoc_mso: mso.clone(),
            })
        } else if expected_credential_claim.required {
            // Fail as required claim was not sent
            return Err(OpenID4VCError::ValidationError(
                "Required claim not submitted".to_string(),
            ));
        } else {
            // Not present but also not required
            continue;
        }
    }
    Ok(proved_claims)
}

fn resolve_claim<'a>(
    claim_name: &str,
    claims: &'a HashMap<String, CredentialClaim>,
) -> Result<Option<&'a CredentialClaim>, OpenID4VCError> {
    // Simplest case - claim is not nested
    if let Some(value) = claims.get(claim_name) {
        return Ok(Some(value));
    }

    match claim_name.split_once(NESTED_CLAIM_MARKER) {
        None => Ok(None),
        Some((prefix, rest)) => match claims.get(prefix) {
            None => Ok(None),
            Some(value) => resolve_claim_inner(rest, value),
        },
    }
}

fn resolve_claim_inner<'a>(
    claim_name: &str,
    claims: &'a CredentialClaim,
) -> Result<Option<&'a CredentialClaim>, OpenID4VCError> {
    if let Some(value) = claims.value.as_object().and_then(|obj| obj.get(claim_name)) {
        return Ok(Some(value));
    }

    match claim_name.split_once(NESTED_CLAIM_MARKER) {
        Some((prefix, rest)) => match claims.value.as_object().and_then(|obj| obj.get(prefix)) {
            None => Ok(None),
            Some(value) => resolve_claim_inner(rest, value),
        },
        None => Ok(None),
    }
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

pub(super) fn validate_proof_completeness(
    proof: &Proof,
    proved_claims: &[ValidatedProofClaimDTO],
) -> Result<(), OpenID4VCError> {
    for input_schema in proof
        .schema
        .as_ref()
        .ok_or(OpenID4VCError::ValidationError(
            "Missing proof schema".to_string(),
        ))?
        .input_schemas
        .as_ref()
        .ok_or(OpenID4VCError::ValidationError(
            "Missing proof input schemas".to_string(),
        ))?
    {
        let credential_schema =
            input_schema
                .credential_schema
                .as_ref()
                .ok_or(OpenID4VCError::ValidationError(
                    "Missing credential schema".to_string(),
                ))?;
        for proof_claim_input_schema in
            input_schema
                .claim_schemas
                .as_ref()
                .ok_or(OpenID4VCError::ValidationError(
                    "Missing claim input schemas".to_string(),
                ))?
        {
            if proof_claim_input_schema.required
                && !proved_claims.iter().any(|proved_claim| {
                    credential_schema.id == proved_claim.credential_schema.id
                        && proof_claim_input_schema.schema.id
                            == proved_claim.proof_input_claim.schema.id
                })
            {
                return Err(OpenID4VCError::ValidationError(format!(
                    "Claim `{}` (key `{}`) is required but not found in proof submission for proof `{}`",
                    proof_claim_input_schema.schema.id,
                    proof_claim_input_schema.schema.key,
                    proof.id
                )));
            }
        }
    }
    Ok(())
}
