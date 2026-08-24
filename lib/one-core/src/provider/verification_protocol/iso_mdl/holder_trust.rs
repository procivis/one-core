use std::borrow::Cow;

use coset::iana;
use shared_types::{EcosystemId, ProofId};
use standardized_types::jwk::PublicJwk;
use standardized_types::openid4vp::{VerifierInfoAttestation, VerifierInfoAttestationFormat};

use super::common::{DeviceRequest, ItemsRequest};
use super::mapper::device_request_to_dcql_query;
use crate::error::ContextWithErrorCode;
use crate::mapper::x509::der_chain_into_pem_chain;
use crate::model::identifier::Identifier;
use crate::model::interaction::Interaction;
use crate::proto::certificate_validator::{
    CertificateValidationOptions, CertificateValidator, EnforceKeyUsage, ParsedCertificate,
};
use crate::proto::cose::CoseSign1;
use crate::proto::identifier_creator::{IdentifierCreator, IdentifierName};
use crate::provider::credential_formatter::mdoc_formatter::try_verify_detached_signature_with_provider;
use crate::provider::credential_formatter::mdoc_formatter::util::{EmbeddedCbor, cose_header};
use crate::provider::credential_formatter::model::{
    CertificateDetails, IdentifierDetails, VerificationFn, X5References,
};
use crate::provider::ecosystem::directory::EcosystemDirectory;
use crate::provider::ecosystem::model::ProtocolArtifact;
use crate::provider::presentation_formatter::mso_mdoc::model::ReaderAuthentication;
use crate::provider::presentation_formatter::mso_mdoc::session_transcript::SessionTranscript;
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::repository::interaction_repository::InteractionRepository;
use crate::validator::ecosystem::{SelectionRole, resolve_ecosystem};

#[expect(clippy::too_many_arguments)]
pub(super) async fn resolve_verifier_and_trust(
    device_request: &DeviceRequest,
    session_transcript: &SessionTranscript,
    proof_id: ProofId,
    interaction: &Interaction,
    interaction_repository: &dyn InteractionRepository,
    ecosystem_provider: &dyn EcosystemDirectory,
    certificate_validator: &dyn CertificateValidator,
    identifier_creator: &dyn IdentifierCreator,
    verify_fn: &VerificationFn,
) -> Result<(Option<Identifier>, Option<EcosystemId>), VerificationProtocolError> {
    let dcql_query = device_request_to_dcql_query(device_request);
    let verifier_info = extract_reg_certs(device_request)?;
    let verifier_details = extract_verifier(
        device_request,
        session_transcript,
        certificate_validator,
        verify_fn,
    )
    .await?;

    // the device request carries all the trust information there is, so the ecosystem is final
    let ecosystem = resolve_ecosystem(
        interaction.id,
        &ProtocolArtifact::HolderProof {
            verifier_details: Cow::Borrowed(&verifier_details),
            dcql_query,
            verifier_info,
            proof_id,
        },
        interaction_repository,
        ecosystem_provider,
        SelectionRole::Holder,
    )
    .await
    .error_while("resolving ecosystem")?;

    let identifier = if let Some(verifier_details) = verifier_details {
        let (identifier, _) = identifier_creator
            .get_or_create_remote_identifier(
                interaction.organisation.as_ref().await?.as_ref(),
                &verifier_details,
                IdentifierName::PrefixForId("ReaderAuth".to_string()),
            )
            .await
            .error_while("creating remote identifier")?;

        Some(identifier)
    } else {
        None
    };

    Ok((identifier, ecosystem))
}

fn extract_reg_certs(
    device_request: &DeviceRequest,
) -> Result<Vec<VerifierInfoAttestation>, VerificationProtocolError> {
    let mut result = vec![];
    for doc_request in &device_request.doc_requests {
        let items_request = doc_request.items_request.inner();
        if let Some(request_info) = &items_request.request_info
            && let Some(rc) = request_info.get(&"eUWrprc".to_string())
        {
            let data = match rc {
                ciborium::Value::Bytes(utf_8) => {
                    String::from_utf8(utf_8.to_owned()).map_err(|_| {
                        VerificationProtocolError::InvalidRequest(
                            "Could not parse `eUWrprc`".to_string(),
                        )
                    })?
                }
                ciborium::Value::Text(rc) => rc.to_owned(),
                _ => {
                    return Err(VerificationProtocolError::InvalidRequest(
                        "Unrecognized `eUWrprc` format".to_string(),
                    ));
                }
            };

            result.push(VerifierInfoAttestation {
                format: VerifierInfoAttestationFormat::RegistrationCert,
                data,
                credential_ids: vec![items_request.doc_type.to_owned().into()],
            });
        }
    }

    Ok(result)
}

/// Extracts verifier details
///
/// To workaround possibility of multiple verifier certificates within one request,
/// we require one certificate to be used for all docs, or no readerAuth
async fn extract_verifier(
    device_request: &DeviceRequest,
    session_transcript: &SessionTranscript,
    certificate_validator: &dyn CertificateValidator,
    verify_fn: &VerificationFn,
) -> Result<Option<IdentifierDetails>, VerificationProtocolError> {
    let mut result_certificate: Option<CertificateDetails> = None;
    let mut reader_auth_specified = None;

    for doc_request in &device_request.doc_requests {
        let reader_auth = doc_request.reader_auth.as_ref();
        if let Some(reader_auth_specified) = reader_auth_specified {
            if reader_auth.is_some() != reader_auth_specified {
                return Err(VerificationProtocolError::InvalidRequest(
                    "Inconsistent reader-auth: specified for one DocRequest, not specified for another"
                        .to_string(),
                ));
            }
        } else {
            reader_auth_specified = Some(reader_auth.is_some());
        }

        if let Some(reader_auth) = reader_auth {
            let certificate = extract_verifier_ceritificate(
                reader_auth,
                session_transcript,
                &doc_request.items_request,
                certificate_validator,
                verify_fn,
            )
            .await?;

            if let Some(result_certificate) = &result_certificate {
                if result_certificate.fingerprint != certificate.fingerprint {
                    return Err(VerificationProtocolError::InvalidRequest(
                        "Inconsistent reader-auth: different certificates used".to_string(),
                    ));
                }
            } else {
                result_certificate = Some(certificate);
            }
        }
    }

    Ok(result_certificate.map(IdentifierDetails::Certificate))
}

/// extracts verifier details + checks signature of readerAuth
async fn extract_verifier_ceritificate(
    reader_auth: &CoseSign1,
    session_transcript: &SessionTranscript,
    items_request: &EmbeddedCbor<ItemsRequest>,
    certificate_validator: &dyn CertificateValidator,
    verify_fn: &VerificationFn,
) -> Result<CertificateDetails, VerificationProtocolError> {
    let x5chain = cose_header(&reader_auth.0, iana::HeaderParameter::X5Chain).ok_or(
        VerificationProtocolError::InvalidRequest("Missing readerAuth x5chain".to_string()),
    )?;

    let x5chain = match x5chain {
        ciborium::Value::Bytes(cert) => vec![cert.clone()],
        ciborium::Value::Array(certs) => certs
            .iter()
            .flat_map(|cert| cert.as_bytes().into_iter().cloned())
            .collect(),
        other => {
            return Err(VerificationProtocolError::InvalidRequest(format!(
                "Unexpected value in x5chain header: {other:?}"
            )));
        }
    };
    let pem_chain = der_chain_into_pem_chain(x5chain);

    let validation_context = CertificateValidationOptions::signature_and_revocation(Some(vec![
        EnforceKeyUsage::DigitalSignature,
    ]));

    let ParsedCertificate {
        attributes,
        subject_common_name,
        public_key,
        ..
    } = certificate_validator
        .parse_pem_chain(&pem_chain, validation_context)
        .await
        .error_while("parsing PEM chain")?;

    let verifier_key = public_key
        .public_key_as_jwk()
        .error_while("parsing verifier key")?;

    try_verify_reader_auth(
        reader_auth,
        session_transcript.to_owned(),
        items_request.to_owned(),
        &verifier_key,
        verify_fn,
    )
    .await?;

    Ok(CertificateDetails {
        chain: pem_chain,
        fingerprint: attributes.fingerprint,
        expiry: attributes.not_after,
        subject_common_name,
        x5_references: X5References {
            x5c: true,
            x5u: false,
            x5t_s256: false,
        },
    })
}

async fn try_verify_reader_auth(
    reader_auth: &CoseSign1,
    session_transcript: SessionTranscript,
    items_request: EmbeddedCbor<ItemsRequest>,
    verifier_key: &PublicJwk,
    verify_fn: &VerificationFn,
) -> Result<(), VerificationProtocolError> {
    let reader_authentication = ReaderAuthentication {
        session_transcript,
        items_request,
    };
    let reader_authentication_bytes = EmbeddedCbor::new(reader_authentication)?.into_bytes();

    Ok(try_verify_detached_signature_with_provider(
        &reader_auth.0,
        &reader_authentication_bytes,
        &[],
        verifier_key,
        verify_fn,
    )
    .await
    .error_while("verifying ReaderAuthentication")?)
}
