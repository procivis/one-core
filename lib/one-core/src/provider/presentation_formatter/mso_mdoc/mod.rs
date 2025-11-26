pub(crate) mod model;
pub(crate) mod session_transcript;

use std::borrow::Cow;
use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use coset::{RegisteredLabelWithPrivate, SignatureContext, iana};
use one_crypto::SignerError;
use serde::Deserialize;
use shared_types::DidValue;
use url::Url;
use uuid::Uuid;

use self::model::{
    DeviceAuth, DeviceAuthentication, DeviceNamespaces, DeviceResponse, DeviceResponseVersion,
    DeviceSigned, Document,
};
use self::session_transcript::iso_18013_7::OID4VPDraftHandover;
use self::session_transcript::{Handover, SessionTranscript};
use crate::config::core_config::{FormatType, KeyAlgorithmType, VerificationProtocolType};
use crate::mapper::x509::pem_chain_into_x5c;
use crate::mapper::{decode_cbor_base64, encode_cbor_base64};
use crate::model::key::PublicKeyJwk;
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::cose::{CoseSign1, CoseSign1Builder};
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::mdoc_formatter::util::{
    EmbeddedCbor, IssuerSigned, extract_certificate_from_x5chain_header,
    try_build_algorithm_header, try_extract_holder_public_key, try_extract_mobile_security_object,
};
use crate::provider::credential_formatter::model::{
    AuthenticationFn, IdentifierDetails, PublicKeySource, SignatureProvider, TokenVerifier,
    VerificationFn,
};
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::presentation_formatter::PresentationFormatter;
use crate::provider::presentation_formatter::model::{
    CredentialToPresent, ExtractPresentationCtx, ExtractedPresentation, FormatPresentationCtx,
    FormattedPresentation,
};
use crate::provider::presentation_formatter::mso_mdoc::session_transcript::openid4vp_final1_0::OID4VPFinal1_0Handover;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    pub leeway: u64,
}

pub struct MsoMdocPresentationFormatter {
    pub certificate_validator: Arc<dyn CertificateValidator>,
    pub key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    pub base_url: Option<String>,
    pub params: Params,
}

impl MsoMdocPresentationFormatter {
    pub fn new(
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        certificate_validator: Arc<dyn CertificateValidator>,
        base_url: Option<String>,
    ) -> Self {
        Self {
            base_url,
            certificate_validator,
            params: Params { leeway: 60 },
            key_algorithm_provider,
        }
    }
}

#[async_trait]
impl PresentationFormatter for MsoMdocPresentationFormatter {
    async fn format_presentation(
        &self,
        credentials_to_present: Vec<CredentialToPresent>,
        holder_binding_fn: AuthenticationFn,
        _holder_did: &Option<DidValue>,
        context: FormatPresentationCtx,
    ) -> Result<FormattedPresentation, FormatterError> {
        let FormatPresentationCtx {
            mdoc_session_transcript: Some(session_transcript),
            ..
        } = context
        else {
            return Err(FormatterError::Failed(format!(
                "Cannot format mdoc presentation invalid context `{context:?}`"
            )));
        };

        let tokens: Vec<String> = credentials_to_present
            .iter()
            .map(|cred| {
                if cred.credential_format != FormatType::Mdoc {
                    return Err(FormatterError::CouldNotFormat(format!(
                        "Unsupported credential format: {}",
                        cred.credential_format
                    )));
                }
                Ok(cred.raw_credential.clone())
            })
            .collect::<Result<Vec<String>, FormatterError>>()?;

        let mut documents = Vec::with_capacity(tokens.len());
        for token in tokens {
            let issuer_signed: IssuerSigned = decode_cbor_base64(&token)?;
            let mso = try_extract_mobile_security_object(&issuer_signed.issuer_auth)?;
            let doc_type = mso.doc_type;
            let algorithm = holder_binding_fn
                .get_key_algorithm()
                .map_err(|key_type| FormatterError::Failed(format!("Failed mapping algorithm `{key_type}` to name compatible with allowed COSE Algorithms")))?;

            let device_signed = try_build_device_signed(
                &*holder_binding_fn,
                algorithm,
                &doc_type,
                &session_transcript,
            )
            .await?;

            let document = Document {
                doc_type,
                issuer_signed,
                device_signed,
                errors: None,
            };

            documents.push(document);
        }

        let device_response = DeviceResponse {
            version: DeviceResponseVersion::V1_0,
            documents: Some(documents),
            document_errors: None,
            // this will be != 0 if document errors is not None
            status: 0,
        };

        Ok(FormattedPresentation {
            vp_token: encode_cbor_base64(device_response)?,
            oidc_format: "mso_mdoc".to_string(),
        })
    }

    async fn extract_presentation(
        &self,
        presentation: &str,
        verification_fn: VerificationFn,
        context: ExtractPresentationCtx,
    ) -> Result<ExtractedPresentation, FormatterError> {
        let device_response_signed: DeviceResponse = decode_cbor_base64(presentation)?;

        let documents =
            device_response_signed
                .documents
                .ok_or(FormatterError::CouldNotExtractPresentation(
                    "Missing docs".to_string(),
                ))?;

        let mut tokens: Vec<String> = Vec::with_capacity(documents.len());

        let (session_transcript, nonce) = self.extract_presentation_context(&context)?;

        let mut presentation_issuer_jwk = None;
        // can we have more than one document?
        for document in documents {
            let issuer_signed = document.issuer_signed;

            let cert_details = extract_certificate_from_x5chain_header(
                &*self.certificate_validator,
                &issuer_signed.issuer_auth,
                true,
            )
            .await?;

            let x5c = pem_chain_into_x5c(&cert_details.chain).map_err(|err| {
                FormatterError::CouldNotExtractPresentation(format!("Failed to create x5c: {err}"))
            })?;
            try_verify_issuer_auth(&issuer_signed.issuer_auth, &x5c, &verification_fn).await?;

            let holder_jwk = try_extract_holder_public_key(&issuer_signed.issuer_auth)?;

            //try verify device signed
            let device_signed = document.device_signed;
            let doc_type = document.doc_type;

            let signature: coset::CoseSign1 = device_signed
                .device_auth
                .device_signature
                .ok_or(FormatterError::CouldNotExtractPresentation(
                    "Missing device signature".to_owned(),
                ))?
                .0;

            try_verify_device_signed(
                session_transcript.to_owned(),
                &doc_type,
                &signature,
                &holder_jwk,
                &verification_fn,
            )
            .await?;

            presentation_issuer_jwk = Some(holder_jwk);
            tokens.push(encode_cbor_base64(issuer_signed)?)
        }

        // todo transfer issued and expires from the token
        Ok(ExtractedPresentation {
            id: Some(Uuid::new_v4().to_string()),
            issued_at: context.issuance_date,
            expires_at: context.expiration_date,
            issuer: presentation_issuer_jwk.map(IdentifierDetails::Key),
            nonce,
            credentials: tokens,
        })
    }

    async fn extract_presentation_unverified(
        &self,
        presentation: &str,
        context: ExtractPresentationCtx,
    ) -> Result<ExtractedPresentation, FormatterError> {
        let device_response_signed: DeviceResponse = decode_cbor_base64(presentation)?;

        let documents =
            device_response_signed
                .documents
                .ok_or(FormatterError::CouldNotExtractPresentation(
                    "Missing docs".to_string(),
                ))?;

        let tokens = documents
            .into_iter()
            .map(|doc| encode_cbor_base64(doc.issuer_signed))
            .collect::<Result<Vec<String>, FormatterError>>()?;

        // todo transfer issued and expires from the token
        Ok(ExtractedPresentation {
            id: Some(Uuid::new_v4().to_string()),
            issued_at: context.issuance_date,
            expires_at: context.expiration_date,
            issuer: None,
            nonce: context.nonce,
            credentials: tokens,
        })
    }

    fn get_leeway(&self) -> u64 {
        self.params.leeway
    }
}

impl MsoMdocPresentationFormatter {
    fn extract_presentation_context(
        &self,
        context: &ExtractPresentationCtx,
    ) -> Result<(SessionTranscript, Option<String>), FormatterError> {
        // ISO mDL:
        if context.verification_protocol_type == VerificationProtocolType::IsoMdl {
            let Some(session_transcript) = context.mdoc_session_transcript.as_ref() else {
                return Err(FormatterError::CouldNotExtractPresentation(
                    "missing ISO mDL session transcript".to_string(),
                ));
            };
            let session_transcript = ciborium::from_reader(session_transcript.as_slice())
                .context("session_transcript deserialization error")
                .map_err(|e| FormatterError::Failed(e.to_string()))?;

            return Ok((session_transcript, None));
        }

        // OpenID4VP:
        let nonce = context
            .nonce
            .as_ref()
            .ok_or(FormatterError::CouldNotExtractPresentation(
                "Missing nonce".to_owned(),
            ))?
            .to_string();

        let client_id = context
            .client_id
            .clone()
            .or_else(|| {
                // fallback for backwards compatibility (also note "base_url" is not available on mobile verifier)
                let base_url = self.base_url.as_ref()?;
                Url::parse(&format!("{base_url}/ssi/openid4vp/draft-20/response"))
                    .map(|u| u.to_string())
                    .ok()
            })
            .ok_or_else(|| {
                FormatterError::CouldNotExtractPresentation(
                    "Could not create client_id for validation".to_owned(),
                )
            })?;

        let response_uri = context
            .response_uri
            .as_deref()
            .unwrap_or(client_id.as_str());

        let handover = match &context.verification_protocol_type {
            VerificationProtocolType::OpenId4VpFinal1_0 => Handover::OID4VPFinal1_0(
                OID4VPFinal1_0Handover::compute(
                    &client_id,
                    response_uri,
                    &nonce,
                    context.verifier_key.as_ref(),
                )
                .map_err(|e| FormatterError::Failed(e.to_string()))?,
            ),
            // proximity V2 (using dcql)
            VerificationProtocolType::OpenId4VpProximityDraft00
                if context.format_nonce.is_none() =>
            {
                Handover::OID4VPFinal1_0(
                    OID4VPFinal1_0Handover::compute(
                        &client_id,
                        response_uri,
                        &nonce,
                        context.verifier_key.as_ref(),
                    )
                    .map_err(|e| FormatterError::Failed(e.to_string()))?,
                )
            }
            _ => {
                let mdoc_generated_nonce = context.format_nonce.as_ref().ok_or(
                    FormatterError::CouldNotExtractPresentation(
                        "Missing mdoc_generated_nonce".to_owned(),
                    ),
                )?;

                Handover::Iso18013_7AnnexB(
                    OID4VPDraftHandover::compute(
                        &client_id,
                        response_uri,
                        &nonce,
                        mdoc_generated_nonce,
                    )
                    .map_err(|e| FormatterError::Failed(e.to_string()))?,
                )
            }
        };

        let session_transcript = SessionTranscript {
            device_engagement_bytes: None,
            e_reader_key_bytes: None,
            handover: Some(handover),
        };

        Ok((session_transcript, Some(nonce)))
    }
}

async fn try_verify_issuer_auth(
    CoseSign1(cose_sign1): &CoseSign1,
    chain: &[String],
    verifier: &dyn TokenVerifier,
) -> Result<(), FormatterError> {
    let token = coset::sig_structure_data(
        SignatureContext::CoseSign1,
        cose_sign1.protected.clone(),
        None,
        &[],
        cose_sign1.payload.as_ref().unwrap_or(&vec![]),
    );

    let algorithm = extract_algorithm_from_header(cose_sign1).ok_or_else(|| {
        FormatterError::CouldNotVerify("IssuerAuth is missing algorithm information".to_owned())
    })?;

    let signature = &cose_sign1.signature;

    let params = PublicKeySource::X5c { x5c: chain };
    verifier
        .verify(params, algorithm, &token, signature)
        .await
        .map_err(|err| FormatterError::CouldNotVerify(err.to_string()))
}

async fn try_verify_device_signed(
    session_transcript: SessionTranscript,
    doctype: &str,
    signature: &coset::CoseSign1,
    holder_key: &PublicKeyJwk,
    verify_fn: &VerificationFn,
) -> Result<(), FormatterError> {
    let device_namespaces = EmbeddedCbor::new([].into()).map_err(|err| {
        FormatterError::Failed(format!(
            "CBOR serialization failed for DeviceNamespaces: {err}"
        ))
    })?;

    let device_auth = DeviceAuthentication {
        session_transcript,
        doctype: doctype.to_owned(),
        device_namespaces,
    };
    let device_auth_bytes = EmbeddedCbor::new(device_auth)
        .map_err(|err| {
            FormatterError::Failed(format!(
                "CBOR serialization failed for DeviceAuthentication: {err}"
            ))
        })?
        .into_bytes();

    try_verify_detached_signature_with_provider(
        signature,
        &device_auth_bytes,
        &[],
        holder_key,
        verify_fn,
    )
    .await
    .map_err(|e| FormatterError::CouldNotSign(e.to_string()))
}

fn extract_algorithm_from_header(cose_sign1: &coset::CoseSign1) -> Option<KeyAlgorithmType> {
    let alg = &cose_sign1.protected.header.alg;

    if let Some(RegisteredLabelWithPrivate::Assigned(algorithm)) = alg {
        match algorithm {
            iana::Algorithm::ES256 => Some(KeyAlgorithmType::Ecdsa),
            iana::Algorithm::EdDSA => Some(KeyAlgorithmType::Eddsa),
            _ => None,
        }
    } else {
        None
    }
}

async fn try_verify_detached_signature_with_provider(
    device_signature: &coset::CoseSign1,
    payload: &[u8],
    external_aad: &[u8],
    issuer_key: &PublicKeyJwk,
    verifier: &dyn TokenVerifier,
) -> Result<(), SignerError> {
    let sig_data = coset::sig_structure_data(
        SignatureContext::CoseSign1,
        device_signature.protected.clone(),
        None,
        external_aad,
        payload,
    );

    let algorithm = extract_algorithm_from_header(device_signature).ok_or(
        SignerError::CouldNotVerify("Missing or invalid signature algorithm".to_string()),
    )?;

    let signature = &device_signature.signature;

    let params = PublicKeySource::Jwk {
        jwk: Cow::Borrowed(issuer_key),
    };
    verifier
        .verify(params, algorithm, &sig_data, signature)
        .await
}

async fn try_build_device_signed(
    auth_fn: &dyn SignatureProvider,
    algorithm: KeyAlgorithmType,
    doctype: &str,
    session_transcript_bytes: &[u8],
) -> Result<DeviceSigned, FormatterError> {
    let session_transcript = ciborium::from_reader(session_transcript_bytes)
        .map_err(|err| FormatterError::Failed(format!("invalid session transcript: {err}")))?;
    let device_namespaces = EmbeddedCbor::<DeviceNamespaces>::new([].into()).map_err(|err| {
        FormatterError::Failed(format!(
            "CBOR serialization failed for DeviceNamespaces: {err}"
        ))
    })?;

    let device_auth = DeviceAuthentication {
        session_transcript,
        doctype: doctype.to_owned(),
        device_namespaces: device_namespaces.clone(),
    };
    let device_auth_bytes = EmbeddedCbor::new(device_auth)
        .map_err(|err| {
            FormatterError::Failed(format!(
                "CBOR serialization failed for DeviceAuthentication: {err}"
            ))
        })?
        .into_bytes();

    let algorithm_header = try_build_algorithm_header(algorithm)?;
    let cose_sign1 = CoseSign1Builder::new()
        .protected(algorithm_header)
        .try_create_detached_signature_with_provider(&device_auth_bytes, &[], auth_fn)
        .await
        .map_err(|err| FormatterError::CouldNotSign(err.to_string()))?
        .build();

    let device_auth = DeviceAuth {
        device_signature: Some(cose_sign1.into()),
    };

    let device_signed = DeviceSigned {
        name_spaces: device_namespaces,
        device_auth,
    };

    Ok(device_signed)
}
