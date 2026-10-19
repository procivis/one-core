use std::borrow::Cow;
use std::sync::Arc;

use async_trait::async_trait;
use coset::{HeaderBuilder, ProtectedHeader, RegisteredLabelWithPrivate, SignatureContext, iana};
use serde::Deserialize;
use serde_with::{DurationSeconds, serde_as};
use standardized_types::jwk::PublicJwk;
use time::Duration;
use url::Url;
use uuid::Uuid;

use self::model::{
    DeviceAuth, DeviceAuthentication, DeviceNamespaces, DeviceResponse, DeviceSigned, Document,
};
use self::session_transcript::{Handover, SessionTranscript};
use crate::config::core_config::{FormatType, KeyAlgorithmType, VerificationProtocolType};
use crate::error::ContextWithErrorCode;
use crate::mapper::x509::pem_chain_into_x5c;
use crate::mapper::{decode_cbor_base64, encode_cbor_base64};
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::cose::{CoseSign1, CoseSign1Builder};
use crate::proto::http_client::HttpClient;
use crate::proto::jwt::TokenError;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::mdoc_formatter::util::{
    EmbeddedCbor, IssuerSigned, build_algorithm_header_value,
    extract_certificate_from_x5chain_header, try_extract_holder_public_key,
    try_extract_mobile_security_object,
};
use crate::provider::credential_formatter::model::{
    AuthenticationFn, IdentifierDetails, PublicKeySource, SignatureProvider, TokenVerifier,
    VerificationFn,
};
use crate::provider::presentation_formatter::PresentationFormatter;
use crate::provider::presentation_formatter::model::{
    CredentialToPresent, ExtractPresentationCtx, ExtractedPresentation, FormatPresentationCtx,
    FormattedPresentation, PresentedTransactionData,
};
use crate::provider::presentation_formatter::mso_mdoc::session_transcript::openid4vp_final1_0::OID4VPFinal1_0Handover;
use crate::provider::transaction_data::processed_transaction_data::ProcessedTransactionData;

pub(crate) mod model;
pub(crate) mod session_transcript;

#[serde_as]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    #[serde_as(as = "DurationSeconds<i64>")]
    pub leeway_seconds: Duration,
}

pub struct MsoMdocPresentationFormatter {
    certificate_validator: Arc<dyn CertificateValidator>,
    base_url: Option<String>,
    params: Params,
    client: Arc<dyn HttpClient>,
}

impl MsoMdocPresentationFormatter {
    pub(crate) fn new(
        certificate_validator: Arc<dyn CertificateValidator>,
        base_url: Option<String>,
        client: Arc<dyn HttpClient>,
    ) -> Self {
        Self {
            base_url,
            certificate_validator,
            params: Params {
                leeway_seconds: Duration::seconds(60),
            },
            client,
        }
    }
}

#[async_trait]
impl PresentationFormatter for MsoMdocPresentationFormatter {
    async fn format_presentation(
        &self,
        credentials_to_present: Vec<CredentialToPresent>,
        holder_binding_fn: AuthenticationFn,
        context: FormatPresentationCtx,
    ) -> Result<FormattedPresentation, FormatterError> {
        let FormatPresentationCtx {
            mdoc_session_transcript: Some(session_transcript),
            ..
        } = context
        else {
            return Err(FormatterError::CouldNotFormat(format!(
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
                Ok(cred.credential_token.clone())
            })
            .collect::<Result<Vec<String>, FormatterError>>()?;

        let transaction_data = match context.transaction_data {
            Some(_) if tokens.len() > 1 => {
                return Err(FormatterError::CouldNotFormat(
                    "Transaction data is only supported in single credential presentations"
                        .to_owned(),
                ));
            }
            Some(ProcessedTransactionData::DeviceSignedElements(device_signed_elements)) => {
                Some(device_signed_elements)
            }
            Some(_) => {
                return Err(FormatterError::CouldNotFormat(
                    "Invalid transaction data".to_owned(),
                ));
            }
            None => None,
        };

        let mut documents = Vec::with_capacity(tokens.len());
        for token in tokens {
            let issuer_signed: IssuerSigned = decode_cbor_base64(&token)?;
            let mso = try_extract_mobile_security_object(&issuer_signed.issuer_auth)?;
            let doc_type = mso.doc_type;
            let algorithm = holder_binding_fn
                .get_key_algorithm()
                .map_err(|key_type| FormatterError::CouldNotFormat(format!("Failed mapping algorithm `{key_type}` to name compatible with allowed COSE Algorithms")))?;

            let device_signed = try_build_device_signed(
                &*holder_binding_fn,
                algorithm,
                &doc_type,
                &session_transcript,
                transaction_data.clone(),
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
            version: Default::default(),
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

        let mut tokens = Vec::with_capacity(documents.len());

        let (session_transcript, nonce) = self.extract_presentation_context(&context)?;

        let mut presentation_issuer_jwk = None;
        let mut device_signed_elements = DeviceNamespaces::new();
        // can we have more than one document?
        for document in documents {
            let issuer_signed = document.issuer_signed;

            let cert_details = extract_certificate_from_x5chain_header(
                &*self.certificate_validator,
                &*self.client,
                &issuer_signed.issuer_auth,
                true,
            )
            .await?;

            let x5c = pem_chain_into_x5c(&cert_details.chain).error_while("parsing PEM chain")?;
            try_verify_cose_sign1(&issuer_signed.issuer_auth, &x5c, &verification_fn)
                .await
                .error_while("verifying issuerAuth")?;

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
                &device_signed.name_spaces,
                &signature,
                &holder_jwk,
                &verification_fn,
            )
            .await?;

            for (namespace, elements) in device_signed.name_spaces.into_inner() {
                device_signed_elements
                    .entry(namespace)
                    .or_default()
                    .extend(elements);
            }

            presentation_issuer_jwk = Some(holder_jwk);
            tokens.push(encode_cbor_base64(issuer_signed)?.into())
        }

        // todo transfer issued and expires from the token
        Ok(ExtractedPresentation {
            id: Some(Uuid::new_v4().to_string()),
            issued_at: context.issuance_date,
            expires_at: context.expiration_date,
            issuer: presentation_issuer_jwk.map(IdentifierDetails::Key),
            nonce,
            credentials: tokens,
            transaction_data: Some(PresentedTransactionData::DeviceSignedElements(
                device_signed_elements,
            )),
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
            .map(|doc| Ok(encode_cbor_base64(doc.issuer_signed)?.into()))
            .collect::<Result<_, FormatterError>>()?;

        // todo transfer issued and expires from the token
        Ok(ExtractedPresentation {
            id: Some(Uuid::new_v4().to_string()),
            issued_at: context.issuance_date,
            expires_at: context.expiration_date,
            issuer: None,
            nonce: context.nonce,
            credentials: tokens,
            transaction_data: None,
        })
    }

    fn get_leeway(&self) -> Duration {
        self.params.leeway_seconds
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
            let session_transcript = ciborium::from_reader(session_transcript.as_slice())?;

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
            .ok_or({
                FormatterError::CouldNotExtractPresentation(
                    "Could not create client_id for validation".to_owned(),
                )
            })?;

        let response_uri = context
            .response_uri
            .as_deref()
            .unwrap_or(client_id.as_str());

        let handover = match &context.verification_protocol_type {
            VerificationProtocolType::OpenId4VpFinal1_0 => {
                Handover::OID4VPFinal1_0(OID4VPFinal1_0Handover::compute(
                    &client_id,
                    response_uri,
                    &nonce,
                    context.verifier_key.as_ref(),
                )?)
            }
            // proximity V2 (using dcql)
            VerificationProtocolType::OpenId4VpProximityDraft00
                if context.format_nonce.is_none() =>
            {
                Handover::OID4VPFinal1_0(OID4VPFinal1_0Handover::compute(
                    &client_id,
                    response_uri,
                    &nonce,
                    context.verifier_key.as_ref(),
                )?)
            }
            _ => {
                return Err(FormatterError::CouldNotExtractPresentation(
                    "Unsupported verification protocol type".to_owned(),
                ));
            }
        };

        let session_transcript = SessionTranscript {
            device_engagement_bytes: None,
            e_reader_key_bytes: None,
            handover,
        };

        Ok((session_transcript, Some(nonce)))
    }
}

pub(crate) async fn try_verify_cose_sign1(
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
        FormatterError::CouldNotVerify("CoseSign1 is missing algorithm information".to_owned())
    })?;

    let params = PublicKeySource::X5c { x5c: chain };
    Ok(verifier
        .verify(params, algorithm, &token, &cose_sign1.signature)
        .await
        .error_while("verifying CoseSign1")?)
}

async fn try_verify_device_signed(
    session_transcript: SessionTranscript,
    doctype: &str,
    device_namespaces: &EmbeddedCbor<DeviceNamespaces>,
    signature: &coset::CoseSign1,
    holder_key: &PublicJwk,
    verify_fn: &VerificationFn,
) -> Result<(), FormatterError> {
    let device_auth = DeviceAuthentication {
        session_transcript,
        doctype: doctype.to_owned(),
        device_namespaces: device_namespaces.to_owned(),
    };
    let device_auth_bytes = EmbeddedCbor::new(device_auth)?.into_bytes();

    Ok(try_verify_detached_signature_with_provider(
        signature,
        &device_auth_bytes,
        &[],
        holder_key,
        verify_fn,
    )
    .await
    .error_while("verifying DeviceSigned")?)
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
    issuer_key: &PublicJwk,
    verifier: &dyn TokenVerifier,
) -> Result<(), TokenError> {
    let sig_data = coset::sig_structure_data(
        SignatureContext::CoseSign1,
        device_signature.protected.clone(),
        None,
        external_aad,
        payload,
    );

    let algorithm = extract_algorithm_from_header(device_signature).ok_or(
        TokenError::MissingJOSEAlgorithm("Missing or invalid signature algorithm".to_string()),
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
    device_namespaces: Option<DeviceNamespaces>,
) -> Result<DeviceSigned, FormatterError> {
    let session_transcript = ciborium::from_reader(session_transcript_bytes)?;
    let device_namespaces =
        EmbeddedCbor::<DeviceNamespaces>::new(device_namespaces.unwrap_or_default())?;

    let device_auth = DeviceAuthentication {
        session_transcript,
        doctype: doctype.to_owned(),
        device_namespaces: device_namespaces.clone(),
    };
    let device_auth_bytes = EmbeddedCbor::new(device_auth)?.into_bytes();

    let protected_headers = HeaderBuilder::new()
        .algorithm(build_algorithm_header_value(algorithm)?)
        .build();

    let cose_sign1 = CoseSign1Builder::new()
        .protected(ProtectedHeader {
            original_data: None,
            header: protected_headers,
        })
        .try_create_detached_signature_with_provider(&device_auth_bytes, &[], auth_fn)
        .await
        .error_while("creating signature")?
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
