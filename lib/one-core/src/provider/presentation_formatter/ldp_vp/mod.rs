use std::sync::Arc;

use async_trait::async_trait;
use indexmap::indexset;
use one_crypto::CryptoProvider;
use serde::Deserialize;
use shared_types::DidValue;
use time::OffsetDateTime;
use url::Url;

pub mod model;
#[cfg(test)]
mod test;

use crate::config::core_config::{FormatType, KeyAlgorithmType};
use crate::mapper::oidc::map_to_openid4vp_format;
use crate::proto::http_client::HttpClient;
use crate::provider::caching_loader::json_ld_context::{ContextCache, JsonLdCachingLoader};
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::json_ld_classic::{
    prepare_proof_hash, sign_proof_hash, verify_proof_signature,
};
use crate::provider::credential_formatter::model::{
    AuthenticationFn, Context, IdentifierDetails, Issuer, VerificationFn,
};
use crate::provider::credential_formatter::vcdm::{ContextType, VcdmProof};
use crate::provider::presentation_formatter::PresentationFormatter;
use crate::provider::presentation_formatter::ldp_vp::model::{
    CredentialEnvelope, LdPresentation, VerifiableCredential,
};
use crate::provider::presentation_formatter::model::{
    CredentialToPresent, ExtractPresentationCtx, ExtractedPresentation, FormatPresentationCtx,
    FormattedPresentation, PresentationFormatterCapabilities,
};
use crate::util::rdf_canonization::json_ld_processor_options;
use crate::util::vcdm_jsonld_contexts::{DEFAULT_ALLOWED_CONTEXTS, is_context_list_valid};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    pub leeway: u64,
    allowed_contexts: Option<Vec<Url>>,
}

pub struct LdpVpPresentationFormatter {
    pub crypto: Arc<dyn CryptoProvider>,
    pub caching_loader: ContextCache,
    pub params: Params,
}

impl LdpVpPresentationFormatter {
    pub fn new(
        crypto: Arc<dyn CryptoProvider>,
        caching_loader: JsonLdCachingLoader,
        client: Arc<dyn HttpClient>,
    ) -> Self {
        Self {
            crypto,
            caching_loader: ContextCache::new(caching_loader, client),
            params: Params {
                leeway: 60,
                allowed_contexts: None,
            },
        }
    }
}

#[async_trait]
impl PresentationFormatter for LdpVpPresentationFormatter {
    async fn format_presentation(
        &self,
        credentials_to_present: Vec<CredentialToPresent>,
        holder_binding_fn: AuthenticationFn,
        holder_did: &DidValue,
        context: FormatPresentationCtx,
    ) -> Result<FormattedPresentation, FormatterError> {
        let json_ld_context = indexset![ContextType::Url(Context::CredentialsV2.to_url())];

        let verifiable_credential: VerifiableCredential = credentials_to_present
            .iter()
            .map(|cred| match cred.credential_format {
                FormatType::JsonLdClassic | FormatType::JsonLdBbsPlus => {
                    serde_json::from_str(cred.raw_credential.as_str())
                        .map_err(|err| FormatterError::CouldNotFormat(err.to_string()))
                }
                _ => {
                    let openid_format_identifier = map_to_openid4vp_format(&cred.credential_format)
                        .map_err(|e| FormatterError::CouldNotFormat(e.to_string()))?;

                    let enveloped = CredentialEnvelope::new(
                        openid_format_identifier,
                        cred.raw_credential.as_str(),
                    );

                    let json_value = serde_json::to_value(enveloped)
                        .map_err(|err| FormatterError::CouldNotFormat(err.to_string()))?;
                    let map = json_value
                        .as_object()
                        .ok_or_else(|| {
                            FormatterError::CouldNotFormat(
                                "Credential must be an object".to_string(),
                            )
                        })?
                        .to_owned();
                    Ok(map)
                }
            })
            .collect::<Result<Vec<_>, FormatterError>>()?;

        let mut presentation = LdPresentation {
            context: json_ld_context.clone(),
            r#type: vec!["VerifiablePresentation".to_string()],
            verifiable_credential,
            holder: holder_did.as_str().parse().map(Issuer::Url).map_err(|_| {
                FormatterError::CouldNotFormat("Holder DID is not a URL".to_string())
            })?,
            proof: None,
        };

        let algorithm = holder_binding_fn
            .get_key_algorithm()
            .map_err(|e| FormatterError::CouldNotFormat(format!("Unsupported algorithm: {e}")))?;

        let cryptosuite = match algorithm {
            KeyAlgorithmType::Eddsa => "eddsa-rdfc-2022",
            KeyAlgorithmType::Ecdsa => "ecdsa-rdfc-2019",
            _ => {
                return Err(FormatterError::CouldNotFormat(format!(
                    "Unsupported algorithm: {algorithm}"
                )));
            }
        };

        let key_id = holder_binding_fn
            .get_key_id()
            .ok_or(FormatterError::CouldNotFormat(
                "Missing jwk key id".to_string(),
            ))?;

        let mut proof = VcdmProof::builder()
            .context(json_ld_context)
            .maybe_nonce(context.nonce)
            .created(OffsetDateTime::now_utc())
            .proof_purpose("authentication")
            .cryptosuite(cryptosuite)
            .verification_method(key_id)
            .build();

        let proof_hash = prepare_proof_hash(
            &presentation,
            &proof,
            &*self.crypto,
            self.caching_loader.to_owned(),
            None,
            json_ld_processor_options(),
        )
        .await?;

        let signed_proof = sign_proof_hash(&proof_hash, holder_binding_fn).await?;

        proof.proof_value = Some(signed_proof);
        proof.context = None;
        presentation.proof = Some(proof);

        let resp = serde_json::to_string(&presentation)
            .map_err(|e| FormatterError::CouldNotFormat(e.to_string()))?;

        Ok(FormattedPresentation {
            vp_token: resp,
            oidc_format: "ldp_vp".to_string(),
        })
    }

    async fn extract_presentation(
        &self,
        presentation: &str,
        verification_fn: VerificationFn,
        _context: ExtractPresentationCtx,
    ) -> Result<ExtractedPresentation, FormatterError> {
        self.extract_presentation_internal(presentation, Some(verification_fn))
            .await
    }

    async fn extract_presentation_unverified(
        &self,
        presentation: &str,
        _context: ExtractPresentationCtx,
    ) -> Result<ExtractedPresentation, FormatterError> {
        self.extract_presentation_internal(presentation, None).await
    }

    fn get_leeway(&self) -> u64 {
        60
    }

    fn get_capabilities(&self) -> PresentationFormatterCapabilities {
        PresentationFormatterCapabilities {
            supported_credential_formats: vec![
                FormatType::JsonLdClassic,
                FormatType::JsonLdBbsPlus,
                FormatType::Mdoc,
                FormatType::Jwt,
                FormatType::SdJwt,
                FormatType::SdJwtVc,
            ],
        }
    }
}

impl LdpVpPresentationFormatter {
    async fn extract_presentation_internal(
        &self,
        presentation: &str,
        verification_fn: Option<VerificationFn>,
    ) -> Result<ExtractedPresentation, FormatterError> {
        let presentation: LdPresentation = serde_json::from_str(presentation)
            .map_err(|e| FormatterError::CouldNotExtractPresentation(e.to_string()))?;

        if let Some(verification_fn) = verification_fn {
            verify_presentation_signature(
                presentation.clone(),
                verification_fn,
                &*self.crypto,
                self.caching_loader.to_owned(),
            )
            .await?;
        }

        if !is_context_list_valid(
            &presentation.context,
            self.params.allowed_contexts.as_ref(),
            &DEFAULT_ALLOWED_CONTEXTS,
            None,
            None,
        ) {
            return Err(FormatterError::CouldNotVerify(
                "Used context is not allowed".to_string(),
            ));
        };

        let credentials: Vec<String> = presentation
            .verifiable_credential
            .iter()
            .map(|token| {
                if token.contains_key("type") && token["type"] == "EnvelopedVerifiableCredential" {
                    let enveloped: CredentialEnvelope =
                        serde_json::from_value(serde_json::Value::Object(token.to_owned()))?;

                    Ok(enveloped.get_token())
                } else {
                    serde_json::to_string(token)
                }
            })
            .collect::<Result<_, _>>()
            .map_err(|err| FormatterError::CouldNotExtractCredentials(err.to_string()))?;

        let proof = presentation.proof.as_ref();
        Ok(ExtractedPresentation {
            id: None,
            issued_at: proof.and_then(|p| p.created),
            expires_at: None,
            issuer: Some(IdentifierDetails::Did(presentation.holder.to_did_value()?)),
            nonce: proof.and_then(|p| p.nonce.to_owned()),
            credentials,
        })
    }
}

pub async fn verify_presentation_signature(
    mut presentation: LdPresentation,
    verification_fn: VerificationFn,
    crypto: &dyn CryptoProvider,
    caching_loader: ContextCache,
) -> Result<(), FormatterError> {
    // Remove proof for canonicalization
    let mut proof = presentation
        .proof
        .take()
        .ok_or(FormatterError::CouldNotVerify("Missing proof".to_owned()))?;
    let proof_value = proof.proof_value.ok_or(FormatterError::CouldNotVerify(
        "Missing proof_value".to_owned(),
    ))?;
    let key_id = proof.verification_method.as_str();
    let issuer_did = &presentation.holder;

    if proof.context.is_none() {
        proof.context = Some(presentation.context.clone());
    }

    // Remove proof value for canonicalization
    proof.proof_value = None;

    let proof_hash = prepare_proof_hash(
        &presentation,
        &proof,
        crypto,
        caching_loader,
        None,
        json_ld_processor_options(),
    )
    .await?;

    verify_proof_signature(
        &proof_hash,
        &proof_value,
        &issuer_did.to_did_value()?,
        key_id,
        &proof.cryptosuite,
        verification_fn,
    )
    .await?;

    Ok(())
}
