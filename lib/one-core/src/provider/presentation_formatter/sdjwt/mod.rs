use std::sync::Arc;

use async_trait::async_trait;
use one_crypto::CryptoProvider;
use serde::Deserialize;
use serde_json::Value;
use shared_types::DidValue;
use time::Duration;

use crate::config::core_config::FormatType;
use crate::proto::http_client::HttpClient;
use crate::proto::jwt::Jwt;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{
    AuthenticationFn, HolderBindingCtx, VerificationFn,
};
use crate::provider::credential_formatter::sdjwt::append_key_binding_token;
use crate::provider::credential_formatter::sdjwt::disclosures::parse_token;
use crate::provider::credential_formatter::sdjwt_formatter::extract_credentials_internal;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::presentation_formatter::PresentationFormatter;
use crate::provider::presentation_formatter::jwt_vp_json::JwtVpPresentationFormatter;
use crate::provider::presentation_formatter::model::{
    CredentialToPresent, ExtractPresentationCtx, ExtractedPresentation, FormatPresentationCtx,
    FormattedPresentation,
};
use crate::provider::presentation_formatter::sdjwt::model::Sdvp;

mod model;

#[cfg(test)]
mod test;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    pub leeway: u64,
}

// TODO ONE-6774: Remove once productive holders have been updated to release v1.57+
pub struct SdjwtPresentationFormatter {
    client: Arc<dyn HttpClient>,
    crypto: Arc<dyn CryptoProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    params: Params,
}

impl SdjwtPresentationFormatter {
    pub fn new(
        client: Arc<dyn HttpClient>,
        crypto: Arc<dyn CryptoProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    ) -> Self {
        Self {
            client,
            crypto,
            key_algorithm_provider,
            params: Params { leeway: 60 },
        }
    }
}

#[async_trait]
impl PresentationFormatter for SdjwtPresentationFormatter {
    async fn format_presentation(
        &self,
        credentials: Vec<CredentialToPresent>,
        holder_binding_fn: AuthenticationFn,
        holder_did: &Option<DidValue>,
        context: FormatPresentationCtx,
    ) -> Result<FormattedPresentation, FormatterError> {
        let mut processed_credentials = Vec::with_capacity(credentials.len());

        for credential in &credentials {
            let mut vp_token = credential.credential_token.clone();
            let jwt = parse_token(&vp_token)?;
            let jwt_payload = Jwt::<Value>::decompose_token(jwt.jwt)?.payload;

            // The CNF claim is optional as per https://www.w3.org/TR/vc-jose-cose/#cnf
            // We only append a key binding token if the CNF is present
            // All presented credentials are wrapped in a JWT verifiable presentation
            if jwt_payload.proof_of_possession_key.is_none() {
                processed_credentials.push(CredentialToPresent {
                    credential_token: vp_token,
                    credential_format: FormatType::SdJwt,
                    lvvc_credential_token: credential.lvvc_credential_token.clone(),
                });

                continue;
            }

            let FormatPresentationCtx {
                nonce: Some(nonce),
                audience: Some(audience),
                ..
            } = context.clone()
            else {
                return Err(FormatterError::Failed(
                "Missing nonce or audience in context, cannot format presentation SD-JWT with key binding token".to_owned(),
            ));
            };

            let hash_alg = jwt_payload
                .custom
                .get("_sd_alg")
                .and_then(|alg| alg.as_str())
                .unwrap_or("sha-256");

            let hasher = self.crypto.get_hasher(hash_alg)?;

            append_key_binding_token(
                &*hasher,
                HolderBindingCtx {
                    nonce: nonce.clone(),
                    audience: audience.clone(),
                },
                &*holder_binding_fn,
                &mut vp_token,
            )
            .await?;

            processed_credentials.push(CredentialToPresent {
                credential_token: vp_token,
                credential_format: FormatType::SdJwt,
                lvvc_credential_token: credential.lvvc_credential_token.clone(),
            });
        }

        let jwt_formatter = JwtVpPresentationFormatter::new(self.key_algorithm_provider.clone());

        jwt_formatter
            .format_presentation(
                processed_credentials,
                holder_binding_fn,
                holder_did,
                context,
            )
            .await
    }

    async fn extract_presentation(
        &self,
        presentation: &str,
        verification_fn: VerificationFn,
        _context: ExtractPresentationCtx,
    ) -> Result<ExtractedPresentation, FormatterError> {
        self.extract_presentation_internal(presentation, Some(&verification_fn), &*self.client)
            .await
    }

    async fn extract_presentation_unverified(
        &self,
        presentation: &str,
        _context: ExtractPresentationCtx,
    ) -> Result<ExtractedPresentation, FormatterError> {
        self.extract_presentation_internal(presentation, None, &*self.client)
            .await
    }

    fn get_leeway(&self) -> u64 {
        self.params.leeway
    }
}

impl SdjwtPresentationFormatter {
    async fn extract_presentation_internal(
        &self,
        token: &str,
        verification: Option<&VerificationFn>,
        http_client: &dyn HttpClient,
    ) -> Result<ExtractedPresentation, FormatterError> {
        // W3C VP SD-JWT tokens and SD-JWT tokens.
        let as_jwt_vp: Result<Jwt<Sdvp>, FormatterError> =
            Jwt::build_from_token(token, verification, None)
                .await
                .map_err(|e| FormatterError::Failed(format!("Failed to build Jwt<Sdvp>: {e}")));

        if let Ok(jwt_vp) = as_jwt_vp {
            return jwt_vp.try_into().map_err(|e| {
                FormatterError::Failed(format!("Failed to convert Jwt<Sdvp> to Presentation: {e}"))
            });
        }

        let (credential, proof_of_key_possesion) = extract_credentials_internal(
            token,
            verification,
            &*self.crypto,
            None,
            Duration::seconds(self.get_leeway() as i64),
            http_client,
        )
        .await?;

        let proof_of_key_possesion = proof_of_key_possesion.ok_or(FormatterError::Failed(
            "Missing proof of key possesion".to_string(),
        ))?;

        let presentation = ExtractedPresentation {
            id: proof_of_key_possesion.jwt_id,
            issued_at: proof_of_key_possesion.issued_at,
            expires_at: proof_of_key_possesion.expires_at,
            issuer: credential.subject,
            nonce: Some(proof_of_key_possesion.custom.nonce),
            credentials: vec![token.to_string()],
        };

        Ok(presentation)
    }
}
