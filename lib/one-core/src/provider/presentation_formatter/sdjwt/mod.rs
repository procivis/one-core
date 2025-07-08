use std::sync::Arc;

use async_trait::async_trait;
use one_crypto::CryptoProvider;
use serde::Deserialize;
use shared_types::DidValue;
use time::Duration;

use crate::config::core_config::FormatType;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{
    AuthenticationFn, ExtractPresentationCtx, FormatPresentationCtx, FormattedPresentation,
    Presentation, VerificationFn,
};
use crate::provider::credential_formatter::sdjwt::disclosures::parse_token;
use crate::provider::credential_formatter::sdjwt::model::DecomposedToken;
use crate::provider::credential_formatter::sdjwt_formatter::extract_credentials_internal;
use crate::provider::http_client::HttpClient;
use crate::provider::presentation_formatter::PresentationFormatter;
use crate::provider::presentation_formatter::jwt_vp_json::JwtVpPresentationFormatter;
use crate::provider::presentation_formatter::model::{
    CredentialToPresent, PresentationFormatterCapabilities,
};
use crate::provider::presentation_formatter::sdjwt::model::Sdvp;
use crate::util::jwt::Jwt;

mod model;

#[cfg(test)]
mod test;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    pub leeway: u64,
}

pub struct SdjwtPresentationFormatter {
    client: Arc<dyn HttpClient>,
    crypto: Arc<dyn CryptoProvider>,
    params: Params,
}

impl SdjwtPresentationFormatter {
    pub fn new(client: Arc<dyn HttpClient>, crypto: Arc<dyn CryptoProvider>) -> Self {
        Self {
            client,
            crypto,
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
        holder_did: &DidValue,
        context: FormatPresentationCtx,
    ) -> Result<FormattedPresentation, FormatterError> {
        if credentials.len() != 1 {
            return Err(FormatterError::Failed(
                "SD-JWT formatter only supports single credential presentations".to_string(),
            ));
        }

        let credential = credentials.first().ok_or(FormatterError::Failed(
            "Empty credential list passed to format_presentation".to_string(),
        ))?;

        let DecomposedToken { jwt, .. } = parse_token(&credential.raw_credential)?;
        let decomposed_token = Jwt::<()>::decompose_token(jwt)?;
        if decomposed_token.payload.proof_of_possession_key.is_some() {
            return Ok(FormattedPresentation {
                vp_token: credential.raw_credential.to_owned(),
                oidc_format: "vc+sd-jwt".to_string(),
            });
        }

        if decomposed_token.payload.subject.is_none() {
            return Err(FormatterError::Failed(
                "Credential has neither subject nor cnf claim. Cannot create holder binding proof."
                    .to_string(),
            ));
        }

        // ONE-6254: There is no cnf claim in old legacy SD-JWT credentials. Instead, there is a sub
        // claim referring to a holder did. For legacy compatibility, wrap in W3C verifiable presentation
        // signed by a key matching the holder did.
        // Remove once legacy credential compatibility is no longer needed.
        let jwt_formatter = JwtVpPresentationFormatter::new();
        jwt_formatter
            .format_presentation(credentials, holder_binding_fn, holder_did, context)
            .await
    }

    async fn extract_presentation(
        &self,
        presentation: &str,
        verification_fn: VerificationFn,
        _context: ExtractPresentationCtx,
    ) -> Result<Presentation, FormatterError> {
        self.extract_presentation_internal(presentation, Some(&verification_fn), &*self.client)
            .await
    }

    async fn extract_presentation_unverified(
        &self,
        presentation: &str,
        _context: ExtractPresentationCtx,
    ) -> Result<Presentation, FormatterError> {
        self.extract_presentation_internal(presentation, None, &*self.client)
            .await
    }

    fn get_leeway(&self) -> u64 {
        self.params.leeway
    }

    fn get_capabilities(&self) -> PresentationFormatterCapabilities {
        PresentationFormatterCapabilities {
            supported_credential_formats: vec![FormatType::SdJwtVc, FormatType::SdJwt],
        }
    }
}

impl SdjwtPresentationFormatter {
    async fn extract_presentation_internal(
        &self,
        token: &str,
        verification: Option<&VerificationFn>,
        http_client: &dyn HttpClient,
    ) -> Result<Presentation, FormatterError> {
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

        let presentation = Presentation {
            id: proof_of_key_possesion.jwt_id,
            issued_at: proof_of_key_possesion.issued_at,
            expires_at: proof_of_key_possesion.expires_at,
            issuer_did: credential.subject,
            nonce: Some(proof_of_key_possesion.custom.nonce),
            credentials: vec![token.to_string()],
        };

        Ok(presentation)
    }
}
