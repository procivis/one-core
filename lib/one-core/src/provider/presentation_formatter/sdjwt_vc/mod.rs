use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use one_crypto::CryptoProvider;
use serde::Deserialize;
use serde_json::Value;
use shared_types::DidValue;
use time::Duration;

use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::http_client::HttpClient;
use crate::proto::jwt::Jwt;
use crate::proto::jwt::model::JWTPayload;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{
    AuthenticationFn, HolderBindingCtx, IdentifierDetails, VerificationFn,
};
use crate::provider::credential_formatter::sdjwt::disclosures::parse_token;
use crate::provider::credential_formatter::sdjwt::model::KeyBindingPayload;
use crate::provider::credential_formatter::sdjwt::{
    SdJwtHolderBindingParams, append_key_binding_token,
};
use crate::provider::credential_formatter::sdjwtvc_formatter::model::SdJwtVc;
use crate::provider::presentation_formatter::PresentationFormatter;
use crate::provider::presentation_formatter::model::{
    CredentialToPresent, ExtractPresentationCtx, ExtractedPresentation, FormatPresentationCtx,
    FormattedPresentation,
};

#[cfg(test)]
mod test;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    pub leeway: u64,

    // Toggles SWIYU quirks, specifically the malformed `cnf` claim
    #[serde(default)]
    pub swiyu_mode: bool,
}

pub struct SdjwtVCPresentationFormatter {
    client: Arc<dyn HttpClient>,
    crypto: Arc<dyn CryptoProvider>,
    certificate_validator: Arc<dyn CertificateValidator>,
    params: Params,
}

impl SdjwtVCPresentationFormatter {
    pub fn new(
        client: Arc<dyn HttpClient>,
        crypto: Arc<dyn CryptoProvider>,
        certificate_validator: Arc<dyn CertificateValidator>,
        swiyu_mode: bool,
    ) -> Self {
        Self {
            client,
            crypto,
            certificate_validator,
            params: Params {
                leeway: 60,
                swiyu_mode,
            },
        }
    }
}

#[async_trait]
impl PresentationFormatter for SdjwtVCPresentationFormatter {
    async fn format_presentation(
        &self,
        credentials: Vec<CredentialToPresent>,
        holder_binding_fn: AuthenticationFn,
        _holder_did: &Option<DidValue>,
        context: FormatPresentationCtx,
    ) -> Result<FormattedPresentation, FormatterError> {
        let [credential] = credentials.as_slice() else {
            return Err(FormatterError::Failed(format!(
                "SD_JWT_VC presentation formatter only supports single credential presentations, received {} credentials",
                credentials.len()
            )));
        };

        let mut vp_token = credential.credential_token.clone();

        let jwt = parse_token(&vp_token)?;
        let decomposed_token = Jwt::<Value>::decompose_token(jwt.jwt)?;
        let hash_alg = decomposed_token
            .payload
            .custom
            .get("_sd_alg")
            .and_then(|alg| alg.as_str())
            .unwrap_or("sha-256");

        let hasher = self.crypto.get_hasher(hash_alg)?;

        // As per https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-22.html#section-4.3
        // Both nonce and audience are required
        let FormatPresentationCtx {
            nonce: Some(nonce),
            audience: Some(audience),
            ..
        } = context
        else {
            return Err(FormatterError::Failed(
                "Missing nonce or audience in context, cannot format presentation SD-JWT VC with key binding token".to_owned(),
            ));
        };

        append_key_binding_token(
            &*hasher,
            HolderBindingCtx { nonce, audience },
            &*holder_binding_fn,
            &mut vp_token,
        )
        .await?;

        Ok(FormattedPresentation {
            vp_token,
            oidc_format: "vc+sd-jwt".to_string(),
        })
    }

    async fn extract_presentation(
        &self,
        token: &str,
        verification_fn: VerificationFn,
        _context: ExtractPresentationCtx,
    ) -> Result<ExtractedPresentation, FormatterError> {
        let (subject, proof_of_key_possession) = self
            .extract_presentation_internal(
                token,
                Some(verification_fn),
                &*self.crypto,
                Duration::seconds(self.get_leeway() as i64),
            )
            .await?;

        let proof_of_key_possession = proof_of_key_possession.ok_or(FormatterError::Failed(
            "Missing proof of key possession".to_string(),
        ))?;

        Ok(ExtractedPresentation {
            id: proof_of_key_possession.jwt_id,
            issued_at: proof_of_key_possession.issued_at,
            expires_at: proof_of_key_possession.expires_at,
            issuer: subject.map(IdentifierDetails::Did),
            nonce: Some(proof_of_key_possession.custom.nonce),
            credentials: vec![token.to_string()],
        })
    }

    async fn extract_presentation_unverified(
        &self,
        token: &str,
        _context: ExtractPresentationCtx,
    ) -> Result<ExtractedPresentation, FormatterError> {
        let (subject, proof_of_key_possession) = self
            .extract_presentation_internal(
                token,
                None,
                &*self.crypto,
                Duration::seconds(self.get_leeway() as i64),
            )
            .await?;

        let proof_of_key_possession = proof_of_key_possession.ok_or(FormatterError::Failed(
            "Missing proof of key possesion".to_string(),
        ))?;

        Ok(ExtractedPresentation {
            id: proof_of_key_possession.jwt_id,
            issued_at: proof_of_key_possession.issued_at,
            expires_at: proof_of_key_possession.expires_at,
            issuer: subject.map(IdentifierDetails::Did),
            nonce: Some(proof_of_key_possession.custom.nonce),
            credentials: vec![token.to_string()],
        })
    }

    fn get_leeway(&self) -> u64 {
        self.params.leeway
    }
}

impl SdjwtVCPresentationFormatter {
    async fn extract_presentation_internal(
        &self,
        token: &str,
        verification: Option<VerificationFn>,
        crypto: &dyn CryptoProvider,
        leeway: Duration,
    ) -> Result<(Option<DidValue>, Option<JWTPayload<KeyBindingPayload>>), FormatterError> {
        let params = SdJwtHolderBindingParams {
            holder_binding_context: None,
            leeway,
            skip_holder_binding_aud_check: self.params.swiyu_mode, // skip holder binding aud check for SWIYU as aud is randomly populated
        };
        let (jwt, proof_of_key_possession, _): (Jwt<SdJwtVc>, _, _) =
            Jwt::build_from_token_with_disclosures(
                token,
                crypto,
                verification.as_ref(),
                params,
                Some(&*self.certificate_validator),
                &*self.client,
            )
            .await?;

        let subject = jwt
            .payload
            .subject
            .map(|did| DidValue::from_str(&did))
            .transpose()
            .map_err(|e| FormatterError::Failed(e.to_string()))?;

        Ok((subject, proof_of_key_possession))
    }
}
