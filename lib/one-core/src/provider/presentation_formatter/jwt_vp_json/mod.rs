use async_trait::async_trait;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use serde::Deserialize;
use shared_types::DidValue;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::config::core_config::FormatType;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{
    AuthenticationFn, ExtractPresentationCtx, FormatPresentationCtx, FormattedPresentation,
    Presentation, VerificationFn,
};
use crate::provider::presentation_formatter::PresentationFormatter;
use crate::provider::presentation_formatter::jwt_vp_json::model::{
    EnvelopedContent, VP, VPContent, VerifiableCredential,
};
use crate::provider::presentation_formatter::model::{
    CredentialToPresent, PresentationFormatterCapabilities,
};
use crate::util::jwt::Jwt;
use crate::util::jwt::model::JWTPayload;
use crate::util::vcdm_jsonld_contexts::vcdm_v2_base_context;

mod mapper;
mod model;
#[cfg(test)]
mod test;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    pub leeway: u64,
}

pub struct JwtVpPresentationFormatter {
    params: Params,
}

impl JwtVpPresentationFormatter {
    pub fn new() -> Self {
        Self {
            params: Params { leeway: 60 },
        }
    }
}

impl Default for JwtVpPresentationFormatter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PresentationFormatter for JwtVpPresentationFormatter {
    async fn format_presentation(
        &self,
        credentials_to_present: Vec<CredentialToPresent>,
        holder_binding_fn: AuthenticationFn,
        holder_did: &DidValue,
        context: FormatPresentationCtx,
    ) -> Result<FormattedPresentation, FormatterError> {
        let supported_credential_formats = self.get_capabilities().supported_credential_formats;

        let tokens = credentials_to_present
            .iter()
            .map(|cred| {
                if !supported_credential_formats.contains(&cred.credential_format) {
                    return Err(FormatterError::Failed(format!(
                        "Credential format {} not supported",
                        cred.credential_format
                    )));
                }

                Ok(cred.raw_credential.clone())
            })
            .collect::<Result<Vec<String>, FormatterError>>()?;

        let nonce = context.nonce;

        let vp: VP = format_payload(&tokens, nonce)?;

        let now = OffsetDateTime::now_utc();
        let valid_for = Duration::minutes(5);

        let payload = JWTPayload {
            issued_at: Some(now),
            expires_at: now.checked_add(valid_for),
            invalid_before: now.checked_sub(Duration::seconds(self.get_leeway() as i64)),
            issuer: Some(holder_did.to_string()),
            subject: Some(holder_did.to_string()),
            jwt_id: Some(Uuid::new_v4().to_string()),
            custom: vp,
            ..Default::default()
        };

        let key_id = holder_binding_fn.get_key_id();

        let jose_alg = holder_binding_fn
            .jose_alg()
            .ok_or(FormatterError::Failed("Invalid key algorithm".to_string()))?;

        let jwt = Jwt::new("JWT".to_owned(), jose_alg, key_id, None, payload);

        let vp_token = jwt.tokenize(Some(holder_binding_fn)).await?;
        Ok(FormattedPresentation {
            vp_token,
            oidc_format: "jwt_vp_json".to_string(),
        })
    }

    async fn extract_presentation(
        &self,
        presentation: &str,
        verification_fn: VerificationFn,
        _context: ExtractPresentationCtx,
    ) -> Result<Presentation, FormatterError> {
        let jwt: Jwt<VP> =
            Jwt::build_from_token(presentation, Some(&verification_fn), None).await?;

        jwt.try_into()
    }

    async fn extract_presentation_unverified(
        &self,
        presentation: &str,
        _context: ExtractPresentationCtx,
    ) -> Result<Presentation, FormatterError> {
        let jwt: Jwt<VP> = Jwt::build_from_token(presentation, None, None).await?;

        jwt.try_into()
    }

    fn get_leeway(&self) -> u64 {
        self.params.leeway
    }

    fn get_capabilities(&self) -> PresentationFormatterCapabilities {
        PresentationFormatterCapabilities {
            supported_credential_formats: vec![
                FormatType::Jwt,
                FormatType::SdJwt,
                FormatType::SdJwtVc,
                FormatType::JsonLdClassic,
                FormatType::JsonLdBbsPlus,
                FormatType::Mdoc,
            ],
        }
    }
}

fn format_payload(credentials: &[String], nonce: Option<String>) -> Result<VP, FormatterError> {
    let mut has_enveloped_presentation = false;

    let tokens = credentials
        .iter()
        .map(|token| {
            if Base64UrlSafeNoPadding::decode_to_vec(token, None).is_ok() {
                let token = format!("data:application/vp+mso_mdoc,{token}");

                let vp = EnvelopedContent {
                    context: Vec::from_iter(vcdm_v2_base_context(None)),
                    id: token,
                    r#type: vec!["EnvelopedVerifiablePresentation".to_owned()],
                };
                has_enveloped_presentation = true;

                Ok(VerifiableCredential::Enveloped(vp))
            } else {
                Ok(VerifiableCredential::Token(token.to_owned()))
            }
        })
        .collect::<Result<Vec<VerifiableCredential>, FormatterError>>()?;

    let types = match has_enveloped_presentation {
        false => vec!["VerifiablePresentation".to_owned()],
        true => vec![
            "VerifiablePresentation".to_owned(),
            "EnvelopedVerifiablePresentation".to_owned(),
        ],
    };

    Ok(VP {
        vp: VPContent {
            context: Vec::from_iter(vcdm_v2_base_context(None)),
            r#type: types,
            verifiable_credential: tokens,
        },
        nonce,
    })
}
