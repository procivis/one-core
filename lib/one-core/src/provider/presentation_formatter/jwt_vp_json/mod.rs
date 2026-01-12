use std::sync::Arc;

use async_trait::async_trait;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use serde::Deserialize;
use shared_types::DidValue;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::config::core_config::FormatType;
use crate::proto::jwt::model::JWTPayload;
use crate::proto::jwt::{Jwt, JwtPublicKeyInfo};
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{AuthenticationFn, VerificationFn};
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::presentation_formatter::PresentationFormatter;
use crate::provider::presentation_formatter::jwt_vp_json::model::{
    EnvelopedContent, VP, VPContent, VerifiableCredential,
};
use crate::provider::presentation_formatter::model::{
    CredentialToPresent, ExtractPresentationCtx, ExtractedPresentation, FormatPresentationCtx,
    FormattedPresentation,
};
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
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
}

impl JwtVpPresentationFormatter {
    pub fn new(key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>) -> Self {
        Self {
            params: Params { leeway: 60 },
            key_algorithm_provider,
        }
    }
}

#[async_trait]
impl PresentationFormatter for JwtVpPresentationFormatter {
    async fn format_presentation(
        &self,
        credentials_to_present: Vec<CredentialToPresent>,
        holder_binding_fn: AuthenticationFn,
        holder_did: &Option<DidValue>,
        context: FormatPresentationCtx,
    ) -> Result<FormattedPresentation, FormatterError> {
        let supported_credential_formats = [
            FormatType::Jwt,
            FormatType::SdJwt,
            FormatType::SdJwtVc,
            FormatType::JsonLdClassic,
            FormatType::JsonLdBbsPlus,
            FormatType::Mdoc,
        ];

        for credential in &credentials_to_present {
            if !supported_credential_formats.contains(&credential.credential_format) {
                return Err(FormatterError::Failed(format!(
                    "Credential format {} not supported",
                    credential.credential_format
                )));
            }
        }

        // LVVC credentials are included in the same presentation, alongside the regular credentials
        let credentials_with_lvvcs = credentials_to_present
            .into_iter()
            .flat_map(|credential| match credential.lvvc_credential_token {
                Some(lvvc) => vec![credential.credential_token, lvvc],
                None => vec![credential.credential_token],
            })
            .collect::<Vec<String>>();

        let vp: VP = format_payload(&credentials_with_lvvcs, context.nonce)?;

        let now = OffsetDateTime::now_utc();
        let valid_for = Duration::minutes(5);

        let holder_did = holder_did.as_ref().map(|did| did.to_string());
        let payload = JWTPayload {
            issued_at: Some(now),
            expires_at: now.checked_add(valid_for),
            invalid_before: now.checked_sub(Duration::seconds(self.get_leeway() as i64)),
            issuer: holder_did.to_owned(),
            subject: holder_did.to_owned(),
            jwt_id: Some(Uuid::new_v4().to_string()),
            custom: vp,
            ..Default::default()
        };

        let key_id = holder_binding_fn.get_key_id();

        let jose_alg = holder_binding_fn
            .jose_alg()
            .ok_or(FormatterError::Failed("Invalid key algorithm".to_string()))?;

        let public_key_info = if holder_did.is_none() {
            let key_algorithm = holder_binding_fn
                .get_key_algorithm()
                .map_err(FormatterError::Failed)?;
            let key_algorithm = self
                .key_algorithm_provider
                .key_algorithm_from_type(key_algorithm)
                .ok_or(FormatterError::Failed("Invalid key algorithm".to_string()))?;
            let key = key_algorithm
                .reconstruct_key(&holder_binding_fn.get_public_key(), None, None)
                .map_err(|e| FormatterError::Failed(e.to_string()))?;
            Some(JwtPublicKeyInfo::Jwk(
                key.public_key_as_jwk()
                    .map_err(|e| FormatterError::Failed(e.to_string()))?,
            ))
        } else {
            None
        };

        let jwt = Jwt::new("JWT".to_owned(), jose_alg, key_id, public_key_info, payload);

        let vp_token = jwt.tokenize(Some(&*holder_binding_fn)).await?;
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
    ) -> Result<ExtractedPresentation, FormatterError> {
        let jwt: Jwt<VP> =
            Jwt::build_from_token(presentation, Some(&verification_fn), None).await?;

        jwt.try_into()
    }

    async fn extract_presentation_unverified(
        &self,
        presentation: &str,
        _context: ExtractPresentationCtx,
    ) -> Result<ExtractedPresentation, FormatterError> {
        let jwt: Jwt<VP> = Jwt::build_from_token(presentation, None, None).await?;

        jwt.try_into()
    }

    fn get_leeway(&self) -> u64 {
        self.params.leeway
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
