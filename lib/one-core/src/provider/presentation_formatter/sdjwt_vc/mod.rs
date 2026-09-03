use std::sync::Arc;

use async_trait::async_trait;
use one_crypto::CryptoProvider;
use serde::Deserialize;
use serde_json::Value;
use serde_with::{DurationSeconds, serde_as};
use time::Duration;

use crate::error::ContextWithErrorCode;
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
    FormattedPresentation, PresentedTransactionData,
};
use crate::provider::transaction_data::processed_transaction_data::ProcessedTransactionData;

#[cfg(test)]
mod test;

#[serde_as]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    #[serde_as(as = "DurationSeconds<i64>")]
    pub leeway_seconds: Duration,
}

pub struct SdjwtVCPresentationFormatter {
    client: Arc<dyn HttpClient>,
    crypto: Arc<dyn CryptoProvider>,
    certificate_validator: Arc<dyn CertificateValidator>,
    params: Params,
}

impl SdjwtVCPresentationFormatter {
    pub(crate) fn new(
        client: Arc<dyn HttpClient>,
        crypto: Arc<dyn CryptoProvider>,
        certificate_validator: Arc<dyn CertificateValidator>,
    ) -> Self {
        Self {
            client,
            crypto,
            certificate_validator,
            params: Params {
                leeway_seconds: Duration::seconds(60),
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
        context: FormatPresentationCtx,
    ) -> Result<FormattedPresentation, FormatterError> {
        let [credential] = credentials.as_slice() else {
            return Err(FormatterError::CouldNotFormat(format!(
                "SD_JWT_VC presentation formatter only supports single credential presentations, received {} credentials",
                credentials.len()
            )));
        };

        let mut vp_token = credential.credential_token.clone();
        let serialized_credential = vp_token.as_str().into();

        let jwt = parse_token(&serialized_credential)?;
        let decomposed_token =
            Jwt::<Value>::decompose_token(jwt.jwt).error_while("parsing SD-JWT token")?;
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
            transaction_data,
            ..
        } = context
        else {
            return Err(FormatterError::CouldNotFormat(
                "Missing nonce or audience in context, cannot format presentation SD-JWT VC with key binding token".to_owned(),
            ));
        };

        let transaction_data = match transaction_data {
            Some(ProcessedTransactionData::KbJwtClaims(transaction_data)) => {
                Some(Value::Object(transaction_data))
            }
            Some(_) => {
                return Err(FormatterError::CouldNotFormat(
                    "Invalid transaction data".to_owned(),
                ));
            }
            None => None,
        };

        append_key_binding_token(
            &*hasher,
            HolderBindingCtx {
                nonce,
                audience,
                transaction_data,
            },
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
        context: ExtractPresentationCtx,
    ) -> Result<ExtractedPresentation, FormatterError> {
        let (issuer, proof_of_key_possession) = self
            .extract_presentation_internal(token, Some(verification_fn), &*self.crypto, &context)
            .await?;

        Ok(ExtractedPresentation {
            id: proof_of_key_possession.jwt_id,
            issued_at: proof_of_key_possession.issued_at,
            expires_at: proof_of_key_possession.expires_at,
            issuer: Some(issuer),
            nonce: Some(proof_of_key_possession.custom.nonce),
            credentials: vec![token.into()],
            transaction_data: Some(PresentedTransactionData::KbJwtClaims(
                match proof_of_key_possession.custom.transaction_data {
                    Some(Value::Object(claims)) => claims,
                    _ => Default::default(),
                },
            )),
        })
    }

    async fn extract_presentation_unverified(
        &self,
        token: &str,
        context: ExtractPresentationCtx,
    ) -> Result<ExtractedPresentation, FormatterError> {
        let (issuer, proof_of_key_possession) = self
            .extract_presentation_internal(token, None, &*self.crypto, &context)
            .await?;

        Ok(ExtractedPresentation {
            id: proof_of_key_possession.jwt_id,
            issued_at: proof_of_key_possession.issued_at,
            expires_at: proof_of_key_possession.expires_at,
            issuer: Some(issuer),
            nonce: Some(proof_of_key_possession.custom.nonce),
            credentials: vec![token.into()],
            transaction_data: None,
        })
    }

    fn get_leeway(&self) -> Duration {
        self.params.leeway_seconds
    }
}

impl SdjwtVCPresentationFormatter {
    async fn extract_presentation_internal(
        &self,
        token: &str,
        verification: Option<VerificationFn>,
        crypto: &dyn CryptoProvider,
        context: &ExtractPresentationCtx,
    ) -> Result<(IdentifierDetails, JWTPayload<KeyBindingPayload>), FormatterError> {
        let (jwt, _issuer_details, key_binding_token): (Jwt<SdJwtVc>, _, _) =
            Jwt::build_from_token_with_disclosures(
                &token.into(),
                crypto,
                verification.as_ref(),
                Some(&*self.certificate_validator),
                &*self.client,
            )
            .await?;

        let cnf = jwt.payload.proof_of_possession_key.as_ref().ok_or(
            FormatterError::CouldNotExtractPresentation(
                "Missing proof of key possession".to_string(),
            ),
        )?;
        let holder_binding_ctx = match (&context.nonce, &context.client_id) {
            (Some(nonce), Some(client_id)) => Some(HolderBindingCtx {
                nonce: nonce.clone(),
                audience: client_id.clone(),
                transaction_data: None,
            }),
            _ => None,
        };
        let hash_alg = jwt.payload.custom.hash_alg.as_deref().unwrap_or("sha-256");
        let hasher = crypto.get_hasher(hash_alg)?;
        let params = SdJwtHolderBindingParams {
            holder_binding_context: holder_binding_ctx,
            leeway: self.get_leeway(),
        };
        let proof_of_key_possession = Jwt::<SdJwtVc>::verify_holder_binding(
            cnf,
            token,
            key_binding_token.as_deref(),
            &*hasher,
            verification.as_ref(),
            params,
        )
        .await?;
        Ok((
            IdentifierDetails::Key(cnf.jwk.jwk().clone()),
            proof_of_key_possession,
        ))
    }
}
