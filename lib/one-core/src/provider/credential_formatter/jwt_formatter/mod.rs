//! Implementations for JWT credential format.

use async_trait::async_trait;
use mapper::format_vc;
use model::{VCContent, VPContent, VC, VP};
use serde::Deserialize;
use serde_json::json;
use shared_types::DidValue;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::json_ld::model::ContextType;
use super::jwt::model::JWTPayload;
use super::jwt::Jwt;
use super::model::{Context, CredentialSubject, Issuer};
use crate::model::did::Did;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{
    AuthenticationFn, CredentialData, CredentialPresentation, DetailCredential,
    ExtractPresentationCtx, FormatPresentationCtx, FormatterCapabilities, Presentation,
    VerificationFn,
};
use crate::provider::credential_formatter::CredentialFormatter;
use crate::provider::revocation::bitstring_status_list::model::StatusPurpose;
use crate::util::vcdm_jsonld_contexts::vcdm_v2_base_context;

#[cfg(test)]
mod test;

mod mapper;
mod model;

pub struct JWTFormatter {
    params: Params,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    pub leeway: u64,
    pub embed_layout_properties: bool,
}

impl JWTFormatter {
    pub fn new(params: Params) -> Self {
        Self { params }
    }
}

#[async_trait]
impl CredentialFormatter for JWTFormatter {
    async fn format_credentials(
        &self,
        credential: CredentialData,
        holder_did: &Option<DidValue>,
        algorithm: &str,
        additional_context: Vec<ContextType>,
        additional_types: Vec<String>,
        auth_fn: AuthenticationFn,
        _json_ld_context_url: Option<String>,
        _custom_subject_name: Option<String>,
    ) -> Result<String, FormatterError> {
        let issued_at = credential.issuance_date;
        let expires_at = issued_at.checked_add(credential.valid_for);
        let credential_id = credential.id.clone();

        let issuer = credential.issuer_did.clone();
        let holder_did = holder_did.as_ref().ok_or(FormatterError::MissingHolder)?;

        let vc = format_vc(
            credential,
            issuer.clone(),
            additional_context,
            additional_types,
            self.params.embed_layout_properties,
        )?;

        let payload = JWTPayload {
            issued_at: Some(issued_at),
            expires_at,
            invalid_before: issued_at.checked_sub(Duration::seconds(self.get_leeway() as i64)),
            issuer: Some(issuer.to_did_value().to_string()),
            subject: Some(holder_did.to_string()),
            jwt_id: credential_id,
            custom: vc,
            nonce: None,
        };

        let key_id = auth_fn.get_key_id();
        let jwt = Jwt::new("JWT".to_owned(), algorithm.to_owned(), key_id, payload);

        jwt.tokenize(auth_fn).await
    }

    async fn format_bitstring_status_list(
        &self,
        revocation_list_url: String,
        issuer_did: &Did,
        encoded_list: String,
        algorithm: String,
        auth_fn: AuthenticationFn,
        status_purpose: StatusPurpose,
    ) -> Result<String, FormatterError> {
        let issuer = Issuer::Url(
            issuer_did
                .did
                .as_str()
                .parse()
                .map_err(|_| FormatterError::Failed("Invalid issuer DID".to_string()))?,
        );

        let subject_id = format!("{}#list", revocation_list_url);
        let credential_subject = CredentialSubject {
            values: [
                ("id".into(), json!(subject_id)),
                ("type".into(), json!("BitstringStatusList")),
                ("statusPurpose".into(), json!(status_purpose)),
                ("encodedList".into(), json!(encoded_list)),
            ]
            .into_iter()
            .collect(),
        };

        let vc = VC {
            vc: VCContent {
                context: vec![ContextType::Url(Context::CredentialsV2.to_url())],
                id: Some(revocation_list_url.to_owned()),
                r#type: vec![
                    "VerifiableCredential".to_string(),
                    "BitstringStatusListCredential".to_string(),
                ],
                issuer: Some(issuer),
                valid_from: Some(OffsetDateTime::now_utc()),
                credential_subject,
                credential_status: vec![],
                credential_schema: None,
                valid_until: None,
            },
        };

        let payload = JWTPayload {
            issuer: Some(issuer_did.did.to_string()),
            jwt_id: Some(revocation_list_url),
            subject: Some(subject_id),
            custom: vc,
            issued_at: None,
            expires_at: None,
            invalid_before: None,
            nonce: None,
        };

        let jwt = Jwt::new("JWT".to_owned(), algorithm, None, payload);

        jwt.tokenize(auth_fn).await
    }

    async fn extract_credentials(
        &self,
        token: &str,
        verification: VerificationFn,
    ) -> Result<DetailCredential, FormatterError> {
        // Build fails if verification fails
        let jwt: Jwt<VC> = Jwt::build_from_token(token, Some(verification)).await?;

        Ok(jwt.into())
    }

    async fn extract_credentials_unverified(
        &self,
        token: &str,
    ) -> Result<DetailCredential, FormatterError> {
        let jwt: Jwt<VC> = Jwt::build_from_token(token, None).await?;

        Ok(jwt.into())
    }

    async fn format_credential_presentation(
        &self,
        credential: CredentialPresentation,
    ) -> Result<String, FormatterError> {
        Ok(credential.token)
    }

    async fn format_presentation(
        &self,
        tokens: &[String],
        holder_did: &DidValue,
        algorithm: &str,
        auth_fn: AuthenticationFn,
        FormatPresentationCtx { nonce, .. }: FormatPresentationCtx,
    ) -> Result<String, FormatterError> {
        let vp: VP = format_payload(tokens);

        let now = OffsetDateTime::now_utc();
        let valid_for = time::Duration::minutes(5);

        let payload = JWTPayload {
            issued_at: Some(now),
            expires_at: now.checked_add(valid_for),
            invalid_before: now.checked_sub(Duration::seconds(self.get_leeway() as i64)),
            issuer: Some(holder_did.to_string()),
            subject: Some(holder_did.to_string()),
            jwt_id: Some(Uuid::new_v4().to_string()),
            custom: vp,
            nonce,
        };

        let key_id = auth_fn.get_key_id();
        let jwt = Jwt::new("JWT".to_owned(), algorithm.to_owned(), key_id, payload);

        jwt.tokenize(auth_fn).await
    }

    async fn extract_presentation(
        &self,
        token: &str,
        verification: VerificationFn,
        _context: ExtractPresentationCtx,
    ) -> Result<Presentation, FormatterError> {
        // Build fails if verification fails
        let jwt: Jwt<VP> = Jwt::build_from_token(token, Some(verification)).await?;

        Ok(jwt.into())
    }

    fn get_leeway(&self) -> u64 {
        self.params.leeway
    }

    fn get_capabilities(&self) -> FormatterCapabilities {
        FormatterCapabilities {
            signing_key_algorithms: vec![
                "EDDSA".to_owned(),
                "ES256".to_owned(),
                "DILITHIUM".to_owned(),
            ],
            features: vec!["SUPPORTS_CREDENTIAL_DESIGN".to_string()],
            selective_disclosure: vec![],
            issuance_did_methods: vec![
                "KEY".to_string(),
                "WEB".to_string(),
                "JWK".to_string(),
                "X509".to_string(),
            ],
            issuance_exchange_protocols: vec![
                "OPENID4VC".to_string(),
                "PROCIVIS_TEMPORARY".to_string(),
            ],
            proof_exchange_protocols: vec![
                "OPENID4VC".to_string(),
                "PROCIVIS_TEMPORARY".to_string(),
            ],
            revocation_methods: vec![
                "NONE".to_string(),
                "BITSTRINGSTATUSLIST".to_string(),
                "LVVC".to_string(),
            ],
            verification_key_algorithms: vec![
                "EDDSA".to_string(),
                "ES256".to_string(),
                "DILITHIUM".to_string(),
            ],
            verification_key_storages: vec![
                "INTERNAL".to_string(),
                "AZURE_VAULT".to_string(),
                "SECURE_ELEMENT".to_string(),
            ],
            allowed_schema_ids: vec![],
            datatypes: vec![
                "STRING".to_string(),
                "BOOLEAN".to_string(),
                "EMAIL".to_string(),
                "DATE".to_string(),
                "STRING".to_string(),
                "COUNT".to_string(),
                "BIRTH_DATE".to_string(),
                "NUMBER".to_string(),
                "PICTURE".to_string(),
                "OBJECT".to_string(),
                "ARRAY".to_string(),
            ],
            forbidden_claim_names: vec!["0".to_string()],
        }
    }

    async fn extract_presentation_unverified(
        &self,
        token: &str,
        _context: ExtractPresentationCtx,
    ) -> Result<Presentation, FormatterError> {
        let jwt: Jwt<VP> = Jwt::build_from_token(token, None).await?;

        Ok(jwt.into())
    }
}

fn format_payload(credentials: &[String]) -> VP {
    VP {
        vp: VPContent {
            context: vcdm_v2_base_context(None),
            r#type: vec!["VerifiablePresentation".to_owned()],
            verifiable_credential: credentials.to_vec(),
        },
    }
}
