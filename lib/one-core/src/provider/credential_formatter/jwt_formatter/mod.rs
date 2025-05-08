//! Implementations for JWT credential format.
//! https://datatracker.ietf.org/doc/html/rfc7519

use std::sync::Arc;

use async_trait::async_trait;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use model::{EnvelopedContent, VPContent, VcClaim, VerifiableCredential, VP};
use serde::Deserialize;
use serde_json::json;
use shared_types::DidValue;
use time::{Duration, OffsetDateTime};
use url::Url;
use uuid::Uuid;

use super::jwt::model::JWTPayload;
use super::jwt::Jwt;
use super::model::{CredentialData, Features, HolderBindingCtx, Issuer};
use super::vcdm::{VcdmCredential, VcdmCredentialSubject};
use crate::config::core_config::{
    DidType, IdentifierType, IssuanceProtocolType, KeyAlgorithmType, KeyStorageType,
    RevocationType, VerificationProtocolType,
};
use crate::model::credential_schema::CredentialSchema;
use crate::model::did::Did;
use crate::model::revocation_list::StatusListType;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::jwt_formatter::model::{
    TokenStatusListContent, TokenStatusListSubject,
};
use crate::provider::credential_formatter::model::{
    AuthenticationFn, CredentialPresentation, DetailCredential, ExtractPresentationCtx,
    FormatPresentationCtx, FormatterCapabilities, Presentation, VerificationFn,
};
use crate::provider::credential_formatter::CredentialFormatter;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::revocation::bitstring_status_list::model::StatusPurpose;
use crate::provider::revocation::token_status_list::util::PREFERRED_ENTRY_SIZE;
use crate::util::vcdm_jsonld_contexts::vcdm_v2_base_context;

#[cfg(test)]
mod test;

mod mapper;
pub(crate) mod model;

pub struct JWTFormatter {
    params: Params,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    pub leeway: u64,
    pub embed_layout_properties: bool,
}

impl JWTFormatter {
    pub fn new(params: Params, key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>) -> Self {
        Self {
            params,
            key_algorithm_provider,
        }
    }
}

#[async_trait]
impl CredentialFormatter for JWTFormatter {
    async fn format_credential(
        &self,
        credential_data: CredentialData,
        auth_fn: AuthenticationFn,
    ) -> Result<String, FormatterError> {
        let mut vcdm = credential_data.vcdm;
        let issued_at = vcdm.valid_from.or(vcdm.issuance_date);
        let expires_at = vcdm.valid_until.or(vcdm.expiration_date);
        let credential_id = vcdm.id.clone().map(|id| id.to_string());

        let issuer = vcdm.issuer.as_url().to_string();

        if !self.params.embed_layout_properties {
            vcdm.remove_layout_properties();
        }

        let vc = VcClaim { vc: vcdm.into() };

        let payload = JWTPayload {
            issued_at,
            expires_at,
            invalid_before: issued_at
                .and_then(|iat| iat.checked_sub(Duration::seconds(self.get_leeway() as i64))),
            issuer: Some(issuer),
            subject: credential_data.holder_did.map(|did| did.to_string()),
            jwt_id: credential_id,
            custom: vc,
            ..Default::default()
        };

        let key_id = auth_fn.get_key_id();
        let jwt = Jwt::new(
            "JWT".to_owned(),
            auth_fn.jose_alg().ok_or(FormatterError::CouldNotFormat(
                "Invalid key algorithm".to_string(),
            ))?,
            key_id,
            None,
            payload,
        );

        jwt.tokenize(Some(auth_fn)).await
    }

    async fn format_status_list(
        &self,
        revocation_list_url: String,
        issuer_did: &Did,
        encoded_list: String,
        algorithm: String,
        auth_fn: AuthenticationFn,
        status_purpose: StatusPurpose,
        status_list_type: StatusListType,
    ) -> Result<String, FormatterError> {
        let issuer = Issuer::Url(
            issuer_did
                .did
                .as_str()
                .parse()
                .map_err(|_| FormatterError::Failed("Invalid issuer DID".to_string()))?,
        );

        let key_algorithm = self
            .key_algorithm_provider
            .key_algorithm_from_name(&algorithm)
            .ok_or(FormatterError::Failed("Missing key algorithm".to_string()))?;

        let jose_alg = key_algorithm
            .issuance_jose_alg_id()
            .ok_or(FormatterError::Failed("Invalid key algorithm".to_string()))?;

        match status_list_type {
            StatusListType::BitstringStatusList => {
                let revocation_list_url: Url = revocation_list_url.parse().map_err(|_| {
                    FormatterError::Failed("Invalid revocation list url".to_string())
                })?;

                let credential_id = revocation_list_url.clone();

                let credential_subject_id = {
                    let mut url = revocation_list_url;
                    url.set_fragment(Some("list"));
                    url
                };

                let credential_subject = VcdmCredentialSubject::new([
                    ("type", json!("BitstringStatusList")),
                    ("statusPurpose", json!(status_purpose)),
                    ("encodedList", json!(encoded_list)),
                ])
                .with_id(credential_subject_id.clone());

                let vc = VcdmCredential::new_v2(issuer, credential_subject)
                    .add_type("BitstringStatusListCredential".to_string())
                    .with_id(credential_id);

                let vc_claim = VcClaim { vc: vc.into() };

                let payload = JWTPayload {
                    issuer: Some(issuer_did.did.to_string()),
                    subject: Some(credential_subject_id.to_string()),
                    custom: vc_claim,
                    issued_at: Some(OffsetDateTime::now_utc()),
                    ..Default::default()
                };

                let jwt = Jwt::new("JWT".to_owned(), jose_alg, None, None, payload);

                jwt.tokenize(Some(auth_fn)).await
            }
            StatusListType::TokenStatusList => {
                let content = TokenStatusListContent {
                    status_list: TokenStatusListSubject {
                        bits: PREFERRED_ENTRY_SIZE,
                        value: encoded_list,
                    },
                };

                let payload = JWTPayload {
                    issuer: Some(issuer_did.did.to_string()),
                    subject: Some(revocation_list_url),
                    custom: content,
                    issued_at: Some(OffsetDateTime::now_utc()),
                    ..Default::default()
                };

                let jwt = Jwt::new("statuslist+jwt".to_owned(), jose_alg, None, None, payload);

                jwt.tokenize(Some(auth_fn)).await
            }
        }
    }

    async fn extract_credentials<'a>(
        &self,
        token: &str,
        _credential_schema: Option<&'a CredentialSchema>,
        verification: VerificationFn,
        _holder_binding_ctx: Option<HolderBindingCtx>,
    ) -> Result<DetailCredential, FormatterError> {
        // Build fails if verification fails
        let jwt: Jwt<VcClaim> = Jwt::build_from_token(token, Some(&verification), None).await?;

        DetailCredential::try_from(jwt).map_err(|e| FormatterError::Failed(e.to_string()))
    }

    async fn extract_credentials_unverified<'a>(
        &self,
        token: &str,
        _credential_schema: Option<&'a CredentialSchema>,
    ) -> Result<DetailCredential, FormatterError> {
        let jwt: Jwt<VcClaim> = Jwt::build_from_token(token, None, None).await?;

        DetailCredential::try_from(jwt).map_err(|e| FormatterError::Failed(e.to_string()))
    }

    async fn format_credential_presentation(
        &self,
        credential: CredentialPresentation,
        _holder_binding_ctx: Option<HolderBindingCtx>,
        _holder_binding_fn: Option<AuthenticationFn>,
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
        let vp: VP = format_payload(tokens, nonce)?;

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

        let key_id = auth_fn.get_key_id();

        let key_algorithm = self
            .key_algorithm_provider
            .key_algorithm_from_name(algorithm)
            .ok_or(FormatterError::Failed("Missing key algorithm".to_string()))?;

        let jose_alg = key_algorithm
            .issuance_jose_alg_id()
            .ok_or(FormatterError::Failed("Invalid key algorithm".to_string()))?;

        let jwt = Jwt::new("JWT".to_owned(), jose_alg, key_id, None, payload);

        jwt.tokenize(Some(auth_fn)).await
    }

    async fn extract_presentation(
        &self,
        token: &str,
        verification: VerificationFn,
        _context: ExtractPresentationCtx,
    ) -> Result<Presentation, FormatterError> {
        // Build fails if verification fails
        let jwt: Jwt<VP> = Jwt::build_from_token(token, Some(&verification), None).await?;

        jwt.try_into()
    }

    fn get_leeway(&self) -> u64 {
        self.params.leeway
    }

    fn get_capabilities(&self) -> FormatterCapabilities {
        FormatterCapabilities {
            signing_key_algorithms: vec![
                KeyAlgorithmType::Eddsa,
                KeyAlgorithmType::Ecdsa,
                KeyAlgorithmType::Dilithium,
            ],
            features: vec![Features::SupportsCredentialDesign],
            selective_disclosure: vec![],
            issuance_did_methods: vec![
                DidType::Key,
                DidType::Web,
                DidType::Jwk,
                DidType::X509,
                DidType::WebVh,
            ],
            issuance_exchange_protocols: vec![IssuanceProtocolType::OpenId4VciDraft13],
            proof_exchange_protocols: vec![
                VerificationProtocolType::OpenId4VpDraft20,
                VerificationProtocolType::OpenId4VpDraft25,
                VerificationProtocolType::OpenId4VpProximityDraft00,
            ],
            revocation_methods: vec![
                RevocationType::None,
                RevocationType::BitstringStatusList,
                RevocationType::Lvvc,
            ],
            verification_key_algorithms: vec![
                KeyAlgorithmType::Eddsa,
                KeyAlgorithmType::Ecdsa,
                KeyAlgorithmType::Dilithium,
            ],
            verification_key_storages: vec![
                KeyStorageType::Internal,
                KeyStorageType::AzureVault,
                KeyStorageType::SecureElement,
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
            issuance_identifier_types: vec![IdentifierType::Did],
            verification_identifier_types: vec![IdentifierType::Did],
        }
    }

    async fn extract_presentation_unverified(
        &self,
        token: &str,
        _context: ExtractPresentationCtx,
    ) -> Result<Presentation, FormatterError> {
        let jwt: Jwt<VP> = Jwt::build_from_token(token, None, None).await?;

        jwt.try_into()
    }
}

fn format_payload(credentials: &[String], nonce: Option<String>) -> Result<VP, FormatterError> {
    let mut has_enveloped_presentation = false;

    let tokens = credentials
        .iter()
        .map(|token| {
            if Base64UrlSafeNoPadding::decode_to_vec(token, None).is_ok() {
                let token = format!("data:application/vp+mso_mdoc,{}", token);

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
