use std::sync::Arc;
use std::vec;

use async_trait::async_trait;
use one_providers::credential_formatter::imp::json_ld::context::caching_loader::CachingLoader;
use one_providers::crypto::CryptoProvider;
use one_providers::did::provider::DidMethodProvider;
use one_providers::key_storage::provider::AuthenticationFn;
use serde::Deserialize;
use serde_with::{serde_as, DurationSeconds};
use shared_types::DidValue;
use time::{Duration, OffsetDateTime};

use super::error::FormatterError;
use super::json_ld::jsonld_forbidden_claim_names;
use super::json_ld::model::*;
use super::model::{CredentialPresentation, CredentialSubject, DetailCredential, Presentation};
use super::{
    json_ld, Context, CredentialData, CredentialFormatter, ExtractPresentationCtx,
    FormatPresentationCtx, FormatterCapabilities, VerificationFn,
};

#[allow(dead_code)]
pub struct JsonLdClassic {
    pub base_url: Option<String>,
    pub crypto: Arc<dyn CryptoProvider>,
    pub did_method_provider: Arc<dyn DidMethodProvider>,
    pub caching_loader: CachingLoader,
    params: Params,
}

#[serde_as]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    #[serde_as(as = "DurationSeconds<i64>")]
    leeway: Duration,
}

#[async_trait]
impl CredentialFormatter for JsonLdClassic {
    async fn extract_credentials_unverified(
        &self,
        credential: &str,
    ) -> Result<DetailCredential, FormatterError> {
        self.extract_credentials_internal(credential, None).await
    }

    async fn format_credentials(
        &self,
        credential: CredentialData,
        holder_did: &DidValue,
        algorithm: &str,
        additional_context: Vec<String>,
        additional_types: Vec<String>,
        auth_fn: AuthenticationFn,
        json_ld_context_url: Option<String>,
        custom_subject_name: Option<String>,
    ) -> Result<String, FormatterError> {
        let mut credential = json_ld::prepare_credential(
            credential,
            holder_did,
            additional_context,
            additional_types,
            json_ld_context_url,
            custom_subject_name,
        )?;

        let cryptosuite = match algorithm {
            "EDDSA" => "eddsa-rdfc-2022",
            "ES256" => "ecdsa-rdfc-2019",
            _ => {
                return Err(FormatterError::CouldNotFormat(format!(
                    "Unsupported algorithm: {algorithm}"
                )))
            }
        };

        let key_id = auth_fn.get_key_id().ok_or(FormatterError::CouldNotFormat(
            "Missing jwk key id".to_string(),
        ))?;

        let mut proof = json_ld::prepare_proof_config(
            "assertionMethod",
            cryptosuite,
            vec![Context::DataIntegrityV2.to_string()],
            key_id,
        )
        .await?;

        let proof_hash = json_ld::prepare_proof_hash(
            &credential,
            &self.crypto,
            &proof,
            self.caching_loader.to_owned(),
        )
        .await?;

        let signed_proof = json_ld::sign_proof_hash(&proof_hash, auth_fn).await?;

        proof.proof_value = Some(signed_proof);
        credential.proof = Some(proof);

        let resp = serde_json::to_string(&credential)
            .map_err(|e| FormatterError::CouldNotFormat(e.to_string()))?;

        Ok(resp)
    }

    async fn extract_credentials(
        &self,
        credential: &str,
        verification_fn: VerificationFn,
    ) -> Result<DetailCredential, FormatterError> {
        self.extract_credentials_internal(credential, Some(verification_fn))
            .await
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
        let issuance_date = OffsetDateTime::now_utc();

        let context = json_ld::prepare_context(vec![]);

        // To support object or an array
        let verifiable_credential = if tokens.len() == 1 {
            tokens[0].to_owned()
        } else {
            serde_json::to_string(tokens).map_err(|e| {
                FormatterError::CouldNotFormat(format!(
                    "Credential array serialization error: `{e}`"
                ))
            })?
        };

        let mut presentation = LdPresentation {
            context,
            r#type: "VerifiablePresentation".to_string(),
            verifiable_credential,
            issuance_date,
            holder: holder_did.to_owned(),
            nonce,
            proof: None,
        };

        let cryptosuite = match algorithm {
            "EDDSA" => "eddsa-rdfc-2022",
            "ES256" => "ecdsa-rdfc-2019",
            _ => {
                return Err(FormatterError::CouldNotFormat(format!(
                    "Unsupported algorithm: {algorithm}"
                )))
            }
        };

        let key_id = auth_fn.get_key_id().ok_or(FormatterError::CouldNotFormat(
            "Missing jwk key id".to_string(),
        ))?;

        let mut proof = json_ld::prepare_proof_config(
            "authentication",
            cryptosuite,
            vec![Context::DataIntegrityV2.to_string()],
            key_id,
        )
        .await?;

        let proof_hash = json_ld::prepare_proof_hash(
            &presentation,
            &self.crypto,
            &proof,
            self.caching_loader.to_owned(),
        )
        .await?;

        let signed_proof = json_ld::sign_proof_hash(&proof_hash, auth_fn).await?;

        proof.proof_value = Some(signed_proof);
        presentation.proof = Some(proof);

        let resp = serde_json::to_string(&presentation)
            .map_err(|e| FormatterError::CouldNotFormat(e.to_string()))?;

        Ok(resp)
    }

    async fn extract_presentation(
        &self,
        json_ld: &str,
        verification_fn: VerificationFn,
        _context: ExtractPresentationCtx,
    ) -> Result<Presentation, FormatterError> {
        self.extract_presentation_internal(json_ld, Some(verification_fn))
            .await
    }

    fn get_leeway(&self) -> u64 {
        self.params.leeway.whole_seconds() as u64
    }

    fn get_capabilities(&self) -> FormatterCapabilities {
        FormatterCapabilities {
            signing_key_algorithms: vec!["EDDSA".to_owned(), "ES256".to_owned()],
            features: vec![],
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
            verification_key_algorithms: vec!["EDDSA".to_string(), "ES256".to_string()],
            forbidden_claim_names: jsonld_forbidden_claim_names(),
        }
    }

    async fn extract_presentation_unverified(
        &self,
        json_ld: &str,
        _context: ExtractPresentationCtx,
    ) -> Result<Presentation, FormatterError> {
        self.extract_presentation_internal(json_ld, None).await
    }
}

impl JsonLdClassic {
    pub fn new(
        params: Params,
        crypto: Arc<dyn CryptoProvider>,
        base_url: Option<String>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        caching_loader: CachingLoader,
    ) -> Self {
        Self {
            params,
            crypto,
            base_url,
            did_method_provider,
            caching_loader,
        }
    }

    async fn extract_credentials_internal(
        &self,
        credential: &str,
        verification_fn: Option<VerificationFn>,
    ) -> Result<DetailCredential, FormatterError> {
        let credential: LdCredential = serde_json::from_str(credential)
            .map_err(|e| FormatterError::CouldNotExtractCredentials(e.to_string()))?;

        if let Some(verification_fn) = verification_fn {
            json_ld::verify_credential_signature(
                credential.clone(),
                verification_fn,
                &self.crypto,
                self.caching_loader.to_owned(),
            )
            .await?;
        }

        // We only take first subject now as one credential only contains one credential schema
        let subject = credential
            .credential_subject
            .subject
            .values()
            .next()
            .ok_or(FormatterError::JsonMapping(
                "subject is not defined".to_string(),
            ))?
            .as_object()
            .ok_or(FormatterError::JsonMapping(
                "subject is not an Object".to_string(),
            ))?;

        let claims = CredentialSubject {
            values: subject
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect(),
        };

        Ok(DetailCredential {
            id: Some(credential.id),
            issued_at: Some(credential.issuance_date),
            expires_at: None,
            update_at: None,
            invalid_before: None,
            issuer_did: Some(credential.issuer),
            subject: Some(credential.credential_subject.id),
            claims,
            status: credential.credential_status,
            credential_schema: credential.credential_schema,
        })
    }

    async fn extract_presentation_internal(
        &self,
        json_ld: &str,
        verification_fn: Option<VerificationFn>,
    ) -> Result<Presentation, FormatterError> {
        let presentation: LdPresentation = serde_json::from_str(json_ld)
            .map_err(|e| FormatterError::CouldNotExtractPresentation(e.to_string()))?;

        if let Some(verification_fn) = verification_fn {
            json_ld::verify_presentation_signature(
                presentation.clone(),
                verification_fn,
                &self.crypto,
                self.caching_loader.to_owned(),
            )
            .await?;
        }

        let credentials: Vec<String> = if presentation.verifiable_credential.starts_with('[') {
            serde_json::from_str(&presentation.verifiable_credential).map_err(|_| {
                FormatterError::CouldNotExtractPresentation(
                    "Invalid credential collection".to_string(),
                )
            })?
        } else {
            vec![presentation.verifiable_credential]
        };

        Ok(Presentation {
            id: None,
            issued_at: Some(presentation.issuance_date),
            expires_at: None,
            issuer_did: Some(presentation.holder),
            nonce: presentation.nonce,
            credentials,
        })
    }
}
