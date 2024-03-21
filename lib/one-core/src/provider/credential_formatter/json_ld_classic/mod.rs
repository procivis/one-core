use std::sync::Arc;
use std::vec;

use async_trait::async_trait;
use serde::Deserialize;
use shared_types::DidValue;
use time::OffsetDateTime;

use crate::crypto::CryptoProvider;
use crate::provider::did_method::provider::DidMethodProvider;

use super::error::FormatterError;
use super::json_ld::{self, model::*};
use super::model::{CredentialPresentation, CredentialSubject, DetailCredential, Presentation};
use super::{
    AuthenticationFn, Context, CredentialData, CredentialFormatter, FormatterCapabilities,
    VerificationFn,
};

#[allow(dead_code)]
pub struct JsonLdClassic {
    pub base_url: Option<String>,
    pub crypto: Arc<dyn CryptoProvider>,
    pub did_method_provider: Arc<dyn DidMethodProvider>,
    params: Params,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {}

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
        let did_document = self
            .did_method_provider
            .resolve(&credential.issuer_did)
            .await
            .map_err(|e| FormatterError::CouldNotFormat(e.to_string()))?;

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

        let mut proof = json_ld::prepare_proof_config(
            "assertionMethod",
            cryptosuite,
            vec![Context::DataIntegrityV2.to_string()],
            &did_document,
        )
        .await?;

        let proof_hash = json_ld::prepare_proof_hash(&credential, &self.crypto, &proof).await?;

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
        nonce: Option<String>,
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

        let did_document = self
            .did_method_provider
            .resolve(holder_did)
            .await
            .map_err(|e| FormatterError::CouldNotFormat(e.to_string()))?;

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

        let mut proof = json_ld::prepare_proof_config(
            "authentication",
            cryptosuite,
            vec![Context::DataIntegrityV2.to_string()],
            &did_document,
        )
        .await?;

        let proof_hash = json_ld::prepare_proof_hash(&presentation, &self.crypto, &proof).await?;

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
    ) -> Result<Presentation, FormatterError> {
        self.extract_presentation_internal(json_ld, Some(verification_fn))
            .await
    }

    fn get_leeway(&self) -> u64 {
        0
    }

    fn get_capabilities(&self) -> FormatterCapabilities {
        FormatterCapabilities {
            signing_key_algorithms: vec!["EDDSA".to_owned(), "ES256".to_owned()],
            features: vec![],
        }
    }

    async fn extract_presentation_unverified(
        &self,
        json_ld: &str,
    ) -> Result<Presentation, FormatterError> {
        self.extract_presentation_internal(json_ld, None).await
    }
}

impl JsonLdClassic {
    #[allow(clippy::new_without_default)]
    pub fn new(
        params: Params,
        crypto: Arc<dyn CryptoProvider>,
        base_url: Option<String>,
        did_method_provider: Arc<dyn DidMethodProvider>,
    ) -> Self {
        Self {
            params,
            crypto,
            base_url,
            did_method_provider,
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
            json_ld::verify_credential_signature(credential.clone(), verification_fn, &self.crypto)
                .await?;
        }

        // We only take first subject now as one credential only contains one credential schema
        let subject = credential
            .credential_subject
            .subject
            .into_iter()
            .next()
            .ok_or(FormatterError::CouldNotExtractCredentials(
                "Missing credential subject".to_string(),
            ))?;

        let claims = CredentialSubject {
            values: subject.1.into_iter().collect(),
        };

        Ok(DetailCredential {
            id: Some(credential.id),
            issued_at: Some(credential.issuance_date),
            expires_at: None,
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
