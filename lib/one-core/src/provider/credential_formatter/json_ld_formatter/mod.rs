use convert_case::{Case, Casing};
use serde::{Deserialize, Serialize};
use sophia_api::quad::Spog;
use sophia_api::source::QuadSource;
use sophia_api::term::SimpleTerm;
use sophia_jsonld::loader::HttpLoader;
use sophia_jsonld::loader_factory::DefaultLoaderFactory;
use sophia_jsonld::JsonLdOptions;
use std::collections::HashMap;
use std::sync::Arc;
use std::vec;

use crate::crypto::CryptoProvider;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::json_ld_formatter::model::LdCredential;
use crate::provider::credential_formatter::model::{
    CredentialStatus, CredentialSubject, DetailCredential,
};
use crate::provider::did_method::provider::DidMethodProvider;
use crate::service::credential::dto::CredentialDetailResponseDTO;
use async_trait::async_trait;
use shared_types::DidValue;
use time::OffsetDateTime;

use self::model::*;

use super::model::{CredentialPresentation, Presentation};
use super::{AuthenticationFn, CredentialFormatter, FormatterCapabilities, VerificationFn};

use sophia_c14n::rdfc10;
use sophia_jsonld::parser::JsonLdParser;
pub mod model;

type LdDataset = std::collections::HashSet<Spog<SimpleTerm<'static>>>;

#[allow(dead_code)]
pub struct JsonLdFormatter {
    pub base_url: Option<String>,
    pub crypto: Arc<dyn CryptoProvider>,
    pub did_method_provider: Arc<dyn DidMethodProvider>,
    params: Params,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {}

#[async_trait]
impl CredentialFormatter for JsonLdFormatter {
    async fn format_credentials(
        &self,
        credential: &CredentialDetailResponseDTO,
        _credential_status: Option<CredentialStatus>,
        holder_did: &DidValue,
        _algorithm: &str,
        additional_context: Vec<String>,
        additional_types: Vec<String>,
        auth_fn: AuthenticationFn,
    ) -> Result<String, FormatterError> {
        let issuance_date = OffsetDateTime::now_utc();

        let mut context = self.prepare_context(additional_context);

        if let Some(url) = &self.base_url {
            context.push(format!("{}/ssi/context/v1/{}", url, credential.schema.id));
        }

        let ld_type = self.prepare_credential_type(credential, additional_types);

        let id = format!("urn:uuid:{}", credential.id);

        let issuer_did = credential
            .issuer_did
            .as_ref()
            .map(|did| did.did.clone())
            .ok_or(FormatterError::MissingIssuer)?;

        let credential_subject = self.prepare_credential_subject(credential, holder_did);

        let mut credential = LdCredential {
            context,
            id,
            r#type: ld_type,
            issuer: issuer_did.clone(),
            issuance_date,
            credential_subject,
            proof: None,
        };

        let mut proof = self.prepare_proof(&issuer_did, "assertionMethod").await?;

        let proof_hash = self.prepare_proof_hash(&credential, &proof).await?;

        let signed_proof = self.sign_proof_hash(&proof_hash, auth_fn).await?;

        proof.proof_value = Some(signed_proof);
        credential.proof = Some(proof);

        let resp = serde_json::to_string(&credential)
            .map_err(|e| FormatterError::CouldNotFormat(e.to_string()))?;

        Ok(resp)
    }

    //This could later be optimized to operate od LdDataSource directly.
    async fn extract_credentials(
        &self,
        credential: &str,
        verification_fn: VerificationFn,
    ) -> Result<DetailCredential, FormatterError> {
        let credential: LdCredential = serde_json::from_str(credential)
            .map_err(|e| FormatterError::CouldNotExtractCredentials(e.to_string()))?;

        self.verify_credential_signature(credential.clone(), verification_fn)
            .await?;

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
            status: None,
        })
    }

    fn format_credential_presentation(
        &self,
        credential: CredentialPresentation,
    ) -> Result<String, FormatterError> {
        Ok(credential.token)
    }

    async fn format_presentation(
        &self,
        tokens: &[String],
        holder_did: &DidValue,
        _algorithm: &str,
        auth_fn: AuthenticationFn,
        nonce: Option<String>,
    ) -> Result<String, FormatterError> {
        let issuance_date = OffsetDateTime::now_utc();

        let context = self.prepare_context(vec![]);

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

        let mut proof = self.prepare_proof(holder_did, "authentication").await?;

        let proof_hash = self.prepare_proof_hash(&presentation, &proof).await?;

        let signed_proof = self.sign_proof_hash(&proof_hash, auth_fn).await?;

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
        let presentation: LdPresentation = serde_json::from_str(json_ld)
            .map_err(|e| FormatterError::CouldNotExtractPresentation(e.to_string()))?;

        self.verify_presentation_signature(presentation.clone(), verification_fn)
            .await?;

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

    fn get_leeway(&self) -> u64 {
        0
    }

    fn get_capabilities(&self) -> FormatterCapabilities {
        FormatterCapabilities::default()
    }
}

impl JsonLdFormatter {
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

    async fn prepare_proof(
        &self,
        isuser_did: &DidValue,
        proof_purpose: &str,
    ) -> Result<LdProof, FormatterError> {
        let context = vec!["https://w3id.org/security/data-integrity/v2".to_string()];
        let r#type = "DataIntegrityProof".to_owned();
        let cryptosuite = "eddsa-rdfc-2022".to_string(); // For EDDSA Only!

        let did_resolved = self
            .did_method_provider
            .resolve(isuser_did)
            .await
            .map_err(|e| FormatterError::CouldNotFormat(e.to_string()))?;

        // We take first key as we don't have a way to select other one.
        let key_id = did_resolved
            .assertion_method
            .ok_or(FormatterError::CouldNotFormat(
                "Missing assertion method id".to_owned(),
            ))?
            .first()
            .ok_or(FormatterError::CouldNotFormat(
                "Missing assertion methgod".to_owned(),
            ))?
            .clone();

        let verification_method = key_id;

        Ok(LdProof {
            context,
            r#type,
            created: OffsetDateTime::now_utc(),
            cryptosuite,
            verification_method,
            proof_purpose: proof_purpose.to_owned(),
            proof_value: None,
            nonce: None,
            challenge: None,
            domain: None,
        })
    }

    fn prepare_context(&self, additional_context: Vec<String>) -> Vec<String> {
        let mut context = vec![
            "https://www.w3.org/2018/credentials/v1".to_string(),
            "https://w3id.org/security/data-integrity/v2".to_string(),
        ];

        context.extend(additional_context);
        context
    }

    fn prepare_credential_type(
        &self,
        credential: &CredentialDetailResponseDTO,
        additional_types: Vec<String>,
    ) -> Vec<String> {
        let pascal_schema_name = credential.schema.name.to_case(Case::Pascal);

        let mut types = vec![
            "VerifiableCredential".to_string(),
            format!("{}Subject", pascal_schema_name),
        ];

        types.extend(additional_types);

        types
    }

    fn prepare_credential_subject(
        &self,
        credential: &CredentialDetailResponseDTO,
        holder_did: &DidValue,
    ) -> LdCredentialSubject {
        let pascal_schema_name = credential.schema.name.to_case(Case::Pascal);
        let claims: Claims = credential
            .claims
            .iter()
            .map(|claim| (claim.schema.key.clone(), claim.value.clone()))
            .collect();

        let mut subject = HashMap::new();
        subject.insert(format!("{}Subject", pascal_schema_name), claims);

        LdCredentialSubject {
            id: holder_did.clone(),
            subject,
        }
    }

    async fn prepare_proof_hash<T>(
        &self,
        object: &T,
        proof: &LdProof,
    ) -> Result<Vec<u8>, FormatterError>
    where
        T: Serialize,
    {
        let transformed_document = self.canonize_any(object).await?;

        let transformed_proof_config = self.canonize_any(proof).await?;

        let hashing_function = "sha-256";
        let hasher = self.crypto.get_hasher(hashing_function).map_err(|_| {
            FormatterError::CouldNotFormat(format!("Hasher {} unavailable", hashing_function))
        })?;

        let transformed_document_hash = hasher
            .hash(transformed_document.as_bytes())
            .map_err(|e| FormatterError::CouldNotFormat(format!("Hasher error: `{}`", e)))?;

        let mut transformed_proof_config_hash = hasher
            .hash(transformed_proof_config.as_bytes())
            .map_err(|e| FormatterError::CouldNotFormat(format!("Hasher error: `{}`", e)))?;

        transformed_proof_config_hash.extend(transformed_document_hash);
        Ok(transformed_proof_config_hash)
    }

    async fn sign_proof_hash(
        &self,
        proof_hash: &[u8],
        auth_fn: AuthenticationFn,
    ) -> Result<String, FormatterError> {
        let signature = auth_fn
            .sign(proof_hash)
            .await
            .map_err(|e| FormatterError::CouldNotSign(e.to_string()))?;

        Ok(bs58::encode(signature).into_string())
    }

    async fn verify_proof_signature(
        &self,
        proof_hash: &[u8],
        proof_value_bs58: &str,
        issuer_did: &DidValue,
        key_id: &str,
        verification_fn: VerificationFn,
    ) -> Result<(), FormatterError> {
        let signature = bs58::decode(proof_value_bs58)
            .into_vec()
            .map_err(|_| FormatterError::CouldNotVerify("Hash decoding error".to_owned()))?;

        verification_fn
            .verify(
                Some(issuer_did.clone()),
                Some(key_id),
                "EDDSA", // Fixed for now
                proof_hash,
                &signature,
            )
            .await
            .map_err(|_| FormatterError::CouldNotVerify("Verification error".to_string()))?;

        Ok(())
    }

    async fn canonize_any<T>(&self, json_ld: &T) -> Result<String, FormatterError>
    where
        T: Serialize,
    {
        let content_str = serde_json::to_string(&json_ld)
            .map_err(|e| FormatterError::CouldNotFormat(e.to_string()))?;

        let options: JsonLdOptions<DefaultLoaderFactory<HttpLoader>> = JsonLdOptions::default();

        let parser = JsonLdParser::new_with_options(options);

        // This will actually fetch context
        let parsed = parser.async_parse_str(&content_str).await;

        let dataset: LdDataset = parsed
            .collect_quads()
            .map_err(|e| FormatterError::CouldNotFormat(e.to_string()))?;

        self.canonize_dataset(dataset).await
    }

    async fn canonize_dataset(&self, dataset: LdDataset) -> Result<String, FormatterError> {
        let mut buf = Vec::<u8>::new();
        rdfc10::normalize(&dataset, &mut buf)
            .map_err(|e| FormatterError::CouldNotFormat(format!("Normalization error: `{}`", e)))?;

        let str = String::from_utf8_lossy(buf.as_slice());

        Ok(str.to_string())
    }

    async fn verify_credential_signature(
        &self,
        mut ld_credential: LdCredential,
        verification_fn: VerificationFn,
    ) -> Result<(), FormatterError> {
        let mut proof = ld_credential
            .proof
            .as_ref()
            .ok_or(FormatterError::CouldNotVerify("Missing proof".to_owned()))?
            .clone();
        let proof_value = proof.proof_value.ok_or(FormatterError::CouldNotVerify(
            "Missing proof_value".to_owned(),
        ))?;
        let key_id = proof.verification_method.as_str();
        let issuer_did = &ld_credential.issuer;

        // Remove proof value and proof for canonicalization
        proof.proof_value = None;
        ld_credential.proof = None;

        let proof_hash = self.prepare_proof_hash(&ld_credential, &proof).await?;
        self.verify_proof_signature(
            &proof_hash,
            &proof_value,
            issuer_did,
            key_id,
            verification_fn,
        )
        .await?;

        Ok(())
    }

    async fn verify_presentation_signature(
        &self,
        mut presentation: LdPresentation,
        verification_fn: VerificationFn,
    ) -> Result<(), FormatterError> {
        let mut proof = presentation
            .proof
            .as_ref()
            .ok_or(FormatterError::CouldNotVerify("Missing proof".to_owned()))?
            .clone();
        let proof_value = proof.proof_value.ok_or(FormatterError::CouldNotVerify(
            "Missing proof_value".to_owned(),
        ))?;
        let key_id = proof.verification_method.as_str();
        let issuer_did = &presentation.holder;

        // Remove proof value and proof for canonicalization
        proof.proof_value = None;
        presentation.proof = None;

        let proof_hash = self.prepare_proof_hash(&presentation, &proof).await?;
        self.verify_proof_signature(
            &proof_hash,
            &proof_value,
            issuer_did,
            key_id,
            verification_fn,
        )
        .await?;

        Ok(())
    }
}
