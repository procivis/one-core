use async_trait::async_trait;

use shared_types::DidValue;

use super::model::CredentialPresentation;
use super::{
    AuthenticationFn, CredentialData, CredentialFormatter, DetailCredential,
    ExtractPresentationCtx, FormatPresentationCtx, FormatterCapabilities, FormatterError,
    Presentation, VerificationFn,
};

pub struct PhysicalCardFormatter {}

#[async_trait]
impl CredentialFormatter for PhysicalCardFormatter {
    async fn format_credentials(
        &self,
        _credential: CredentialData,
        _holder_did: &DidValue,
        _algorithm: &str,
        _additional_context: Vec<String>,
        _additional_types: Vec<String>,
        _auth_fn: AuthenticationFn,
        _json_ld_context_url: Option<String>,
        _custom_subject_name: Option<String>,
    ) -> Result<String, FormatterError> {
        todo!()
    }

    async fn extract_credentials(
        &self,
        _token: &str,
        _verification: VerificationFn,
    ) -> Result<DetailCredential, FormatterError> {
        todo!()
    }

    async fn extract_credentials_unverified(
        &self,
        _token: &str,
    ) -> Result<DetailCredential, FormatterError> {
        todo!()
    }

    async fn format_presentation(
        &self,
        _credentials: &[String],
        _holder_did: &DidValue,
        _algorithm: &str,
        _auth_fn: AuthenticationFn,
        _context: FormatPresentationCtx,
    ) -> Result<String, FormatterError> {
        todo!()
    }

    async fn extract_presentation(
        &self,
        _token: &str,
        _verification: VerificationFn,
        _context: ExtractPresentationCtx,
    ) -> Result<Presentation, FormatterError> {
        todo!()
    }

    async fn format_credential_presentation(
        &self,
        _credential: CredentialPresentation,
    ) -> Result<String, FormatterError> {
        todo!()
    }

    fn get_leeway(&self) -> u64 {
        todo!()
    }

    fn get_capabilities(&self) -> FormatterCapabilities {
        FormatterCapabilities {
            signing_key_algorithms: vec![
                "EDDSA".to_owned(),
                "ES256".to_owned(),
                "DILITHIUM".to_owned(),
            ],
            features: vec![],
            selective_disclosure: vec![],
            issuance_did_methods: vec![],
            issuance_exchange_protocols: vec![],
            proof_exchange_protocols: vec!["SCAN_TO_VERIFY".to_string()],
            revocation_methods: vec!["NONE".to_string()],
            verification_key_algorithms: vec![
                "EDDSA".to_string(),
                "ES256".to_string(),
                "DILITHIUM".to_string(),
            ],
            datatypes: vec![
                "STRING".to_string(),
                "BOOLEAN".to_string(),
                "EMAIL".to_string(),
                "DATE".to_string(),
                "STRING".to_string(),
                "COUNT".to_string(),
                "BIRTH_DATE".to_string(),
                "NUMBER".to_string(),
            ],
        }
    }

    async fn extract_presentation_unverified(
        &self,
        _token: &str,
        _context: ExtractPresentationCtx,
    ) -> Result<Presentation, FormatterError> {
        todo!()
    }
}

#[allow(clippy::new_without_default)]
impl PhysicalCardFormatter {
    pub fn new() -> Self {
        Self {}
    }
}
