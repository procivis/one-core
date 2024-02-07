use serde::Deserialize;

use std::vec;

use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{CredentialStatus, DetailCredential};
use crate::service::credential::dto::CredentialDetailResponseDTO;
use async_trait::async_trait;
use shared_types::DidValue;

use super::model::{CredentialPresentation, Presentation};
use super::{AuthenticationFn, CredentialFormatter, FormatterCapabilities, VerificationFn};

#[allow(dead_code)]
pub struct JsonLdBbsplus {
    params: Params,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {}

#[async_trait]
impl CredentialFormatter for JsonLdBbsplus {
    async fn format_credentials(
        &self,
        _credential: &CredentialDetailResponseDTO,
        _credential_status: Option<CredentialStatus>,
        _holder_did: &DidValue,
        _algorithm: &str,
        _additional_context: Vec<String>,
        _additional_types: Vec<String>,
        _auth_fn: AuthenticationFn,
    ) -> Result<String, FormatterError> {
        todo!()
    }

    //This could later be optimized to operate od LdDataSource directly.
    async fn extract_credentials(
        &self,
        _credential: &str,
        _verification_fn: VerificationFn,
    ) -> Result<DetailCredential, FormatterError> {
        todo!()
    }

    fn format_credential_presentation(
        &self,
        _credential: CredentialPresentation,
    ) -> Result<String, FormatterError> {
        todo!()
    }

    async fn format_presentation(
        &self,
        _tokens: &[String],
        _holder_did: &DidValue,
        _algorithm: &str,
        _auth_fn: AuthenticationFn,
        _nonce: Option<String>,
    ) -> Result<String, FormatterError> {
        todo!()
    }

    async fn extract_presentation(
        &self,
        _json_ld: &str,
        _verification_fn: VerificationFn,
    ) -> Result<Presentation, FormatterError> {
        todo!()
    }

    fn get_leeway(&self) -> u64 {
        0
    }

    fn get_capabilities(&self) -> FormatterCapabilities {
        FormatterCapabilities {
            signing_key_algorithms: vec!["BBS_PLUS".to_owned()],
            features: vec!["SELECTIVE_DISCLOSURE".to_owned()],
        }
    }
}

impl JsonLdBbsplus {
    pub fn new(params: Params) -> Self {
        Self { params }
    }
}
