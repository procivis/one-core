use mockall::*;

use crate::credential_formatter::CredentialStatus;
use crate::{
    credential_formatter::{
        CredentialPresentation, DetailCredential, FormatterError, PresentationCredential,
    },
    service::credential::dto::CredentialDetailResponseDTO,
};

#[derive(Default)]
struct CredentialFormatter;

mock! {
    pub CredentialFormatter {
        fn format_credentials(
            &self,
            credential: &CredentialDetailResponseDTO,
            credential_status: Option<CredentialStatus>,
            holder_did: &str,
            algorithm: &str,
            additional_context: Vec<String>,
            additional_types: Vec<String>,
        ) -> Result<String, FormatterError>;
        fn extract_credentials(
            &self,
            credentials: &str
        ) -> Result<DetailCredential, FormatterError>;
        fn format_presentation(
            &self,
            tokens: &[PresentationCredential],
            holder_did: &str,
            algorithm: &str
        ) -> Result<String, FormatterError>;
        fn extract_presentation(
            &self,
            token: &str
        ) -> Result<CredentialPresentation, FormatterError>;
    }
}

#[async_trait::async_trait]
impl crate::credential_formatter::CredentialFormatter for MockCredentialFormatter {
    fn format_credentials(
        &self,
        credential: &CredentialDetailResponseDTO,
        credential_status: Option<CredentialStatus>,
        holder_did: &str,
        algorithm: &str,
        additional_context: Vec<String>,
        additional_types: Vec<String>,
    ) -> Result<String, FormatterError> {
        self.format_credentials(
            credential,
            credential_status,
            holder_did,
            algorithm,
            additional_context,
            additional_types,
        )
    }

    fn extract_credentials(&self, credentials: &str) -> Result<DetailCredential, FormatterError> {
        self.extract_credentials(credentials)
    }

    fn format_presentation(
        &self,
        tokens: &[PresentationCredential],
        holder_did: &str,
        algorithm: &str,
    ) -> Result<String, FormatterError> {
        self.format_presentation(tokens, holder_did, algorithm)
    }

    fn extract_presentation(&self, token: &str) -> Result<CredentialPresentation, FormatterError> {
        self.extract_presentation(token)
    }
}
