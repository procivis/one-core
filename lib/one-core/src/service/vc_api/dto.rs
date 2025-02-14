use crate::provider::credential_formatter::json_ld::model::{LdCredential, LdPresentation};
use crate::provider::credential_formatter::vcdm::VcdmCredential;

#[derive(Debug)]
pub struct CredentialIssueRequest {
    pub credential: VcdmCredential,
    pub options: CredentialIssueOptions,
}

#[derive(Debug)]
pub struct CredentialIssueOptions {
    pub signature_algorithm: String,
    pub credential_format: Option<String>,
    pub revocation_method: Option<String>,
}

#[derive(Debug)]
pub struct CredentialIssueResponse {
    pub verifiable_credential: LdCredential,
}

#[derive(Debug)]
pub struct CredentialVerifiyRequest {
    pub verifiable_credential: VcdmCredential,
    pub options: VerifyOptions,
}

#[derive(Debug)]
pub struct VerifyOptions {
    pub checks: Vec<String>,
    pub credential_format: Option<String>,
}

#[derive(Debug)]
pub struct CredentialVerifyResponse {
    pub checks: Vec<String>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
    pub credential: VcdmCredential,
}

#[derive(Debug)]
pub struct PresentationVerifyRequest {
    pub verifiable_presentation: LdPresentation,
    pub options: VerifyOptions,
}

#[derive(Debug)]
pub struct PresentationVerifyResponse {
    pub checks: Vec<String>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}
